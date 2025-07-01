package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/arnavsurve/routekit/pkg/config"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/pgvector/pgvector-go"
	"github.com/sashabaranov/go-openai"
)

const DSN = "postgres://routekit:routekit@localhost:5433/routekit?sslmode=disable"

type Registry struct {
	db       *pgxpool.Pool
	services map[string]config.ServiceConfig
	mu       sync.RWMutex
}

func New(dbPool *pgxpool.Pool) *Registry {
	cfg, err := config.Load("routekit.yml")
	if err != nil {
		log.Fatalf("Registry: failed to load routekit.yml: %v", err)
	}

	serviceMap := make(map[string]config.ServiceConfig)
	for _, service := range cfg.Services {
		serviceMap[service.Name] = service
	}

	log.Printf("Registry: loaded %d services from config.", len(serviceMap))

	return &Registry{
		db:       dbPool,
		services: serviceMap,
	}
}

func (r *Registry) Close() {
	r.db.Close()
}

// createEmbedding uses the OpenAI API to create an embedding for the given text.
func (r *Registry) createEmbedding(ctx context.Context, text string) ([]float32, error) {
	resp, err := openai.NewClient(os.Getenv("OPENAI_API_KEY")).CreateEmbeddings(ctx, openai.EmbeddingRequest{
		Input: []string{text},
		Model: openai.AdaEmbeddingV2,
	})
	if err != nil {
		return nil, fmt.Errorf("creating embedding: %w", err)
	}
	return resp.Data[0].Embedding, nil
}

// GetServices returns the list of configured downstream services.
func (r *Registry) GetServices() []config.ServiceConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	services := make([]config.ServiceConfig, 0, len(r.services))
	for _, s := range r.services {
		services = append(services, s)
	}
	return services
}

// RegisterCapabilities creates embeddings for discovered tools and stores them in the database.
func (r *Registry) RegisterCapabilities(ctx context.Context, serviceName, serviceURL string, tools []mcp.Tool) {
	log.Printf("Registry: Registering %d tools for service %q", len(tools), serviceName)
	for _, tool := range tools {
		fqn := fmt.Sprintf("%s__%s", serviceName, tool.Name)
		embeddingText := fmt.Sprintf("Tool: %s. Description: %s", tool.Name, tool.Description)

		embedding, err := r.createEmbedding(ctx, embeddingText)
		if err != nil {
			log.Printf("Registry: ERROR - Failed to create embedding for %q: %v\n", fqn, err)
			continue
		}

		inputSchemaBytes, err := json.Marshal(tool.InputSchema)
		if err != nil {
			log.Printf("Registry: ERROR - Failed to marshal inputSchema for %q: %v\n", fqn, err)
			continue
		}

		_, err = r.db.Exec(ctx, `
			INSERT INTO capabilities (fqn, service_name, tool_name, description, target_url, input_schema, embedding)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (fqn) DO UPDATE SET
				description = EXCLUDED.description,
				target_url = EXCLUDED.target_url,
				embedding = EXCLUDED.embedding,
				input_schema = EXCLUDED.input_schema;
		`,
			fqn, serviceName, tool.Name, tool.Description, serviceURL, inputSchemaBytes, pgvector.NewVector(embedding))

		if err != nil {
			log.Printf("Registry: ERROR - Failed to register capability %q: %v\n", fqn, err)
		} else {
			log.Printf("Registry: Registered capability %q\n", fqn)
		}
	}
}

// SearchCapabilities performs a semantic vector search against the capabilities table.
func (r *Registry) SearchCapabilities(ctx context.Context, query string) ([]mcp.Tool, error) {
	queryEmbedding, err := r.createEmbedding(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("creating query embedding: %w", err)
	}

	rows, err := r.db.Query(ctx, `
		SELECT fqn, service_name, description, input_schema
		FROM capabilities
		ORDER BY embedding <-> $1
		LIMIT 5;
	`, pgvector.NewVector(queryEmbedding))
	if err != nil {
		return nil, fmt.Errorf("searching capabilities: %w", err)
	}
	defer rows.Close()

	var results []mcp.Tool
	for rows.Next() {
		var (
			fqn              string
			serviceName      string
			description      string
			inputSchemaBytes []byte
		)
		if err := rows.Scan(&fqn, &serviceName, &description, &inputSchemaBytes); err != nil {
			return nil, fmt.Errorf("scanning capabilities: %w", err)
		}

		var inputSchema mcp.ToolInputSchema
		if len(inputSchemaBytes) > 0 {
			if err := json.Unmarshal(inputSchemaBytes, &inputSchema); err != nil {
				log.Printf("Registry: WARN - could not parse inputSchema for tool %q: %v\n", fqn, err)
			}
		} else {
			inputSchema = mcp.ToolInputSchema{Type: "object", Properties: map[string]any{}}
		}

		results = append(results, mcp.Tool{
			Name:        fqn,
			Description: fmt.Sprintf("[%s] %s", serviceName, description),
			InputSchema: inputSchema,
		})
	}

	return results, nil
}

func (r *Registry) GetAllCapabilities(ctx context.Context) ([]mcp.Tool, error) {
	rows, err := r.db.Query(ctx, `
		SELECT fqn, service_name, description, input_schema
		FROM capabilities
		ORDER BY fqn;
	`)
	if err != nil {
		return nil, fmt.Errorf("getting all capabilities: %w", err)
	}
	defer rows.Close()

	var results []mcp.Tool
	for rows.Next() {
		var (
			fqn              string
			serviceName      string
			description      string
			inputSchemaBytes []byte
		)
		if err := rows.Scan(&fqn, &serviceName, &description, &inputSchemaBytes); err != nil {
			return nil, fmt.Errorf("scanning capabilities: %w", err)
		}

		var inputSchema mcp.ToolInputSchema
		if len(inputSchemaBytes) > 0 {
			if err := json.Unmarshal(inputSchemaBytes, &inputSchema); err != nil {
				log.Printf("Registry: WARN - could not parse inputSchema for tool %q: %v\n", fqn, err)
			}
		}

		results = append(results, mcp.Tool{
			Name:        fqn,
			Description: fmt.Sprintf("[%s] %s", serviceName, description),
			InputSchema: inputSchema,
		})
	}

	return results, nil
}

func (r *Registry) Resolve(ctx context.Context, fqn string) (config.ServiceConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var serviceName string
	err := r.db.QueryRow(ctx, "SELECT service_name FROM capabilities WHERE fqn = $1", fqn).Scan(&serviceName)
	if err != nil {
		// pgx.ErrNoRows is expected when not found
		return config.ServiceConfig{}, false
	}
	service, found := r.services[serviceName]
	return service, found
}
