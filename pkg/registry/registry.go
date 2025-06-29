package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/pgvector/pgvector-go"
	"github.com/sashabaranov/go-openai"
)

const DSN = "postgres://routekit:routekit@localhost:5433/routekit?sslmode=disable"

type Service struct {
	Name string
	URL  string
}

type Registry struct {
	db           *pgxpool.Pool
	openaiClient *openai.Client
	services     []Service
}

func New() *Registry {
	dbpool, err := pgxpool.New(context.Background(), DSN)
	if err != nil {
		log.Fatalf("Registry: Failed to connect to database: %v\n", err)
	}

	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		log.Fatalf("Registry: OPENAI_API_KEY environment variable is not set.\n")
	}

	services := []Service{
		{Name: "crm-service", URL: "http://localhost:8083/mcp"},
		{Name: "kb-service", URL: "http://localhost:8084/mcp"},
		{Name: "devops-service", URL: "http://localhost:8085/mcp"},
		{Name: "support-service", URL: "http://localhost:8086/mcp"},
		{Name: "bug-tracker-service", URL: "http://localhost:8087/mcp"},
	}

	return &Registry{
		db:           dbpool,
		openaiClient: openai.NewClient(apiKey),
		services:     services,
	}
}

func (r *Registry) Close() {
	r.db.Close()
}

// createEmbedding uses the OpenAI API to create an embedding for the given text.
func (r *Registry) createEmbedding(ctx context.Context, text string) ([]float32, error) {
	resp, err := r.openaiClient.CreateEmbeddings(ctx, openai.EmbeddingRequest{
		Input: []string{text},
		Model: openai.AdaEmbeddingV2,
	})
	if err != nil {
		return nil, fmt.Errorf("creating embedding: %w", err)
	}
	return resp.Data[0].Embedding, nil
}

// GetServices returns the list of configured downstream services.
func (r *Registry) GetServices() []Service {
	return r.services
}

// RegisterCapabilities creates embeddings for discovered tools and stores them in the database.
func (r *Registry) RegisterCapabilities(ctx context.Context, serviceName, serviceURL string, tools []mcp.Tool) {
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
		ORDER BY embedding <=> $1
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

func (r *Registry) Resolve(ctx context.Context, fqn string) (string, bool) {
	var targetURL string
	err := r.db.QueryRow(ctx, "SELECT target_url FROM capabilities WHERE fqn = $1", fqn).Scan(&targetURL)
	if err != nil {
		// pgx.ErrNoRows is expected when not found
		return "", false
	}
	return targetURL, true
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
