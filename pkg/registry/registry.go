package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
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

// GetServices returns a slice of all service configurations.
func (r *Registry) GetServices() []config.ServiceConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	services := make([]config.ServiceConfig, 0, len(r.services))
	for _, s := range r.services {
		services = append(services, s)
	}
	return services
}

func (r *Registry) GetServiceConfig(serviceName string) (config.ServiceConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	service, found := r.services[serviceName]
	return service, found
}

func (r *Registry) SearchCapabilitiesJIT(ctx context.Context, query string, availableTools []mcp.Tool) ([]mcp.Tool, error) {
	if query == "" || len(availableTools) == 0 {
		return availableTools, nil
	}

	queryEmbedding, err := createEmbedding(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to create query embedding: %w", err)
	}

	type ScoredTool struct {
		Tool       mcp.Tool
		Similarity float64
	}

	scoredTools := make([]ScoredTool, len(availableTools))
	var wg sync.WaitGroup
	var mu sync.Mutex
	errors := []error{}

	for i, tool := range availableTools {
		wg.Add(1)
		go func(idx int, t mcp.Tool) {
			defer wg.Done()
			toolText := fmt.Sprintf("Tool: %s; Description: %s", t.Name, t.Description)
			toolEmbedding, err := createEmbedding(ctx, toolText)
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("failed to embed tool %s: %w", t.Name, err))
				mu.Unlock()
				return
			}

			similarity := 0.0
			for i := range queryEmbedding {
				similarity += float64(queryEmbedding[i] * toolEmbedding[i])
			}
			scoredTools[idx] = ScoredTool{Tool: t, Similarity: similarity}
		}(i, tool)
	}

	wg.Wait()
	if len(errors) > 0 {
		log.Printf("Registry: Encountered %d errors during JIT embedding", len(errors))
	}

	sort.Slice(scoredTools, func(i, j int) bool {
		return scoredTools[i].Similarity > scoredTools[j].Similarity
	})

	// TODO: Similarity threshold to filter out irrelevant results.
	// For now, we can just return top N

	const similarityThreshold = 0.75

	var relevantTools []mcp.Tool
	for _, st := range scoredTools {
		if st.Similarity < similarityThreshold {
			relevantTools = append(relevantTools, st.Tool)
		}
	}

	resultCount := 10
	if len(relevantTools) < resultCount {
		resultCount = len(relevantTools)
	}

	finalTools := relevantTools[:resultCount]

	return finalTools, nil
}

// createEmbedding uses the OpenAI API to create an embedding for the given text.
func createEmbedding(ctx context.Context, text string) ([]float32, error) {
	resp, err := openai.NewClient(os.Getenv("OPENAI_API_KEY")).CreateEmbeddings(ctx, openai.EmbeddingRequest{
		Input: []string{text},
		Model: openai.AdaEmbeddingV2,
	})
	if err != nil {
		return nil, fmt.Errorf("creating embedding: %w", err)
	}
	return resp.Data[0].Embedding, nil
}

// SearchCapabilities performs a semantic vector search against the capabilities table.
func (r *Registry) SearchCapabilities(ctx context.Context, query string) ([]mcp.Tool, error) {
	queryEmbedding, err := createEmbedding(ctx, query)
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
