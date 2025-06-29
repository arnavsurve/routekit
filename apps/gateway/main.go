package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/arnavsurve/routekit/pkg/crypto"
	"github.com/arnavsurve/routekit/pkg/db"
	"github.com/arnavsurve/routekit/pkg/registry"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

type GatewayServer struct {
	mcpServer *server.MCPServer
	registry  *registry.Registry
	db        *pgxpool.Pool
	jwtSecret []byte
}

// A context key for passing the userID
type contextKey string

const userIDKey contextKey = "user_id"

func NewGatewayServer(dbPool *pgxpool.Pool, secret []byte) *GatewayServer {
	s := server.NewMCPServer("Routekit-Gateway", "0.1.0",
		server.WithToolCapabilities(true),
	)

	gw := &GatewayServer{
		mcpServer: s,
		registry:  registry.New(dbPool),
		db:        dbPool,
		jwtSecret: secret,
	}

	s.AddTool(
		mcp.NewTool("routekit_search_tools",
			mcp.WithDescription("Search for available tools based on a natural language query. If an empty query is provided, returns all tools."),
			mcp.WithString("query", mcp.Required(), mcp.Description("A description of the task you want to perform.")),
		),
		gw.handleSearchTools,
	)

	s.AddTool(
		mcp.NewTool("routekit_execute",
			mcp.WithDescription("Executes a tool by its fully-qualified name with the given arguments."),
			mcp.WithString("tool_name", mcp.Required()),
			mcp.WithObject("tool_args", mcp.Required()),
		),
		gw.mcpAuthMiddleware(gw.handleExecute),
	)

	return gw
}

// mcpAuthMiddleware extracts the JWT from the request meta, validates it,
// and injects the user ID into the context for downstream handlers.
func (gw *GatewayServer) mcpAuthMiddleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if req.Params.Meta == nil || req.Params.Meta.AdditionalFields["jwt"] == nil {
			return mcp.NewToolResultError("Authentication error: missing token"), nil
		}

		tokenStr, ok := req.Params.Meta.AdditionalFields["jwt"].(string)
		if !ok {
			return mcp.NewToolResultError("Authentication error: invalid token format"), nil
		}

		token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (any, error) {
			return gw.jwtSecret, nil
		})
		if err != nil || !token.Valid {
			return mcp.NewToolResultError("Authentication error: invalid token"), nil
		}

		claims, ok := token.Claims.(*Claims)
		if !ok {
			return mcp.NewToolResultError("Authentication error: invalid claims"), nil
		}

		ctxWithUser := context.WithValue(ctx, userIDKey, claims.UserID)
		return next(ctxWithUser, req)
	}
}

// discoverAndRegisterTools populates the registry by discovering tools from downstream services.
func (gw *GatewayServer) discoverAndRegisterTools(ctx context.Context) error {
	services := gw.registry.GetServices()
	var wg sync.WaitGroup
	log.Printf("Gateway: Starting discovery of %d services...", len(services))

	for _, service := range services {
		wg.Add(1)
		go func(s registry.Service) {
			defer wg.Done()
			log.Printf("Gateway: Discovering tools from %q at %s", s.Name, s.URL)

			var discoveryAuthToken string
			if s.Name == "github" {
				discoveryAuthToken = os.Getenv("ROUTEKIT_SYSTEM_GITHUB_PAT")
				if discoveryAuthToken == "" {
					log.Printf("Gateway: WARN - ROUTEKIT_SYSTEM_GITHUB_PAT environment variable is not set. Skipping discovery of GitHub tools.\n")
					return
				}
			}

			downstreamClient, err := gw.getDownstreamClient(s.URL, discoveryAuthToken)
			if err != nil {
				log.Printf("Gateway: ERROR connecting to %s: %v", s.Name, err)
				return
			}
			defer downstreamClient.Close()

			tools, err := downstreamClient.ListTools(ctx, mcp.ListToolsRequest{})
			if err != nil {
				log.Printf("Gateway: ERROR listing tools from %s: %v", s.Name, err)
				return
			}
			gw.registry.RegisterCapabilities(ctx, s.Name, s.URL, tools.Tools)
		}(service)
	}
	wg.Wait()
	log.Println("Gateway: Discovery complete. Registry is populated.")
	return nil
}

// getDownstreamClient is a helper to manage clients. It dynamically adds the auth token if one is provided.
// For now, it just creates a new client. In production, this should use a connection pool/cache.
func (gw *GatewayServer) getDownstreamClient(targetURL, authToken string) (*client.Client, error) {
	// TODO: Implement client caching using gw.clientCache
	var opts []transport.StreamableHTTPCOption
	if authToken != "" {
		opts = append(opts, transport.WithHTTPHeaders(map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", authToken),
		}))
	}

	c, err := client.NewStreamableHttpClient(targetURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create client for %s: %w", targetURL, err)
	}

	initCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = c.Initialize(initCtx, mcp.InitializeRequest{
		Params: struct {
			ProtocolVersion string                 `json:"protocolVersion"`
			Capabilities    mcp.ClientCapabilities `json:"capabilities"`
			ClientInfo      mcp.Implementation     `json:"clientInfo"`
		}{ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION},
	})
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("failed to initialize connection: %w", err)
	}
	return c, nil
}

type SearchResult struct {
	// Instruction string `json:"instruction"`
	Tools []mcp.Tool `json:"tools"`
}

func (gw *GatewayServer) handleSearchTools(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query := req.GetString("query", "")
	log.Printf("Gateway: Searching for tools with query: %s", query)

	var foundTools []mcp.Tool
	var err error

	if query == "" || query == "*" {
		log.Println("Gateway: Performing a 'list all' operation.")
		foundTools, err = gw.registry.GetAllCapabilities(ctx)
	} else {
		log.Println("Gateway: Performing a semantic search.")
		foundTools, err = gw.registry.SearchCapabilities(ctx, query)
	}

	if err != nil {
		log.Printf("Gateway: ERROR - Search failed: %v", err)
		return mcp.NewToolResultError("search failed: " + err.Error()), nil
	}

	searchResult := SearchResult{
		// Instruction: "To use a tool, call the 'routekit_execute' tool with the desired 'tool_name' and 'tool_args'.",
		Tools: foundTools,
	}

	jsonRes, err := json.MarshalIndent(searchResult, "", "  ")
	if err != nil {
		log.Printf("Gateway: ERROR serializing search results: %v", err)
		return mcp.NewToolResultError("failed to serialize search results: " + err.Error()), nil
	}

	log.Printf("Gateway: Search results returned to agent:\n%s", string(jsonRes))
	return mcp.NewToolResultText(string(jsonRes)), nil
}

// handleExecute routes a tool call to the correct downstream service.
func (gw *GatewayServer) handleExecute(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	userID, ok := ctx.Value(userIDKey).(string)
	if !ok {
		return mcp.NewToolResultError("Internal error; user ID not found in context"), nil
	}

	fqn := req.GetString("tool_name", "")
	args, ok := req.GetArguments()["tool_args"].(map[string]any)
	if !ok {
		return mcp.NewToolResultError("tool_args must be an object"), nil
	}

	nameParts := strings.SplitN(fqn, "__", 2)
	if len(nameParts) != 2 {
		return mcp.NewToolResultError(fmt.Sprintf("invalid tool name format: %s", fqn)), nil
	}
	serviceName := nameParts[0]
	originalToolName := nameParts[1]

	var downstreamAuthToken string
	if serviceName == "github" {
		var encryptedPat []byte
		err := gw.db.QueryRow(ctx, "SELECT credentials_encrypted FROM connected_services WHERE user_id = $1 AND service_name = 'github'", userID).Scan(&encryptedPat)
		if err != nil {
			if err == pgx.ErrNoRows {
				return mcp.NewToolResultError("GitHub not connected. Please connect your GitHub account in settings."), nil
			}
			log.Printf("Gateway: ERROR - DB error fetching PAT for user: %s: %v", userID, err)
			return mcp.NewToolResultError("internal database error: " + err.Error()), nil
		}

		decryptedPat, err := crypto.Decrypt(encryptedPat)
		if err != nil {
			log.Printf("Gateway: ERROR - Failed to decrypt PAT for user: %s: %v", userID, err)
			return mcp.NewToolResultError("internal encryption error: " + err.Error()), nil
		}
		downstreamAuthToken = string(decryptedPat)
	}

	targetURL, found := gw.registry.Resolve(ctx, fqn)
	if !found {
		log.Printf("Gateway: Capability %q not found in registry", fqn)
		return mcp.NewToolResultError(fmt.Sprintf("Unknown capability: %s. Please use routekit__search_tools to find available tools.", fqn)), nil
	}
	log.Printf("Gateway: Routing tool call %q to %s", fqn, targetURL)

	downstreamClient, err := gw.getDownstreamClient(targetURL, downstreamAuthToken)
	if err != nil {
		log.Printf("Gateway: ERROR - Failed to create client for %q at %s: %v", fqn, targetURL, err)
		return mcp.NewToolResultError("internal routing error: " + err.Error()), nil
	}
	defer downstreamClient.Close()

	downstreamReq := mcp.CallToolRequest{}
	downstreamReq.Params.Name = originalToolName
	downstreamReq.Params.Arguments = args

	log.Printf("Gateway: Forwarding request for tool %q to downstream service...", downstreamReq.Params.Name)
	return downstreamClient.CallTool(ctx, downstreamReq)
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Gateway: Could not load environment variables: %v", err)
	}

	db.Init()
	defer db.Close()
	crypto.Init()

	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) == 0 {
		log.Fatalf("Gateway: JWT_SECRET environment variable not set.")
	}

	gateway := NewGatewayServer(db.GetPool(), jwtSecret)

	port := ":8080"

	if err := gateway.discoverAndRegisterTools(context.Background()); err != nil {
		log.Fatalf("Gateway: Could not complete initial tool discovery: %v", err)
	}

	log.Printf("Serving Routekit Gateway on %s", port)
	httpServer := server.NewStreamableHTTPServer(gateway.mcpServer)
	if err := httpServer.Start(port); err != nil {
		log.Fatalf("Gateway: Could not start server: %v", err)
	}
}
