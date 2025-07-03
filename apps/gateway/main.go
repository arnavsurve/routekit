package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/arnavsurve/routekit/pkg/config"
	"github.com/arnavsurve/routekit/pkg/crypto"
	"github.com/arnavsurve/routekit/pkg/db"
	rk_mcp "github.com/arnavsurve/routekit/pkg/mcp"
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

type transportWithContext interface {
	Context() context.Context
}

type transportWithCancel interface {
	Cancel()
}

type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

type GatewayServer struct {
	mcpServer   *server.MCPServer
	registry    *registry.Registry
	db          *pgxpool.Pool
	jwtSecret   []byte
	clientCache *sync.Map
}

type contextKey string

const userIDKey contextKey = "user_id"

func NewGatewayServer(dbPool *pgxpool.Pool, secret []byte) *GatewayServer {
	s := server.NewMCPServer("Routekit-Gateway", "0.1.0",
		server.WithToolCapabilities(true),
	)

	gw := &GatewayServer{
		mcpServer:   s,
		registry:    registry.New(dbPool),
		db:          dbPool,
		jwtSecret:   secret,
		clientCache: &sync.Map{},
	}

	s.AddTool(
		mcp.NewTool("routekit_get_connected_services",
			mcp.WithDescription("Get a list of all external services the current user is authenticated with."),
		),
		gw.mcpAuthMiddleware(gw.handleGetConnectedServices),
	)

	s.AddTool(
		mcp.NewTool("routekit_search_tools",
			mcp.WithDescription("Search for available tools within a specified list of services."),
			mcp.WithString("query", mcp.Required(), mcp.Description("A description of the task you want to perform.")),
			mcp.WithArray("services_to_search", mcp.Required(), mcp.Description("A list of service names (from 'get_connected_services') to search within.")),
		),
		gw.mcpAuthMiddleware(gw.handleSearchTools),
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

func (gw *GatewayServer) getOrCreateClient(ctx context.Context, userID string, service config.ServiceConfig) (*client.Client, error) {
	cacheKey := userID + ":" + service.Name

	if cachedClient, ok := gw.clientCache.Load(cacheKey); ok {
		clientInstance := cachedClient.(*client.Client)
		pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := clientInstance.Ping(pingCtx); err == nil {
			log.Printf("Gateway: Reusing cached client for %s", cacheKey)
			return clientInstance, nil
		}
		// Client is stale, remove from cache
		log.Printf("Gateway: Cached client for %s failed ping, creating new one.", cacheKey)
		gw.clientCache.Delete(cacheKey)
		clientInstance.Close()
	}

	newClient, err := gw.createClientForService(ctx, userID, service)
	if err != nil {
		return nil, err
	}

	gw.clientCache.Store(cacheKey, newClient)
	log.Printf("Gateway: Stored new client in cache for %s", cacheKey)

	if transportWithCtx, ok := newClient.GetTransport().(transportWithContext); ok {
		go func() {
			<-transportWithCtx.Context().Done()
			log.Printf("Gateway: Client connection for %s closed. Removing from cache.", cacheKey)
			gw.clientCache.Delete(cacheKey)
		}()
	} else {
		log.Printf("Gateway: Warning - transport for %s does not expose context for automatic cleanup.", service.Name)
	}

	return newClient, nil
}

func (gw *GatewayServer) createClientForService(ctx context.Context, userID string, service config.ServiceConfig) (*client.Client, error) {
	log.Printf("Gateway: Creating client for service %q with transport %q at %s", service.Name, service.Transport, service.URL)

	var c *client.Client
	var err error

	if service.Transport == "sse" || service.Transport == "streamable-http" {

		tokenStore := rk_mcp.NewGatewayTokenStore(gw.db, userID, service.Name)

		oauthConfig := transport.OAuthConfig{
			ClientID:     os.Getenv(strings.ToUpper(service.Name) + "_CLIENT_ID"),
			ClientSecret: os.Getenv(strings.ToUpper(service.Name) + "_CLIENT_SECRET"),
			RedirectURI:  "http://localhost:3000/api/connectors/" + service.Name + "/callback",
			TokenStore:   tokenStore,
			PKCEEnabled:  true,
			Scopes: []string{
				"read:jira-work", "write:jira-work", "read:confluence-content.all",
				"write:confluence-content", "read:jira-user", "offline_access",
			},
		}

		if service.Transport == "sse" {
			c, err = client.NewOAuthSSEClient(service.URL, oauthConfig)
		} else { // streamable-http
			// Note: The GitHub MCP server is different; it just uses a static Bearer token (PAT).
			// If we were connecting to a true streamable-http OAuth server, we would use NewOAuthStreamableHttpClient.
			// For GitHub, we'll create a simpler client.
			if service.Name == "github" {
				token, err_gh := gw.getGitHubPat(ctx, userID)
				if err_gh != nil {
					return nil, fmt.Errorf("could not get token for %s: %w", service.Name, err_gh)
				}
				headers := map[string]string{"Authorization": "Bearer " + token}
				c, err = client.NewStreamableHttpClient(service.URL, transport.WithHTTPHeaders(headers))
			} else {
				c, err = client.NewOAuthStreamableHttpClient(service.URL, oauthConfig)
			}
		}

		if err != nil {
			return nil, fmt.Errorf("failed to create client object for %s: %w", service.Name, err)
		}

		initCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		if needsStart(c) {
			startErr := c.Start(initCtx)

			if client.IsOAuthAuthorizationRequiredError(startErr) {
				c.Close()
				oauthHandler := client.GetOAuthHandler(startErr)
				if oauthHandler == nil {
					return nil, fmt.Errorf("authentication required for %s, but OAuth handler is missing", service.Name)
				}

				state, _ := transport.GenerateState()
				codeVerifier, _ := transport.GenerateCodeVerifier()

				var existingState, existingCodeVerifier string
				err := gw.db.QueryRow(context.Background(), "SELECT state, code_verifier FROM oauth_sessions WHERE user_id = $1 AND service_name = $2", userID, service.Name).Scan(&existingState, &existingCodeVerifier)

				if err == nil {
					log.Printf("Gateway: Found existing auth challenge for user %s. Re-using state: %s", userID, existingState)

					state = existingState
					codeVerifier = existingCodeVerifier
				} else if err == pgx.ErrNoRows {
					state, _ = transport.GenerateState()
					codeVerifier, _ = transport.GenerateCodeVerifier()

					// TODO: migrate this to redis
					_, dbErr := gw.db.Exec(context.Background(), "INSERT INTO oauth_sessions (state, code_verifier, user_id, service_name) VALUES ($1, $2, $3, $4)", state, codeVerifier, userID, service.Name)
					if dbErr != nil {
						return nil, fmt.Errorf("failed to store OAuth session state: %w", dbErr)
					}
					log.Printf("Gateway: Saved auth state for user %s. State : %s", userID, state)
				} else {
					return nil, fmt.Errorf("database error checking for auth session: %w", err)
				}

				codeChallenge := transport.GenerateCodeChallenge(codeVerifier)

				params := url.Values{}
				params.Set("response_type", "code")
				params.Set("client_id", os.Getenv(strings.ToUpper(service.Name)+"_CLIENT_ID"))
				params.Set("redirect_uri", "http://localhost:3000/api/connectors/"+service.Name+"/callback")
				params.Set("scope", strings.Join(oauthConfig.Scopes, " "))
				params.Set("state", state)
				params.Set("code_challenge", codeChallenge)
				params.Set("code_challenge_method", "S256")
				params.Set("audience", "api.atlassian.com")
				params.Set("prompt", "consent")

				authURL := "https://auth.atlassian.com/authorize?" + params.Encode()

				jsonResponse := fmt.Sprintf(
					`{"action_required": "user_authentication", "service_name": "%s", "authorization_url": "%s"}`,
					service.Name,
					authURL,
				)
				return nil, errors.New(jsonResponse)
			}

			if startErr != nil {
				c.Close()
				return nil, fmt.Errorf("failed to start client transport for %s: %w", service.Name, startErr)
			}
		}

	} else {
		return nil, fmt.Errorf("unsupported transport '%q' for service '%s'", service.Transport, service.Name)
	}

	initCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, initErr := c.Initialize(initCtx, mcp.InitializeRequest{
		Params: struct {
			ProtocolVersion string                 `json:"protocolVersion"`
			Capabilities    mcp.ClientCapabilities `json:"capabilities"`
			ClientInfo      mcp.Implementation     `json:"clientInfo"`
		}{ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION},
	})
	if initErr != nil {
		c.Close()
		return nil, fmt.Errorf("failed to initialize MCP session with %s: %w", service.Name, initErr)
	}

	return c, nil
}

func (gw *GatewayServer) getGitHubPat(ctx context.Context, userID string) (string, error) {
	var encryptedCreds []byte
	err := gw.db.QueryRow(ctx, "SELECT credentials_encrypted FROM connected_services WHERE user_id = $1 AND service_name = 'github'", userID).Scan(&encryptedCreds)
	if err != nil {
		return "", err
	}
	decrypted, err := crypto.Decrypt(encryptedCreds)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

func (gw *GatewayServer) handleGetConnectedServices(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	userID, ok := ctx.Value(userIDKey).(string)
	if !ok {
		return mcp.NewToolResultError("Internal error; user ID not found in context"), nil
	}

	rows, err := gw.db.Query(ctx, "SELECT service_name FROM connected_services WHERE user_id = $1", userID)
	if err != nil {
		log.Printf("Gateway: DB error fetching connected services for user %s: %v", userID, err)
		return mcp.NewToolResultError("database error"), nil
	}
	defer rows.Close()

	var serviceNames []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return mcp.NewToolResultError("failed to read service names"), nil
		}
		serviceNames = append(serviceNames, name)
	}

	result := map[string][]string{"services": serviceNames}
	jsonRes, _ := json.Marshal(result)

	return mcp.NewToolResultText(string(jsonRes)), nil
}

type SearchResult struct {
	Tools []mcp.Tool `json:"tools"`
}

func (gw *GatewayServer) handleSearchTools(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	userID, ok := ctx.Value(userIDKey).(string)
	if !ok {
		return mcp.NewToolResultError("Internal error; user ID not found in context"), nil
	}

	query := req.GetString("query", "")
	servicesToSearch, err := req.RequireStringSlice("services_to_search")
	if err != nil {
		return mcp.NewToolResultError("`services_to_search` must be a list of strings."), nil
	}

	log.Printf("Gateway: User %s searching for tools with query %q in services %q", userID, query, servicesToSearch)

	allServiceConfigs := gw.registry.GetServices()
	var targetServices []config.ServiceConfig
	for _, serviceName := range servicesToSearch {
		found := false
		for _, cfg := range allServiceConfigs {
			if cfg.Name == serviceName {
				targetServices = append(targetServices, cfg)
				found = true
				break
			}
		}
		if !found {
			log.Printf("Gateway: WARN - User %s requested search in unknown service %s", userID, serviceName)
		}
	}

	discoveredTools, discoverErr := gw.discoverUserTools(ctx, userID, targetServices)
	if discoverErr != nil {
		return mcp.NewToolResultError(discoverErr.Error()), nil
	}

	var foundTools []mcp.Tool

	if query == "" || query == "*" {
		log.Println("Gateway: Handling as a 'list all' query, bypassing semantic search.")
		foundTools = discoveredTools
	} else {
		var searchErr error
		foundTools, searchErr = gw.registry.SearchCapabilitiesJIT(ctx, query, discoveredTools)
		if searchErr != nil {
			return mcp.NewToolResultError("Search failed: " + searchErr.Error()), nil
		}
	}

	if len(foundTools) == 0 {
		log.Printf("Gateway: No tools found for user %s with query %q in services %q", userID, query, servicesToSearch)
		return mcp.NewToolResultText(`{"tools":[]}`), nil
	}

	searchResult := SearchResult{Tools: foundTools}
	jsonRes, err := json.MarshalIndent(searchResult, "", "  ")
	if err != nil {
		return mcp.NewToolResultError("failed to serialize search results: " + err.Error()), nil
	}

	return mcp.NewToolResultText(string(jsonRes)), nil
}

func (gw *GatewayServer) discoverUserTools(ctx context.Context, userID string, services []config.ServiceConfig) ([]mcp.Tool, error) {
	var wg sync.WaitGroup
	toolChan := make(chan mcp.Tool, 100)
	errChan := make(chan error, len(services))

	for _, service := range services {
		wg.Add(1)
		go func(s config.ServiceConfig) {
			defer wg.Done()

			client, err := gw.getOrCreateClient(ctx, userID, s)
			if err != nil {
				if strings.Contains(err.Error(), "action_required") {
					errChan <- err
					return
				}
				log.Printf("Gateway: Failed to create client for %s dusing user discovery: %v", s.Name, err)
				return
			}
			defer client.Close()

			tools, err := client.ListTools(ctx, mcp.ListToolsRequest{})
			if err != nil {
				log.Printf("Gateway: Failed to list tools from %s for user %s: %v. This is expected for Atlassian before a cloudId is known.", s.Name, userID, err)
				return
			}

			for _, tool := range tools.Tools {
				tool.Name = fmt.Sprintf("%s__%s", s.Name, tool.Name)
				toolChan <- tool
			}
		}(service)
	}

	wg.Wait()
	close(toolChan)
	close(errChan)

	for err := range errChan {
		if err != nil {
			return nil, err
		}
	}

	var allTools []mcp.Tool
	for tool := range toolChan {
		allTools = append(allTools, tool)
	}
	return allTools, nil
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

	serviceConfig, found := gw.registry.GetServiceConfig(serviceName)
	if !found {
		log.Printf("Gateway: Service %q for tool %q not found in service catalog (routekit.yml)", serviceName, fqn)
		return mcp.NewToolResultErrorf("Unknown service in tool name: %s", serviceName), nil
	}

	log.Printf("Gateway: Routing tool call %q to service %s", fqn, serviceConfig.Name)

	downstreamClient, err := gw.getOrCreateClient(ctx, userID, serviceConfig)
	if err != nil {
		log.Printf("Gateway: ERROR - Failed to create client for %q: %v", fqn, err)
		return mcp.NewToolResultError(err.Error()), nil
	}

	downstreamReq := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      originalToolName,
			Arguments: args,
		},
	}

	return downstreamClient.CallTool(ctx, downstreamReq)
}

// needsStart is a helper to check if the client transport needs to be explicitly started.
// The `mcp-go` v0.32.0 `NewStdioMCPClient` starts the client automatically,
// while others like SSE and StreamableHTTP require an explicit `Start()` call.
// We check transport type to be safe.
func needsStart(c *client.Client) bool {
	switch c.GetTransport().(type) {
	case *transport.Stdio:
		return false
	default:
		return true
	}
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

	log.Printf("Serving Routekit Gateway on %s", port)
	httpServer := server.NewStreamableHTTPServer(gateway.mcpServer)
	if err := httpServer.Start(port); err != nil {
		log.Fatalf("Gateway: Could not start server: %v", err)
	}
}
