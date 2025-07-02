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

	"github.com/arnavsurve/routekit/pkg/config"
	"github.com/arnavsurve/routekit/pkg/crypto"
	"github.com/arnavsurve/routekit/pkg/db"
	rk_mcp "github.com/arnavsurve/routekit/pkg/mcp"
	"github.com/arnavsurve/routekit/pkg/registry"
	"github.com/golang-jwt/jwt/v5"
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

func (gw *GatewayServer) createClientForService(ctx context.Context, userID string, service config.ServiceConfig) (*client.Client, error) {
	log.Printf("Gateway: Creating client for service %q with transport %q at %s", service.Name, service.Transport, service.URL)

	var c *client.Client
	var err error

	tokenStore := rk_mcp.NewGatewayTokenStore(gw.db, userID, service.Name)

	initialToken, err := tokenStore.GetToken()
	if err != nil {
		if err == transport.ErrOAuthAuthorizationRequired {
			return nil, transport.ErrOAuthAuthorizationRequired
		}
		return nil, err
	}

	oauthConfig := transport.OAuthConfig{
		ClientID:     os.Getenv(strings.ToUpper(service.Name) + "_CLIENT_ID"),
		ClientSecret: os.Getenv(strings.ToUpper(service.Name) + "_CLIENT_SECRET"),
		TokenStore:   tokenStore,
		// The other fields like RedirectURI are handled by the Routekit web app, not the gateway.
	}

	headers := make(map[string]string)
	if initialToken != nil && !initialToken.IsExpired() {
		headers["Authorization"] = "Bearer " + initialToken.AccessToken
	}

	switch service.Transport {
	case "streamable-http":
		if service.URL == "" {
			return nil, fmt.Errorf("URL is required for streamable-http transport")
		}
		c, err = client.NewStreamableHttpClient(service.URL, transport.WithHTTPHeaders(headers))

	case "sse":
		if service.URL == "" {
			return nil, fmt.Errorf("URL is required for sse transport")
		}

		c, err = client.NewOAuthSSEClient(service.URL, oauthConfig, transport.WithHeaders(headers))

	case "stdio":
		if len(service.Command) == 0 {
			return nil, fmt.Errorf("command is required for stdio transport")
		}
		// stdio transport doesn't support this OAuth flow. We can pass the token via env vars if needed.
		githubPat, err := gw.getGitHubPat(ctx, userID)
		if err != nil {
			return nil, err
		}
		env := []string{"GITHUB_TOKEN=" + githubPat}
		c, err = client.NewStdioMCPClient(service.Command[0], env, service.Command[1:]...)
		if err != nil {
			return nil, fmt.Errorf("failed to create stdio client for service %s: %w", service.Name, err)
		}
	default:
		return nil, fmt.Errorf("unknown transport %q", service.Transport)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create client for service %s: %w", service.Name, err)
	}

	initCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if needsStart(c) {
		startErr := c.Start(initCtx)
		if client.IsOAuthAuthorizationRequiredError(startErr) {
			c.Close()
			return nil, fmt.Errorf(
				"authorization required for service %s. The user's token may be missing or expired, and a refresh failed. Please ask the user to reconnect the service in their settings",
				service.Name,
			)
		}
		if startErr != nil {
			c.Close()
			return nil, fmt.Errorf("failed to start client transport for %s: %w", service.Name, startErr)
		}
	}

	_, initErr := c.Initialize(initCtx, mcp.InitializeRequest{
		Params: struct {
			ProtocolVersion string                 `json:"protocolVersion"`
			Capabilities    mcp.ClientCapabilities `json:"capabilities"`
			ClientInfo      mcp.Implementation     `json:"clientInfo"`
		}{ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION},
	})
	if initErr != nil {
		c.Close()
		return nil, fmt.Errorf("failed to initialize connection for %s: %w", service.Name, initErr)
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

	discoveredTools := gw.discoverUserTools(ctx, userID, targetServices)

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

func (gw *GatewayServer) discoverUserTools(ctx context.Context, userID string, services []config.ServiceConfig) []mcp.Tool {
	var wg sync.WaitGroup
	toolChan := make(chan mcp.Tool, 100)

	for _, service := range services {
		wg.Add(1)
		go func(s config.ServiceConfig) {
			defer wg.Done()

			// `ListTools` for Atlassian will fail without a cloudId, so no point attempting.
			// We just produce the single, known bootstrap tool.
			if s.Name == "atlassian" {
				log.Println("Gateway: Providing bootstrap tool for Atlassian service.")
				bootstrapTool := mcp.NewTool("atlassian__getAccessibleAtlassianResources",
					mcp.WithDescription("Returns a list of Atlassian resources (sites) accessible to the user. This MUST be called first to find the 'cloudId' required by other Atlassian tools."),
				)
				toolChan <- bootstrapTool
				return
			}

			client, err := gw.createClientForService(ctx, userID, s)
			if err != nil {
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
				if s.Name == "atlassian" && strings.Contains(tool.Name, "transitionJiraIssue") {
					log.Printf("Gateway: Skipping malformted Atlassian tool: %s", tool.Name)
					continue
				}
				tool.Name = fmt.Sprintf("%s__%s", s.Name, tool.Name)
				toolChan <- tool
			}
		}(service)
	}

	wg.Wait()
	close(toolChan)

	var allTools []mcp.Tool
	for tool := range toolChan {
		allTools = append(allTools, tool)
	}
	return allTools
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

	// cloudId injection for Atlassian
	if serviceName == "atlassian" {
		if originalToolName != "getAccessibleAtlassianResources" {
			if _, hasCloudId := args["cloudId"]; !hasCloudId {
				log.Printf("Gateway: Atlassian tool %q called without cloudId for user %s. Attempting to discover...", fqn, userID)

				tempTokenStore := rk_mcp.NewGatewayTokenStore(gw.db, userID, "atlassian")
				tempToken, err := tempTokenStore.GetToken()
				if err != nil {
					return mcp.NewToolResultError("Failed to get Atlassian token for cloudId discovery: " + err.Error()), nil
				}

				cloudId, err := gw.discoverUserCloudId(ctx, userID, tempToken.AccessToken)
				if err != nil {
					log.Printf("Gateway: Error - Failed to discover cloudId for user %s: %v", userID, err)
					return mcp.NewToolResultError("Failed to automatically discover Atlassian cloudId. Error: " + err.Error()), nil
				}

				if cloudId == "" {
					return mcp.NewToolResultError("Could not find any accessible Atlassian resources for you. Please ensure you've granted access to at least one Atlassian site."), nil
				}

				log.Printf("Gateway: Discovered cloudId %s for user %s. Injecting into tool args.", cloudId, userID)
				args["cloudId"] = cloudId
			}
		}
	}

	log.Printf("Gateway: Routing tool call %q to service %s", fqn, serviceConfig.Name)

	downstreamClient, err := gw.createClientForService(ctx, userID, serviceConfig)
	if err != nil {
		log.Printf("Gateway: ERROR - Failed to create client for %q: %v", fqn, err)
		return mcp.NewToolResultError(err.Error()), nil
	}
	defer downstreamClient.Close()

	downstreamReq := mcp.CallToolRequest{}
	downstreamReq.Params.Name = originalToolName
	downstreamReq.Params.Arguments = args

	log.Printf("Gateway: Forwarding request for tool %q to downstream service...", downstreamReq.Params.Name)
	return downstreamClient.CallTool(ctx, downstreamReq)
}

// discoverUserCloudId uses the user's credentials to call the `getAccessibleAtlassianResources` tool
// and extracts the first cloudId from the result.
func (gw *GatewayServer) discoverUserCloudId(ctx context.Context, userID string, authToken string) (string, error) {
	const getResourcesToolFQN = "atlassian__getAccessibleAtlassianResources"
	serviceConfig, found := gw.registry.GetServiceConfig("atlassian")
	if !found {
		return "", fmt.Errorf("internal configuration error: %s tool not found in registry", getResourcesToolFQN)
	}

	client, err := client.NewSSEMCPClient(serviceConfig.URL, transport.WithHeaders(map[string]string{
		"Authorization": "Bearer " + authToken,
	}))
	if err != nil {
		return "", fmt.Errorf("failed to create internal client to discover cloudId: %w", err)
	}
	defer client.Close()

	if startErr := client.Start(ctx); startErr != nil {
		return "", fmt.Errorf("failed to start internal client: %w", startErr)
	}

	_, initErr := client.Initialize(ctx, mcp.InitializeRequest{
		Params: struct {
			ProtocolVersion string                 `json:"protocolVersion"`
			Capabilities    mcp.ClientCapabilities `json:"capabilities"`
			ClientInfo      mcp.Implementation     `json:"clientInfo"`
		}{ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION},
	})
	if initErr != nil {
		client.Close()
		return "", fmt.Errorf("failed to initialize internal client for %s: %w", serviceConfig.Name, initErr)
	}

	req := mcp.CallToolRequest{}
	req.Params.Name = "getAccessibleAtlassianResources"
	req.Params.Arguments = map[string]any{}

	log.Printf("Gateway: Calling `getAccessibleAtlassianResources` for user %s to find cloudId.", userID)
	result, err := client.CallTool(ctx, req)
	if err != nil {
		return "", fmt.Errorf("error calling getAccessibleAtlassianResources: %w", err)
	}
	if result.IsError {
		errorContent := "unknown error"
		if len(result.Content) > 0 {
			if tc, ok := result.Content[0].(mcp.TextContent); ok {
				errorContent = tc.Text
			}
		}
		return "", fmt.Errorf("error calling getAccessibleAtlassianResources: %s", errorContent)
	}

	if len(result.Content) == 0 {
		return "", fmt.Errorf("getAccessibleAtlassianResources returned no content")
	}

	textContent, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		return "", fmt.Errorf("unexpected content type from getAccessibleAtlassianResources: expected text")
	}

	var resources []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(textContent.Text), &resources); err != nil {
		return "", fmt.Errorf("failed to parse resources from tool result: %w. Raw text: %s", err, textContent.Text)
	}

	if len(resources) == 0 {
		return "", nil
	}

	return resources[0].ID, nil
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
