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
	"github.com/arnavsurve/routekit/pkg/registry"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"golang.org/x/oauth2"
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

func (gw *GatewayServer) createClientForService(service config.ServiceConfig, authToken string) (*client.Client, error) {
	log.Printf("Gateway: Creating client for service %q with transport %q at %s", service.Name, service.Transport, service.URL)

	var c *client.Client
	var err error

	var httpOpts []transport.StreamableHTTPCOption
	var sseOpts []transport.ClientOption
	if authToken != "" {
		log.Printf("Gateway: Using auth token %s", authToken)
		headers := map[string]string{"Authorization": "Bearer " + authToken}
		httpOpts = append(httpOpts, transport.WithHTTPHeaders(headers))
		sseOpts = append(sseOpts, transport.WithHeaders(headers))
	}

	switch service.Transport {
	case "streamable-http":
		if service.URL == "" {
			return nil, fmt.Errorf("URL is required for streamable-http transport")
		}
		c, err = client.NewStreamableHttpClient(service.URL, httpOpts...)

	case "sse":
		if service.URL == "" {
			return nil, fmt.Errorf("URL is required for sse transport")
		}
		c, err = client.NewSSEMCPClient(service.URL, sseOpts...)

	case "stdio":
		if len(service.Command) == 0 {
			return nil, fmt.Errorf("command is required for stdio transport")
		}
		command := service.Command[0]
		args := service.Command[1:]
		c, err = client.NewStdioMCPClient(command, nil, args...)
	default:
		return nil, fmt.Errorf("unknown transport %q", service.Transport)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create client for service %s: %w", service.Name, err)
	}

	initCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if needsStart(c) {
		if startErr := c.Start(initCtx); startErr != nil {
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

// needsStart is a helper to check if the client transport needs to be explicitly started.
// The `mcp-go` v0.32.0 `NewStdioMCPClient` starts the client automatically,
// while others like SSE and StreamableHTTP require an explicit `Start()` call.
// We can check the transport type to be safe.
func needsStart(c *client.Client) bool {
	switch c.GetTransport().(type) {
	case *transport.Stdio:
		return false
	default:
		return true
	}
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

			authToken, err := gw.getAuthTokenForService(ctx, userID, s.Name)
			if err != nil {
				log.Printf("Gateway: Skipping discovery for %s for user %s: %v", s.Name, userID, err)
				return
			}

			client, err := gw.createClientForService(s, authToken)
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

func (gw *GatewayServer) getAuthTokenForService(ctx context.Context, userID, serviceName string) (string, error) {
	var encryptedCreds []byte
	err := gw.db.QueryRow(ctx, "SELECT credentials_encrypted FROM connected_services WHERE user_id = $1 AND service_name = $2", userID, serviceName).Scan(&encryptedCreds)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", fmt.Errorf("user %s is not connected to service %s. Please ask the user to connect their account in settings", userID, serviceName)
		}
		return "", fmt.Errorf("db error fetching credentials for %s: %v", serviceName, err)
	}

	decryptedCreds, err := crypto.Decrypt(encryptedCreds)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt credentials for %s: %v", serviceName, err)
	}

	switch serviceName {
	case "github":
		return string(decryptedCreds), nil
	case "atlassian":
		var token oauth2.Token
		if err := json.Unmarshal(decryptedCreds, &token); err != nil {
			return "", fmt.Errorf("failed to parse Atlassian token: %w", err)
		}

		conf := &oauth2.Config{
			ClientID:     os.Getenv("ATLASSIAN_CLIENT_ID"),
			ClientSecret: os.Getenv("ATLASSIAN_CLIENT_SECRET"),
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://auth.atlassian.com/authorize",
				TokenURL: "https://auth.atlassian.com/oauth/token",
			},
		}

		tokenSource := conf.TokenSource(ctx, &token)
		refreshedToken, err := tokenSource.Token()
		if err != nil {
			return "", fmt.Errorf("failed to refresh Atlassian token: %v", err)
		}

		if refreshedToken.AccessToken != token.AccessToken {
			log.Printf("Gateway: Refreshed Atlassian token for user %s", userID)

			newTokensBytes, err := json.Marshal(refreshedToken)
			if err != nil {
				return "", fmt.Errorf("failed to marshal refreshed token: %w", err)
			}
			newEncryptedTokens, err := crypto.Encrypt(newTokensBytes)
			if err != nil {
				return "", fmt.Errorf("failed to encrypt new token: %w", err)
			}

			_, err = gw.db.Exec(ctx, `
				UPDATE connected_services
				SET credentials_encrypted = $1
				WHERE user_id = $2 AND service_name = 'atlassian'
			`, newEncryptedTokens, userID)
			if err != nil {
				// Log this but proceed with new token for this request
				log.Printf("Gateway: ERROR - Failed to save refreshed Atlassian token for user %s: %v", userID, err)
			}
		}

		return refreshedToken.AccessToken, nil
	default:
		return "", fmt.Errorf("unhandled auth type for service %s", serviceName)
	}
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

	downstreamAuthToken, err := gw.getAuthTokenForService(ctx, userID, serviceName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	switch serviceName {
	case "github":
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

	case "atlassian":
		var encryptedTokens []byte
		err := gw.db.QueryRow(ctx, "SELECT credentials_encrypted FROM connected_services WHERE user_id = $1 AND service_name = 'atlassian'", userID).Scan(&encryptedTokens)
		if err != nil {
			if err == pgx.ErrNoRows {
				return mcp.NewToolResultError("Atlassian not connected. Please connect your Atlassian account in settings."), nil
			}
			return mcp.NewToolResultError("internal database error: " + err.Error()), nil
		}

		decryptedTokens, err := crypto.Decrypt(encryptedTokens)
		if err != nil {
			return mcp.NewToolResultError("internal encryption error: " + err.Error()), nil
		}

		var token oauth2.Token
		if err := json.Unmarshal(decryptedTokens, &token); err != nil {
			return mcp.NewToolResultError("internal token error: " + err.Error()), nil
		}

		conf := &oauth2.Config{
			ClientID:     os.Getenv("ATLASSIAN_CLIENT_ID"),
			ClientSecret: os.Getenv("ATLASSIAN_CLIENT_SECRET"),
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://auth.atlassian.com/authorize",
				TokenURL: "https://auth.atlassian.com/oauth/token",
			},
		}

		tokenSource := conf.TokenSource(ctx, &token)

		refreshedToken, err := tokenSource.Token()
		if err != nil {
			log.Printf("Gateway: ERROR - Failed to refresh Atlassian token for user %s: %v", userID, err)
			return mcp.NewToolResultError("Failed to refresh Atlassian authentication token. Please try reconnecting your account."), nil
		}

		if refreshedToken.AccessToken != token.AccessToken {
			log.Printf("Gateway: Refreshed Atlassian token for user %s", userID)
			newTokenData, err := json.Marshal(refreshedToken)
			if err != nil {
				log.Printf("Gateway: ERROR - Failed to marshal refreshed token: %v", err)
				// Continue with the new token, but log the failure to persist it.
			} else {
				encryptedNewToken, err := crypto.Encrypt(newTokenData)
				if err != nil {
					log.Printf("Gateway: ERROR - Failed to encrypt refreshed token: %v", err)
				} else {
					go func() {
						_, dbErr := gw.db.Exec(context.Background(),
							"UPDATE connected_services SET credentials_encrypted = $1 WHERE user_id = $2 AND service_name = 'atlassian'",
							encryptedNewToken, userID)
						if dbErr != nil {
							log.Printf("Gateway: ERROR - Failed to save refreshed Atlassian token for user %s: %v", userID, dbErr)
						}
					}()
				}
			}
		}

		downstreamAuthToken = refreshedToken.AccessToken
	default:
		log.Printf("Gateway: No specific auth method found for service %q. Proceeding without a token.", serviceName)
	}

	// cloudId injection for Atlassian
	if serviceName == "atlassian" {
		if originalToolName != "getAccessibleAtlassianResources" {
			if _, hasCloudId := args["cloudId"]; !hasCloudId {
				log.Printf("Gateway: Atlassian tool %q called without cloudId for user %s. Attempting to discover...", fqn, userID)
				cloudId, err := gw.discoverUserCloudId(ctx, userID, downstreamAuthToken)
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

	downstreamClient, err := gw.createClientForService(serviceConfig, downstreamAuthToken)
	if err != nil {
		log.Printf("Gateway: ERROR - Failed to create client for %q: %v", fqn, err)
		return mcp.NewToolResultError("internal routing error: " + err.Error()), nil
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

	client, err := gw.createClientForService(serviceConfig, authToken)
	if err != nil {
		return "", fmt.Errorf("failed to create internal client to discover cloudId: %w", err)
	}
	defer client.Close()

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
