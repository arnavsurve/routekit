package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/arnavsurve/routekit/pkg/config"
	"github.com/arnavsurve/routekit/pkg/crypto"
	"github.com/arnavsurve/routekit/pkg/db"
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
	mcpServer           *server.MCPServer
	db                  *pgxpool.Pool
	jwtSecret           []byte
	clientCache         *sync.Map
	clientCreationLocks *sync.Map
}

type contextKey string

const userIDKey contextKey = "user_id"

func NewGatewayServer(dbPool *pgxpool.Pool, secret []byte) *GatewayServer {
	s := server.NewMCPServer("Routekit-Gateway", "0.1.0",
		server.WithToolCapabilities(true),
	)

	gw := &GatewayServer{
		mcpServer:           s,
		db:                  dbPool,
		jwtSecret:           secret,
		clientCache:         &sync.Map{},
		clientCreationLocks: &sync.Map{},
	}

	s.AddTool(
		mcp.NewTool("routekit_get_connected_services",
			mcp.WithDescription("Get a list of all external services the current user is authenticated with."),
		),
		gw.mcpAuthMiddleware(gw.handleGetConnectedServices),
	)

	s.AddTool(
		mcp.NewTool("routekit_get_service_tools",
			mcp.WithDescription("Get all available tools from specified services."),
			mcp.WithArray("services", mcp.Required(), mcp.Description("A list of service names (from 'get_connected_services') to get tools from.")),
		),
		gw.mcpAuthMiddleware(gw.handleGetServiceTools),
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

func (gw *GatewayServer) getUserServiceConfigs(ctx context.Context, userID string) ([]config.ServiceConfig, error) {
	rows, err := gw.db.Query(ctx, `
		SELECT id, service_name, transport_type, mcp_server_url, auth_type, 
		       auth_config_encrypted, scopes, audience, command, working_dir, environment_vars
		FROM user_service_configs 
		WHERE user_id = $1
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user service configs: %w", err)
	}
	defer rows.Close()

	var services []config.ServiceConfig
	for rows.Next() {
		var service config.ServiceConfig
		var authConfigEncrypted, scopesJSON, envVarsJSON []byte

		err := rows.Scan(
			&service.ID, &service.Name, &service.TransportType, &service.MCPServerURL,
			&service.AuthType, &authConfigEncrypted, &scopesJSON, &service.Audience,
			&service.Command, &service.WorkingDir, &envVarsJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan service config: %w", err)
		}

		// Parse scopes JSON
		var scopes []string
		if scopesJSON != nil {
			if err := json.Unmarshal(scopesJSON, &scopes); err != nil {
				scopes = []string{}
			}
		} else {
			scopes = []string{}
		}

		// Decrypt auth config
		authConfigJSON, err := crypto.Decrypt(authConfigEncrypted)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt auth config: %w", err)
		}

		if err := json.Unmarshal(authConfigJSON, &service.AuthConfig); err != nil {
			return nil, fmt.Errorf("failed to parse auth config: %w", err)
		}

		service.UserID = userID
		service.Scopes = scopes
		services = append(services, service)
	}

	return services, nil
}

func (gw *GatewayServer) getOrCreateClient(ctx context.Context, userID string, service config.ServiceConfig) (*client.Client, error) {
	cacheKey := userID + ":" + service.Name

	// Check cache for an existing, healthy client
	if cachedClient, ok := gw.clientCache.Load(cacheKey); ok {
		clientInstance := cachedClient.(*client.Client)
		pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := clientInstance.Ping(pingCtx); err == nil {
			log.Printf("Gateway: Reusing cached client for %s", cacheKey)
			return clientInstance, nil
		}
		log.Printf("Gateway: Cached client for %s failed ping, creaing new one.", cacheKey)
		gw.clientCache.Delete(cacheKey)
		clientInstance.Close()
	}

	// Lock to prevent concurrent client creation for same user/service
	lock, _ := gw.clientCreationLocks.LoadOrStore(cacheKey, &sync.Mutex{})
	creationLock := lock.(*sync.Mutex)
	creationLock.Lock()
	defer creationLock.Unlock()

	// Double check cache after acquiring lock in case another goroutine created the client
	if cachedClient, ok := gw.clientCache.Load(cacheKey); ok {
		log.Printf("Gateway: Reusing client for %s (created by another goroutine)", cacheKey)
		return cachedClient.(*client.Client), nil
	}

	log.Printf("Gateway: No cached client for %s, creating new connection...", cacheKey)

	newClient, err := gw.createClientForService(ctx, userID, service)
	if err != nil {
		return nil, err
	}

	gw.clientCache.Store(cacheKey, newClient)
	log.Printf("Gateway: Stored new client in cache for %s", cacheKey)

	return newClient, nil
}

// createClientForService is the heart of the gateway's dynamic connection logic.
// It instantiates the correct MCP client based on the service's configuration.
func (gw *GatewayServer) createClientForService(ctx context.Context, userID string, service config.ServiceConfig) (*client.Client, error) {
	log.Printf("Gateway: Creating client for service %q (transport: %s, auth: %s)", service.Name, service.TransportType, service.AuthType)

	if service.TransportType == "sse" && service.AuthType == "mcp_remote_managed" {
		log.Printf("Gateway: Handling mcp_remote_managed service %s via stdio", service.Name)

		command := service.GenerateCommand()
		if len(command) == 0 {
			return nil, fmt.Errorf("command generation failed for SSE service %s", service.Name)
		}

		configDir := fmt.Sprintf("/tmp/routekit_auth/user_%s_service_%s", userID, service.Name)
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create auth config dir for mcp-remote: %w", err)
		}

		env := []string{"MCP_REMOTE_CONFIG_DIR=" + configDir}
		cmdName := command[0]
		args := command[1:]

		c, err := client.NewStdioMCPClient(cmdName, env, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to create stdio client for mcp-remote: %w", err)
		}

		// Race initialization against stderr scanning for an auth URL
		authURLChan := make(chan string, 1)
		errChan := make(chan error, 1)
		stderr, ok := client.GetStderr(c)
		if !ok {
			c.Close()
			return nil, fmt.Errorf("failed to get stderr from mcp-remote process for %s", service.Name)
		}

		go func() {
			scanner := bufio.NewScanner(stderr)
			re := regexp.MustCompile(`Please authorize this client by visiting: (https?://\S+)`)
			for scanner.Scan() {
				line := scanner.Text()
				log.Printf("Gateway: [mcp-remote stderr (%s)] %s", service.Name, line)
				matches := re.FindStringSubmatch(line)
				if len(matches) > 1 {
					authURLChan <- matches[1]
					close(authURLChan)
					return
				}
			}
			if err := scanner.Err(); err != nil {
				errChan <- fmt.Errorf("failed to scan stderr from mcp-remote for %s: %w", service.Name, err)
			}
		}()

		initCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var initErr error
		initDone := make(chan struct{})

		go func() {
			_, initErr = c.Initialize(initCtx, mcp.InitializeRequest{
				Params: mcp.InitializeParams{ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION},
			})
			close(initDone)
		}()

		select {
		case authURL, ok := <-authURLChan:
			if !ok { // Channel was closed without sending a URL
				<-initDone // Wait for the init to finish to get the error
				if initErr != nil {
					c.Close()
					return nil, fmt.Errorf("stdio client for %s failed to initialize: %w", service.Name, initErr)
				}
				return nil, fmt.Errorf("mcp-remote process exited without providing an auth URL or initializing")
			}
			log.Printf("Gateway: Intercepted auth URL for %s: %s", service.Name, authURL)
			c.Close()
			jsonResponse := fmt.Sprintf(
				`{"action_required": "user_authentication", "service_name": "%s", "authorization_url": "%s"}`,
				service.Name,
				authURL,
			)
			return nil, errors.New(jsonResponse)
		case <-initDone:
			if initErr != nil {
				c.Close()
				return nil, fmt.Errorf("failed to initialize stdio client for %s: %w", service.Name, initErr)
			}
			log.Printf("Gateway: Successfully initialized stdio client for %s via mcp-remote.", service.Name)
			return c, nil
		case err := <-errChan:
			c.Close()
			return nil, err
		case <-initCtx.Done():
			c.Close()
			return nil, fmt.Errorf("timeout waiting for stdio client initialization for %s", service.Name)
		}
	}

	switch service.TransportType {
	case "streamable-http":
		if service.MCPServerURL == nil || *service.MCPServerURL == "" {
			return nil, fmt.Errorf("missing mcp_server_url for remote service %s", service.Name)
		}
		urlToConnect := *service.MCPServerURL
		headers := make(map[string]string)
		authConfig := service.AuthConfig

		switch service.AuthType {
		case "pat":
			if authConfig.Token == "" {
				return nil, fmt.Errorf(`{"action_required": "user_authentication", "service_name": "%s", "auth_type": "pat"}`, service.Name)
			}
			headers["Authorization"] = "Bearer " + authConfig.Token
		case "api_key_in_header":
			headers[authConfig.HeaderName] = authConfig.APIKey
		case "api_key_in_url":
			parsedURL, _ := url.Parse(urlToConnect)
			query := parsedURL.Query()
			query.Set(authConfig.QueryParamName, authConfig.APIKey)
			parsedURL.RawQuery = query.Encode()
			urlToConnect = parsedURL.String()
		case "no_auth":
			// No headers needed
		default:
			return nil, fmt.Errorf("unsupported auth type %q for remote service %s", service.AuthType, service.Name)
		}

		c, err := client.NewStreamableHttpClient(urlToConnect, transport.WithHTTPHeaders(headers))
		if err != nil {
			return nil, fmt.Errorf("failed to create http client for %s: %w", service.Name, err)
		}

		// Initialize the remote client
		initCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if needsStart(c) {
			if startErr := c.Start(initCtx); startErr != nil {
				return nil, fmt.Errorf("failed to start client transport for %s: %w", service.Name, startErr)
			}
		}
		_, initErr := c.Initialize(initCtx, mcp.InitializeRequest{
			Params: mcp.InitializeParams{ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION},
		})
		if initErr != nil {
			c.Close()
			return nil, fmt.Errorf("failed to initialize MCP session with %s: %w", service.Name, initErr)
		}
		return c, nil

	case "local_stdio":
		return nil, fmt.Errorf("direct local_stdio not yet supported, use sse with mcp_remote_managed")

	default:
		return nil, fmt.Errorf("unsupported or unhandled transport type: %s", service.TransportType)
	}
}

func (gw *GatewayServer) getCredentialsForService(ctx context.Context, userID string, serviceName string) ([]byte, error) {
	var encryptedCreds []byte
	err := gw.db.QueryRow(ctx, "SELECT credentials_encrypted FROM connected_services WHERE user_id = $1 AND service_name = $2", userID, serviceName).Scan(&encryptedCreds)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf(`{"action_required": "user_authentication", "service_name": "%s"}`, serviceName)
		}
		return nil, fmt.Errorf("database error fetching credentials for %s: %w", serviceName, err)
	}

	if len(encryptedCreds) == 0 {
		// This can happen for services like Linear/Atlassian where the connection record
		// exists but credentials are not stored directly.
		return nil, nil
	}

	return crypto.Decrypt(encryptedCreds)
}

func (gw *GatewayServer) handleGetConnectedServices(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	userID, ok := ctx.Value(userIDKey).(string)
	if !ok {
		return mcp.NewToolResultError("Internal error; user ID not found in context"), nil
	}

	configs, err := gw.getUserServiceConfigs(ctx, userID)
	if err != nil {
		log.Printf("Gateway: DB error fetching user service configs for user %s: %v", userID, err)
		return mcp.NewToolResultError("database error"), nil
	}

	var serviceNames []string
	for _, cfg := range configs {
		serviceNames = append(serviceNames, cfg.Name)
	}

	result := map[string][]string{"services": serviceNames}
	jsonRes, _ := json.Marshal(result)

	return mcp.NewToolResultText(string(jsonRes)), nil
}

type SearchResult struct {
	Tools []mcp.Tool `json:"tools"`
}

func (gw *GatewayServer) handleGetServiceTools(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	userID, ok := ctx.Value(userIDKey).(string)
	if !ok {
		return mcp.NewToolResultError("Internal error; user ID not found in context"), nil
	}

	services, err := req.RequireStringSlice("services")
	if err != nil {
		return mcp.NewToolResultError("`services` must be a list of strings."), nil
	}

	log.Printf("Gateway: User %s getting tools from services %v", userID, services)

	allUserConfigs, err := gw.getUserServiceConfigs(ctx, userID)
	if err != nil {
		return mcp.NewToolResultError("failed to load your service configuration"), nil
	}

	var targetServices []config.ServiceConfig
	configMap := make(map[string]config.ServiceConfig)
	for _, cfg := range allUserConfigs {
		configMap[cfg.Name] = cfg
	}

	for _, serviceName := range services {
		if cfg, ok := configMap[serviceName]; ok {
			targetServices = append(targetServices, cfg)
		} else {
			log.Printf("Gateway: WARN - User %s requested tools from service %s which is not in their config", userID, serviceName)
		}
	}

	discoveredTools, discoverErr := gw.discoverUserTools(ctx, userID, targetServices)
	if discoverErr != nil {
		return mcp.NewToolResultError(discoverErr.Error()), nil
	}

	log.Printf("Gateway: Discovered %d total tools from services.", len(discoveredTools))

	searchResult := SearchResult{Tools: discoveredTools}
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

	discoverCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	for _, service := range services {
		wg.Add(1)
		go func(s config.ServiceConfig) {
			defer wg.Done()
			select {
			case <-discoverCtx.Done():
				return
			default:
			}

			c, err := gw.getOrCreateClient(ctx, userID, s)
			if err != nil {
				if strings.Contains(err.Error(), "action_required") {
					errChan <- err
					return
				}
				log.Printf("Gateway: Failed to create client for %s during discovery: %v", s.Name, err)
				return
			}

			tools, err := c.ListTools(ctx, mcp.ListToolsRequest{})
			if err != nil {
				log.Printf("Gateway: Failed to list tools from %s for user %s: %v", s.Name, userID, err)
				gw.clientCache.Delete(userID + ":" + s.Name)
				if closer, ok := c.GetTransport().(io.Closer); ok {
					closer.Close()
				}
				return
			}

			for _, tool := range tools.Tools {
				tool.Name = fmt.Sprintf("%s__%s", s.Name, tool.Name)
				select {
				case toolChan <- tool:
				case <-discoverCtx.Done():
					return
				}
			}
		}(service)
	}

	go func() {
		wg.Wait()
		close(toolChan)
		close(errChan)
	}()

	var allTools []mcp.Tool
	var firstErr error

	for {
		select {
		case tool, ok := <-toolChan:
			if !ok {
				toolChan = nil
			} else {
				allTools = append(allTools, tool)
			}
		case err, ok := <-errChan:
			if !ok {
				errChan = nil
			} else if err != nil && firstErr == nil {
				firstErr = err
			}
		case <-discoverCtx.Done():
			log.Printf("Gateway: Tool discovery timed out.")
			if firstErr != nil {
				return nil, firstErr
			}
			return allTools, discoverCtx.Err()
		}

		if toolChan == nil && errChan == nil {
			break
		}
	}

	if firstErr != nil {
		return nil, firstErr
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
		if req.GetArguments()["tool_args"] == nil {
			args = make(map[string]any)
		} else {
			return mcp.NewToolResultError("tool_args must be an object"), nil
		}
	}

	nameParts := strings.SplitN(fqn, "__", 2)
	if len(nameParts) != 2 {
		return mcp.NewToolResultErrorf("invalid tool name format: %s. Expected 'service__tool'", fqn), nil
	}
	serviceName := nameParts[0]
	originalToolName := nameParts[1]

	allUserConfigs, err := gw.getUserServiceConfigs(ctx, userID)
	if err != nil {
		return mcp.NewToolResultError("failed to load your service configuration"), nil
	}

	var serviceConfig config.ServiceConfig
	var found bool
	for _, cfg := range allUserConfigs {
		if cfg.Name == serviceName {
			serviceConfig = cfg
			found = true
			break
		}
	}

	if !found {
		log.Printf("Gateway: Service %q for tool %q not found in user service config", serviceName, fqn)
		return mcp.NewToolResultErrorf("Unknown service in tool name: %s", serviceName), nil
	}

	downstreamClient, err := gw.getOrCreateClient(ctx, userID, serviceConfig)
	if err != nil {
		if strings.Contains(err.Error(), "action_required") {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultErrorf("failed to create client for %s: %v", serviceName, err), nil
	}

	downstreamReq := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      originalToolName,
			Arguments: args,
		},
	}

	log.Printf("Gateway: Forwarding request for tool %q (%s) to downstream service %s...", originalToolName, fqn, serviceName)
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
