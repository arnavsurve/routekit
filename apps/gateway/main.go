package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
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
	"gopkg.in/yaml.v2"
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
	registry            *registry.Registry
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
		registry:            registry.New(dbPool),
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

func (gw *GatewayServer) getUserServiceConfigs(ctx context.Context, userID string) ([]config.ServiceConfig, error) {
	var configYAML string
	err := gw.db.QueryRow(ctx, "SELECT config_yaml FROM user_service_configs WHERE user_id = $1", userID).Scan(&configYAML)
	if err != nil {
		if err == pgx.ErrNoRows {
			return []config.ServiceConfig{}, nil
		}
		return nil, fmt.Errorf("failed to get user service config: %w", err)
	}

	var serviceFile struct {
		Services []config.ServiceConfig `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(configYAML), &serviceFile); err != nil {
		return nil, fmt.Errorf("failed to parse user service config YAML: %w", err)
	}

	return serviceFile.Services, nil
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

		log.Printf("Gateway: Cached client for %s failed ping, creaing new one.", cacheKey)
		gw.clientCache.Delete(cacheKey)
		clientInstance.Close()
	}

	lock, _ := gw.clientCreationLocks.LoadOrStore(cacheKey, &sync.Mutex{})
	creationLock := lock.(*sync.Mutex)
	creationLock.Lock()
	defer creationLock.Unlock()

	// Double check cache after acquiring lock in case another goroutine created the client
	// while we were waiting for the lock.
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

	if transportWithCtx, ok := newClient.GetTransport().(transportWithContext); ok {
		go func() {
			<-transportWithCtx.Context().Done()
			log.Printf("Gateway: Client connection for %s closed. Removing from cache.", cacheKey)
			gw.clientCache.Delete(cacheKey)
			gw.clientCreationLocks.Delete(cacheKey)
		}()
	} else if transportWithCancel, ok := newClient.GetTransport().(transportWithCancel); ok {
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				<-ticker.C
				pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
				err := newClient.Ping(pingCtx)
				pingCancel()
				if err != nil {
					log.Printf("Gateway: Client for %s failed health check. Closing and removing from cache.", cacheKey)
					transportWithCancel.Cancel()
					gw.clientCache.Delete(cacheKey)
					gw.clientCreationLocks.Delete(cacheKey)
					return
				}
			}
		}()
	} else {
		log.Printf("Gateway: Warning - transport for %s does not expose context for automatic cleanup.", service.Name)
	}

	return newClient, nil
}

func (gw *GatewayServer) createClientForService(ctx context.Context, userID string, service config.ServiceConfig) (*client.Client, error) {
	log.Printf("Gateway: Creating client for service %q using auth type %q at %s", service.Name, service.Auth.Type, service.URL)

	var c *client.Client
	var err error

	credentials, err := gw.getCredentialsForService(ctx, userID, service.Name)
	if err != nil {
		return nil, err
	}

	switch service.Transport {
	case "stdio":
		if len(service.Command) == 0 {
			return nil, fmt.Errorf("command is required for stdio transport for service %s", service.Name)
		}

		// For stdio services like Atlassian/Linear, we need a unique config dir per user/service
		// to isolate OAuth tokens managed by mcp-remote.
		configDir := fmt.Sprintf("/tmp/routekit_auth/user_%s_service_%s", userID, service.Name)
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create auth config dir: %w", err)
		}

		env := []string{"MCP_REMOTE_CONFIG_DIR=" + configDir}

		command := service.Command[0]
		args := service.Command[1:]

		c, err = client.NewStdioMCPClient(command, env, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to create stdio client for %s: %w", service.Name, err)
		}

		authURLChan := make(chan string)
		errChan := make(chan error, 1)
		stderr, ok := client.GetStderr(c)
		if !ok {
			c.Close()
			return nil, fmt.Errorf("failed to get stderr from stdio client for %s", service.Name)
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
					return
				}
			}

			if err := scanner.Err(); err != nil {
				errChan <- fmt.Errorf("failed to scan stderr from stdio client for %s: %w", service.Name, err)
			}
		}()

		initCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var initErr error
		initDone := make(chan struct{})
		go func() {
			_, initErr = c.Initialize(initCtx, mcp.InitializeRequest{
				Params: mcp.InitializeParams{
					ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
				},
			})
			close(initDone)
		}()

		select {
		case authURL := <-authURLChan:
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
			log.Printf("Gateway: Successfully initialized stdio client for %s without needing new auth.", service.Name)
			return c, nil

		case err := <-errChan:
			c.Close()
			return nil, err

		case <-initCtx.Done():
			c.Close()
			return nil, fmt.Errorf("timeout waiting for stdio client initialization for %s", service.Name)
		}

	case "sse", "streamable-http":
		var opts []transport.StreamableHTTPCOption

		switch service.Auth.Type {
		case "pat":
			if len(credentials) == 0 {
				return nil, fmt.Errorf(`{"action_required": "user_authentication", "service_name": "%s"}`, service.Name)
			}
			opts = append(opts, transport.WithHTTPHeaders(map[string]string{"Authorization": "Bearer " + string(credentials)}))
		case "api_key":
			if len(credentials) == 0 {
				return nil, fmt.Errorf(`"action_required": "user_authentication", "service_name": "%s"`, service.Name)
			}
			opts = append(opts, transport.WithHTTPHeaders(map[string]string{service.Auth.HeaderName: string(credentials)}))
		case "oauth2.1":
			return nil, fmt.Errorf("direct oauth2.1 for http transport not yet supported, use stdio with mcp-remote")
		case "none", "":
			// No auth needed
		default:
			return nil, fmt.Errorf("unsupported auth type %q for service %q", service.Auth.Type, service.Name)
		}

		c, err = client.NewStreamableHttpClient(service.URL, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create http client for %s: %w", service.Name, err)
		}

	default:
		return nil, fmt.Errorf("unsupported transport '%q' for service '%s'", service.Transport, service.Name)
	}

	if needsStart(c) {
		if startErr := c.Start(ctx); startErr != nil {
			return nil, fmt.Errorf("failed to start client transport for %s: %w", service.Name, startErr)
		}
	}

	initCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, initErr := c.Initialize(initCtx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION},
	})
	if initErr != nil {
		c.Close()
		return nil, fmt.Errorf("failed to initialize MCP session with %s: %w", service.Name, initErr)
	}

	return c, nil
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
		log.Printf("Gateway: DB erro fetching user service configs for user %s: %v", userID, err)
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

	log.Printf("Gateway: User %s searching for tools with query %q in services %v", userID, query, servicesToSearch)

	allUserConfigs, err := gw.getUserServiceConfigs(ctx, userID)
	if err != nil {
		return mcp.NewToolResultError("failed to load your service configuration"), nil
	}

	var targetServices []config.ServiceConfig
	configMap := make(map[string]config.ServiceConfig)
	for _, cfg := range allUserConfigs {
		configMap[cfg.Name] = cfg
	}

	for _, serviceName := range servicesToSearch {
		if cfg, ok := configMap[serviceName]; ok {
			targetServices = append(targetServices, cfg)
		} else {
			log.Printf("Gateway: WARN - User %s requested search in service %s which is not in their config", userID, serviceName)
		}
	}

	discoveredTools, discoverErr := gw.discoverUserTools(ctx, userID, targetServices)
	if discoverErr != nil {
		return mcp.NewToolResultError(discoverErr.Error()), nil
	}

	log.Printf("Gateway: Discovered %d total tools from services before search.", len(discoveredTools))

	// TODO: Placeholder. Replace with real semantic search. For now, just return all tools that contain
	// the query string in their name or description.
	var foundTools []mcp.Tool
	if query == "" || query == "*" {
		log.Println("Gateway: Handling as a 'list all' query, bypassing semantic search.")
		foundTools = discoveredTools
	} else {
		for _, tool := range discoveredTools {
			if strings.Contains(strings.ToLower(tool.Name), strings.ToLower(query)) ||
				strings.Contains(strings.ToLower(tool.Description), strings.ToLower(query)) {
				foundTools = append(foundTools, tool)
			}
		}
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

	return allTools, firstErr
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
