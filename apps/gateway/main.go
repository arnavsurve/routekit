package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/arnavsurve/routekit/pkg/registry"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type GatewayServer struct {
	mcpServer   *server.MCPServer
	registry    *registry.Registry
	clientCache sync.Map
}

func NewGatewayServer() *GatewayServer {
	s := server.NewMCPServer("Routekit-Gateway", "0.1.0",
		server.WithToolCapabilities(true),
	)

	gw := &GatewayServer{
		mcpServer: s,
		registry:  registry.New(),
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
		gw.handleExecute,
	)

	return gw
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

			downstreamClient, err := gw.getDownstreamClient(s.URL)
			if err != nil {
				log.Printf("Gateway: ERROR - Failed to create downstream client for %q at %s: %v", s.Name, s.URL, err)
				return
			}

			tools, err := downstreamClient.ListTools(ctx, mcp.ListToolsRequest{})
			if err != nil {
				log.Printf("Gateway: ERROR - Failed to list tools from %q at %s: %v", s.Name, s.URL, err)
				return
			}
			gw.registry.RegisterCapabilities(ctx, s.Name, s.URL, tools.Tools)
		}(service)
	}
	wg.Wait()
	log.Println("Gateway: Discovery complete. Registry is populated.")
	return nil
}

// getDownstreamClient is a helper to manage clients. For now, it just creates a new one.
// In a production system, this would use a connection pool/cache.
func (gw *GatewayServer) getDownstreamClient(targetURL string) (*client.Client, error) {
	// TODO: Implement client caching using gw.clientCache
	c, err := client.NewStreamableHttpClient(targetURL)
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
		return nil, fmt.Errorf("failed to initialize connection: %w", err)
	}
	return c, nil
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

	jsonRes, err := json.MarshalIndent(foundTools, "", "  ")
	if err != nil {
		log.Printf("Gateway: ERROR serializing search results: %v", err)
		return mcp.NewToolResultError("failed to serialize search results: " + err.Error()), nil
	}

	log.Printf("Gateway: Search results returned to agent:\n%s", string(jsonRes))
	return mcp.NewToolResultText(string(jsonRes)), nil
}

// handleExecute routes a tool call to the correct downstream service.
func (gw *GatewayServer) handleExecute(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	fqn := req.GetString("tool_name", "")
	args, ok := req.GetArguments()["tool_args"].(map[string]any)
	if !ok {
		return mcp.NewToolResultError("tool_args must be an object"), nil
	}

	targetURL, found := gw.registry.Resolve(ctx, fqn)
	if !found {
		log.Printf("Gateway: Capability %q not found in registry", fqn)
		return mcp.NewToolResultError(fmt.Sprintf("Unknown capability: %s. Please use routekit__search_tools to find available tools.", fqn)), nil
	}
	log.Printf("Gateway: Routing tool call %q to %s", fqn, targetURL)

	downstreamClient, err := gw.getDownstreamClient(targetURL)
	if err != nil {
		log.Printf("Gateway: ERROR - Failed to create client for %q at %s: %v", fqn, targetURL, err)
		return mcp.NewToolResultError("internal routing error: " + err.Error()), nil
	}
	defer downstreamClient.Close()

	nameParts := strings.SplitN(fqn, "__", 2)
	if len(nameParts) != 2 {
		return mcp.NewToolResultError(fmt.Sprintf("invalid tool name format: %s", fqn)), nil
	}

	downstreamReq := mcp.CallToolRequest{}
	downstreamReq.Params.Name = nameParts[1]
	downstreamReq.Params.Arguments = args

	log.Printf("Gateway: Forwarding request for tool %q to downstream service...", downstreamReq.Params.Name)
	result, err := downstreamClient.CallTool(ctx, downstreamReq)
	if err != nil {
		log.Printf("Gateway: ERROR - Downstream call failed: %v", err)
		return mcp.NewToolResultError("downstream service failed to execute the tool: " + err.Error()), nil
	}

	log.Printf("Gateway: Received result from downstream. Returning to agent.")
	return result, nil
}

func main() {
	gateway := NewGatewayServer()
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
