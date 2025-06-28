package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/arnavsurve/routekit/pkg/registry"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type GatewayServer struct {
	mcpServer *server.MCPServer
	registry  *registry.Registry
	// Cache downstream clients later for performance
}

func NewGatewayServer() *GatewayServer {
	s := server.NewMCPServer("Routekit-Gateway", "0.1.0",
		server.WithToolCapabilities(true),
	)

	gw := &GatewayServer{
		mcpServer: s,
		registry:  registry.New(),
	}

	return gw
}

// discoverAndRegisterTools connects to all downstream services and registers their tools.
func (gw *GatewayServer) discoverAndRegisterTools(ctx context.Context) error {
	services := gw.registry.GetServices()
	var wg sync.WaitGroup

	log.Printf("Gateway: Starting discovery of %d services...", len(services))

	for _, service := range services {
		wg.Add(1)
		go func(s registry.Service) {
			defer wg.Done()
			log.Printf("Gateway: Discovering tools from %q at %s", s.Name, s.URL)

			downstreamClient, err := client.NewStreamableHttpClient(s.URL)
			if err != nil {
				log.Printf("Gateway: ERROR - Failed to create downstream client for %q at %s: %v", s.Name, s.URL, err)
				return
			}

			// Initialize connection
			initCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			_, err = downstreamClient.Initialize(initCtx, mcp.InitializeRequest{
				Params: struct {
					ProtocolVersion string                 `json:"protocolVersion"`
					Capabilities    mcp.ClientCapabilities `json:"capabilities"`
					ClientInfo      mcp.Implementation     `json:"clientInfo"`
				}{
					ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
				},
			})
			if err != nil {
				log.Printf("Gateway: ERROR - Failed to initialize connection to %q at %s: %v", s.Name, s.URL, err)
				return
			}

			tools, err := downstreamClient.ListTools(ctx, mcp.ListToolsRequest{})
			if err != nil {
				log.Printf("Gateway: ERROR - Failed to list tools from %q at %s: %v", s.Name, s.URL, err)
				return
			}

			log.Printf("Gateway: Discovered %d tools from %q at %s", len(tools.Tools), s.Name, s.URL)
			gw.registry.RegisterCapabilities(s.URL, tools.Tools)

			for _, tool := range tools.Tools {
				gw.mcpServer.AddTool(tool, gw.routeToolCall)
				log.Printf("Gateway: Registered tool %q from %q at %s", tool.Name, s.Name, s.URL)
			}
		}(service)
	}

	wg.Wait()
	log.Println("Gateway: Discovery complete.")
	return nil
}

func (gw *GatewayServer) routeToolCall(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	capabilityName := req.Params.Name
	log.Printf("Gateway: Routing tool call %q", capabilityName)

	targetURL, found := gw.registry.Resolve(capabilityName)
	if !found {
		log.Printf("Gateway: Capability %q not found in registry", capabilityName)
		return mcp.NewToolResultError(fmt.Sprintf("unknown capability: %s", capabilityName)), nil
	}
	log.Printf("Gateway: Routing tool call %q to %s", capabilityName, targetURL)

	downstreamClient, err := client.NewStreamableHttpClient(targetURL)
	if err != nil {
		log.Printf("Gateway: ERROR - Failed to create client for %q at %s: %v", capabilityName, targetURL, err)
		return mcp.NewToolResultError("internal routing error"), nil
	}
	defer downstreamClient.Close()

	initCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err = downstreamClient.Initialize(initCtx, mcp.InitializeRequest{
		Params: struct {
			ProtocolVersion string                 `json:"protocolVersion"`
			Capabilities    mcp.ClientCapabilities `json:"capabilities"`
			ClientInfo      mcp.Implementation     `json:"clientInfo"`
		}{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
		},
	})
	if err != nil {
		log.Printf("Gateway: ERROR - Failed to intialize connection to %q at %s: %v", capabilityName, targetURL, err)
		return mcp.NewToolResultError("internal routing error: failed to connect to downstream service"), nil
	}

	log.Printf("Gateway: Forwarding request to downstream server...")
	result, err := downstreamClient.CallTool(ctx, req)
	if err != nil {
		log.Printf("Gateway: ERROR - Downstream call failed: %v", err)
		return mcp.NewToolResultError("downstream service failed"), nil
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

	log.Printf("Starting Routekit Gateway on %s", port)
	httpServer := server.NewStreamableHTTPServer(gateway.mcpServer)
	if err := httpServer.Start(port); err != nil {
		log.Fatalf("Gateway: Could not start server: %v", err)
	}
}
