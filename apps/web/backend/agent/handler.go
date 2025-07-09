package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/arnavsurve/routekit/pkg/llm"
	"github.com/arnavsurve/routekit/pkg/llm/providers"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
)

const gatewayURL = "http://localhost:8080/mcp"

var upgrader = websocket.Upgrader{}

type SessionHandler struct {
	gatewayClient *client.Client
	llmProvider   llm.Provider
	conversation  []llm.Message
	systemPrompt  string
	userJWT       string
}

type WebsocketMessage struct {
	Type    string `json:"type"`
	Sender  string `json:"sender"`
	Content any    `json:"content"`
}

type ToolCallInfo struct {
	Name string `json:"name"`
	Args string `json:"args"`
}

type ToolResultInfo struct {
	Name    string `json:"name"`
	Result  string `json:"result"`
	IsError bool   `json:"is_error"`
}

func HandleWebSocket(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)

	providerConfig := llm.ProviderConfig{
		Type:   c.QueryParam("provider"),
		APIKey: c.QueryParam("api_key"),
		Model:  c.QueryParam("model"),
	}

	if providerConfig.Type == "" {
		providerConfig.Type = "anthropic"
		providerConfig.APIKey = os.Getenv("ANTHROPIC_API_KEY")
		providerConfig.Model = "claude-3-5-sonnet-20241022"
	}

	handler, err := newSessionHandler(user.Raw, providerConfig)
	if err != nil {
		log.Printf("Failed to create session handler: %v\n", err)
		return c.String(http.StatusInternalServerError, "Failed to start agent session")
	}

	ws, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		return fmt.Errorf("upgrading to websocket: %w", err)
	}
	defer ws.Close()

	return handler.runConversation(c, ws)
}

func newSessionHandler(userJWT string, providerCfg llm.ProviderConfig) (*SessionHandler, error) {
	gatewayClient, err := client.NewStreamableHttpClient(gatewayURL)
	if err != nil {
		return nil, fmt.Errorf("creating gateway client: %w", err)
	}

	log.Println("WebApp: Initializing connection to Routekit Gateway...")
	initCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = gatewayClient.Initialize(initCtx, mcp.InitializeRequest{
		Params: struct {
			ProtocolVersion string                 `json:"protocolVersion"`
			Capabilities    mcp.ClientCapabilities `json:"capabilities"`
			ClientInfo      mcp.Implementation     `json:"clientInfo"`
		}{ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION},
	})
	if err != nil {
		return nil, fmt.Errorf("starting gateway client: could not initialize connection: %w", err)
	}
	log.Println("WebApp: Successfully initialized with Routekit Gateway.")

	provider, err := providers.NewProvider(providerCfg)
	if err != nil {
		return nil, fmt.Errorf("creating LLM provider client: %w", err)
	}

	systemPrompt := `You are Routekit, an expert AI assistant capable of getting real work done. Your goal is to help users by using the tools and resources available to you through the Routekit Gateway.

	You have access to two types of capabilities:
	1. **TOOLS** - For actions and operations (creating, updating, searching)
	2. **RESOURCES** - For reading content (files, documents, data)

	You MUST follow this workflow precisely:
	
	1.  **DISCOVER SERVICES:** First, call 'routekit_get_connected_services' to see which external applications are available for the current user. This will return a list of service objects, each with a 'service_slug' (a machine-readable ID) and a 'display_name' (a human-readable name).
    
    2. **SELECT RELEVANT SERVICE(S):** Based on the user's request, identify the most appropriate service from the list. For example, for a coding task or Git repository operation/research, you would identify the 'GitHub' or 'BitBucket' service; for a search task, you might take note of 'Exa Web Search'.
	
	3a. **FOR ACTIONS - GET SERVICE TOOLS:** Call 'routekit_get_service_tools'. Provide a 'services' list containing the 'service_slug'(s) you identified. **You MUST use the 'service_slug', not the 'display_name'**. **ONLY** retrieve tools from the service(s) that is/are explicitly relevant to the current request/conversation.
	
	3b. **FOR READING CONTENT - GET SERVICE RESOURCES:** Call 'routekit_list_resources'. Provide a 'services' list containing the 'service_slug'(s) you identified. This will show you available files, documents, and other readable content.
	
	4a. **EXECUTE TOOLS:** To run a tool, use 'routekit_execute' with the full tool name and arguments.
	
	4b. **READ RESOURCES:** To read content, use 'routekit_read_resource' with the resource URI from the resources list.
	
	**CRITICAL INSTRUCTIONS:**
	- You MUST NOT attempt to call external tools directly. They can ONLY be run via 'routekit_execute'.
	- For reading files or content, always use 'routekit_list_resources' first to find available resources, then 'routekit_read_resource' to read them.
	- Resource URIs are provided in the resources list - use them exactly as given.
	- If a tool call fails with "is a resource, not a tool", use the resource workflow instead.
	
	**Example Tool Usage:**
	{
	  "tool_name": "routekit_execute",
	  "tool_args": {
		"tool_name": "github__search_repositories",
		"tool_args": {
		  "query": "repo:owner/name"
		}
	  }
	}
	
	**Example Resource Usage:**
	1. Call: routekit_list_resources with services: ["github"]
	2. Find resource URI in response: "github://repos/owner/repo/contents/README.md"
	3. Call: routekit_read_resource with resource_uri: "github://repos/owner/repo/contents/README.md"
	
	Whenever assisting a user with a task, be sure to prompt the user to provide ALL necessary details needed. DO NOT MAKE ASSUMPTIONS. DO NOT BE PROACTIVE. When using tools to gather information, be liberal with your searches. Try your best to gather as much information as needed to assist the user with their request. Be detailed.`

	return &SessionHandler{
		gatewayClient: gatewayClient,
		llmProvider:   provider,
		conversation:  []llm.Message{},
		systemPrompt:  systemPrompt,
		userJWT:       userJWT,
	}, nil
}

func (h *SessionHandler) runConversation(c echo.Context, ws *websocket.Conn) error {
	defer h.gatewayClient.Close()
	log.Println("WebApp: Client connected via WebSocket")

	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			log.Println("WebApp: WebSocket read error:", err)
			break
		}

		userMessage := llm.Message{
			Role:    "user",
			Content: string(msg),
		}
		h.conversation = append(h.conversation, userMessage)

		for {
			log.Printf("WebApp: Starting agent turn")
			toolCalls, textResponse, err := h.runAgentTurn(c.Request().Context())
			if err != nil {
				log.Printf("WebApp: Agent turn error: %v", err)
				sendWsMessage(ws, "system_error", "System", ToolResultInfo{Name: "LLM API Call", Result: err.Error(), IsError: true})
				break
			}

			if textResponse != "" {
				log.Printf("WebApp: Agent produced text response: %s", textResponse)
				sendWsMessage(ws, "agent_response", "Agent", textResponse)
			}

			if len(toolCalls) == 0 {
				log.Printf("WebApp: No tool calls requested, conversation turn complete")
				break
			}

			log.Printf("WebApp: Agent requested %d tool calls", len(toolCalls))
			toolResults := h.executeTools(c.Request().Context(), toolCalls, ws)
			if len(toolResults) > 0 {
				// Format tool results properly for the LLM
				var formattedResults []string
				for i, result := range toolResults {
					if i < len(toolCalls) {
						toolName := toolCalls[i].Name
						formattedResults = append(formattedResults, fmt.Sprintf("Tool %s returned:\n%s", toolName, result))
					}
				}

				toolMessage := llm.Message{
					Role:    "user",
					Content: "Tool execution results:\n\n" + strings.Join(formattedResults, "\n\n"),
				}
				h.conversation = append(h.conversation, toolMessage)
			}
		}
	}
	return nil
}

func (h *SessionHandler) runAgentTurn(ctx context.Context) ([]llm.ToolCall, string, error) {
	req := llm.MessageRequest{
		Messages:     h.conversation,
		SystemPrompt: h.systemPrompt,
		MaxTokens:    4096,
	}

	// IMPORTANT: Only provide meta tools to LLM providers
	// External service tools should only be called via routekit_execute
	mcpTools := getMetaToolsDefinition()

	resp, err := h.llmProvider.SendMessageWithTools(ctx, req, convertMCPTools(mcpTools))
	if err != nil {
		return nil, "", fmt.Errorf("calling LLM provider: %w", err)
	}

	// Validate that only meta tools are being called - filter out invalid tools
	var validToolCalls []llm.ToolCall
	for _, toolCall := range resp.ToolCalls {
		if !isValidMetaTool(toolCall.Name) {
			log.Printf("WebApp: WARNING - Agent attempted to call non-meta tool %q directly, will be replaced with error message", toolCall.Name)
			// Create an error tool call that will be handled in executeTools
			errorToolCall := llm.ToolCall{
				ID:   toolCall.ID,
				Name: "_invalid_tool_call",
				Args: map[string]any{
					"original_tool": toolCall.Name,
					"error_message": fmt.Sprintf("Tool %q cannot be called directly. You must use routekit_execute to call external service tools. Please retry by calling routekit_execute with tool_name: %q and your arguments in tool_args", toolCall.Name, toolCall.Name),
				},
			}
			validToolCalls = append(validToolCalls, errorToolCall)
		} else {
			validToolCalls = append(validToolCalls, toolCall)
		}
	}

	assistantMessage := llm.Message{
		Role:    "assistant",
		Content: resp.Content,
	}
	h.conversation = append(h.conversation, assistantMessage)

	return validToolCalls, resp.Content, nil
}

func (h *SessionHandler) executeTools(ctx context.Context, toolCalls []llm.ToolCall, ws *websocket.Conn) []string {
	var toolResults []string

	log.Printf("WebApp: Executing %d tool calls", len(toolCalls))
	for _, toolCall := range toolCalls {
		// Handle validation error tool calls
		if toolCall.Name == "_invalid_tool_call" {
			originalTool := toolCall.Args["original_tool"].(string)
			errorMessage := toolCall.Args["error_message"].(string)

			log.Printf("WebApp: Processing validation error for tool %q", originalTool)

			sendWsMessage(ws, "system_error", "System", ToolResultInfo{
				Name:    originalTool,
				Result:  errorMessage,
				IsError: true,
			})

			toolResults = append(toolResults, errorMessage)
			continue
		}
		toolNameToDisplay := toolCall.Name
		argsBytes, _ := json.MarshalIndent(toolCall.Args, "", "  ")
		toolArgsForDisplay := argsBytes

		if toolCall.Name == "routekit_execute" {
			if fqn, ok := toolCall.Args["tool_name"].(string); ok {
				toolNameToDisplay = fqn
			}
			if toolArgs, ok := toolCall.Args["tool_args"]; ok {
				toolArgsForDisplay, _ = json.MarshalIndent(toolArgs, "", "  ")
			}
		}

		sendWsMessage(ws, "tool_start", "Agent", ToolCallInfo{
			Name: toolNameToDisplay,
			Args: string(toolArgsForDisplay),
		})

		mcpReq := mcp.CallToolRequest{}
		mcpReq.Params.Name = toolCall.Name
		mcpReq.Params.Arguments = toolCall.Args
		mcpReq.Params.Meta = &mcp.Meta{
			AdditionalFields: map[string]any{"jwt": h.userJWT},
		}

		// Log both display args and full args for debugging
		fullArgsBytes, _ := json.MarshalIndent(toolCall.Args, "", "  ")
		log.Printf("WebApp: Calling tool %q with display args: %s", toolCall.Name, string(toolArgsForDisplay))
		log.Printf("WebApp: Full tool args: %s", string(fullArgsBytes))
		result, err := h.gatewayClient.CallTool(ctx, mcpReq)

		// Debug: Log raw result content for debugging resource parsing issues
		if result != nil {
			rawContent, _ := json.MarshalIndent(result, "", "  ")
			if err != nil && strings.Contains(err.Error(), "unsupported resource type") {
				log.Printf("WebApp: DEBUG - Raw MCP result for FAILED tool %q: %s", toolCall.Name, string(rawContent))
			} else if toolCall.Name == "routekit_execute" {
				log.Printf("WebApp: DEBUG - Raw MCP result for tool %q: %s", toolCall.Name, string(rawContent))
			}
		}

		var resultText string
		var isError bool
		if err != nil {
			log.Printf("WebApp: Tool %q failed with error: %v", toolCall.Name, err)
			resultText = err.Error()
			isError = true
		} else if result.IsError {
			if len(result.Content) > 0 {
				if tc, ok := result.Content[0].(mcp.TextContent); ok {
					resultText = tc.Text
				}
			}
			if resultText == "" {
				resultText = "[Downstream service returned an error with no content]"
			}
			log.Printf("WebApp: Tool %q returned error: %s", toolCall.Name, resultText)
			isError = true
		} else {
			contentBytes, jsonErr := json.MarshalIndent(result.Content, "", "  ")
			if jsonErr != nil {
				log.Printf("WebApp: Tool %q failed to marshal result: %v", toolCall.Name, jsonErr)
				resultText = fmt.Sprintf("Failed to marshal result content: %v", jsonErr)
				isError = true
			} else {
				resultText = string(contentBytes)
				isError = false
			}
		}

		if isError {
			sendWsMessage(ws, "system_error", "System", ToolResultInfo{
				Name:    toolNameToDisplay,
				Result:  resultText,
				IsError: true,
			})
		} else {
			sendWsMessage(ws, "tool_result", "Tool", ToolResultInfo{
				Name:    toolNameToDisplay,
				Result:  resultText,
				IsError: false,
			})
		}

		toolResults = append(toolResults, resultText)
	}

	log.Printf("WebApp: Tool execution completed. %d tools executed", len(toolCalls))
	return toolResults
}

// isValidMetaTool checks if a tool name is one of the allowed meta tools
func isValidMetaTool(toolName string) bool {
	validMetaTools := map[string]bool{
		"routekit_get_connected_services": true,
		"routekit_get_service_tools":      true,
		"routekit_execute":                true,
		"routekit_list_resources":         true,
		"routekit_read_resource":          true,
	}
	return validMetaTools[toolName]
}

// convertMCPTools converts anthropic tool definitions to mcp.Tool format
func convertMCPTools(anthropicTools []anthropic.ToolUnionParam) []mcp.Tool {
	var mcpTools []mcp.Tool
	for _, toolUnion := range anthropicTools {
		if toolUnion.OfTool != nil {
			tool := toolUnion.OfTool
			var description string
			if tool.Description.Valid() {
				description = tool.Description.Value
			}
			mcpTool := mcp.Tool{
				Name:        tool.Name,
				Description: description,
				// Note: InputSchema conversion may need adjustment based on mcp.Tool structure
			}
			mcpTools = append(mcpTools, mcpTool)
		}
	}
	return mcpTools
}

func getMetaToolsDefinition() []anthropic.ToolUnionParam {
	getServicesTool := anthropic.ToolParam{
		Name:        "routekit_get_connected_services",
		Description: anthropic.String("Get a list of all external services the current user is authenticated with. This should be the first step in any task requiring external tools."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Type:       "object",
			Properties: map[string]any{}, // No args
		},
	}

	getServiceToolsTool := anthropic.ToolParam{
		Name:        "routekit_get_service_tools",
		Description: anthropic.String("Get all available tools from specified services."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Type: "object",
			Properties: map[string]any{
				"services": map[string]any{
					"type":        "array",
					"description": "A list of service names (from 'routekit_get_connected_services') to get tools from.",
					"items": map[string]any{
						"type": "string",
					},
				},
			},
			Required: []string{"services"},
		},
	}

	executeTool := anthropic.ToolParam{
		Name:        "routekit_execute",
		Description: anthropic.String("Executes a tool by its fully-qualified name with the given arguments."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Type: "object",
			Properties: map[string]any{
				"tool_name": map[string]any{
					"type":        "string",
					"description": "The full namespaced name of the tool to execute, e.g., 'devops-service__get_service_health'.",
				},
				"tool_args": map[string]any{
					"type":                 "object",
					"description":          "A JSON object containing the arguments for the tool.",
					"additionalProperties": true,
				},
			},
			Required: []string{"tool_name", "tool_args"},
		},
	}

	listResourcesTool := anthropic.ToolParam{
		Name:        "routekit_list_resources",
		Description: anthropic.String("Lists available resources (like files, documents) from specified services."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Type: "object",
			Properties: map[string]any{
				"services": map[string]any{
					"type":        "array",
					"description": "A list of service names to get resources from.",
					"items": map[string]any{
						"type": "string",
					},
				},
			},
			Required: []string{"services"},
		},
	}

	readResourceTool := anthropic.ToolParam{
		Name:        "routekit_read_resource",
		Description: anthropic.String("Reads the content of a specific resource by its URI."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Type: "object",
			Properties: map[string]any{
				"resource_uri": map[string]any{
					"type":        "string",
					"description": "The resource URI from the resources list.",
				},
			},
			Required: []string{"resource_uri"},
		},
	}

	return []anthropic.ToolUnionParam{
		{OfTool: &getServicesTool},
		{OfTool: &getServiceToolsTool},
		{OfTool: &executeTool},
		{OfTool: &listResourcesTool},
		{OfTool: &readResourceTool},
	}
}

func sendWsMessage(ws *websocket.Conn, msgType, sender string, content any) {
	message := WebsocketMessage{
		Type:    msgType,
		Sender:  sender,
		Content: content,
	}
	jsonMsg, err := json.Marshal(message)
	if err != nil {
		log.Printf("WebApp: ERROR - Failed to marshal WebSocket message: %v", err)
		return
	}
	if err := ws.WriteMessage(websocket.TextMessage, jsonMsg); err != nil {
		log.Printf("WebApp: WebSocket write error: %v", err)
	}
}
