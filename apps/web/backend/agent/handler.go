package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
)

const gatewayURL = "http://localhost:8080/mcp"

var upgrader = websocket.Upgrader{}

type SessionHandler struct {
	gatewayClient   *client.Client
	anthropicClient anthropic.Client
	conversation    []anthropic.MessageParam
	systemPrompt    string
	userJWT         string
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

	handler, err := newSessionHandler(user.Raw)
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

func newSessionHandler(userJWT string) (*SessionHandler, error) {
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

	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY environment variable is not set")
	}
	anthropicClient := anthropic.NewClient(option.WithAPIKey(apiKey))

	systemPrompt := `You are Routekit, an expert AI assistant capable of getting work done. Your goal is to help users by using the tools available to you through the Routekit Gateway.

	You MUST follow this workflow precisely:
	
	1.  **DISCOVER SERVICES:** First, call 'routekit_get_connected_services' to see which external applications are available for the current user.
	
	2.  **SEARCH FOR TOOLS:** Next, call 'routekit_search_tools'. Provide a natural language 'query' describing the task and a 'services_to_search' list.
	
	3.  **ANALYZE RESULTS:** From the search results, identify the full 'name' of the tool you need to use. This name will include a service prefix, for example: 'atlassian__createJiraIssue'.
	
	4.  **EXECUTE THE TOOL:** To run the tool you found, you MUST call 'routekit_execute'.
		- The 'tool_name' parameter for 'routekit_execute' MUST be the full name from the search result (e.g., 'atlassian__createJiraIssue').
		- The 'tool_args' parameter must be an object containing the arguments for that tool.
	
	**CRITICAL INSTRUCTION:** You MUST NOT attempt to call tools like 'atlassian__createJiraIssue' directly. They can ONLY be run by passing their full name to the 'routekit_execute' tool.
	
	For example, after finding the 'atlassian__createJiraIssue' tool, your next step should be to call 'routekit_execute' like this:
	{
	  "tool_name": "routekit_execute",
	  "tool_args": {
		"tool_name": "atlassian__createJiraIssue",
		"tool_args": {
		  "projectKey": "TEST",
		  "summary": "This is a test ticket",
		  "issueTypeName": "Task"
		}
	  }
	}
	
	If you need more information to fill in the arguments for a tool, you MUST use this same search-and-execute workflow to call other tools to find that information first.`
	
		return &SessionHandler{
			gatewayClient:   gatewayClient,
			anthropicClient: anthropicClient,
			conversation:    []anthropic.MessageParam{},
			systemPrompt:    systemPrompt,
			userJWT:         userJWT,
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

		h.conversation = append(h.conversation, anthropic.NewUserMessage(anthropic.NewTextBlock(string(msg))))

		for {
			toolUseBlocks, textResponse, err := h.runAgentTurn(c.Request().Context())
			if err != nil {
				log.Printf("WebApp: Agent turn error: %v", err)
				sendWsMessage(ws, "system_error", "System", ToolResultInfo{Name: "LLM API Call", Result: err.Error(), IsError: true})
				break
			}

			if textResponse != "" {
				sendWsMessage(ws, "agent_response", "Agent", textResponse)
			}

			if len(toolUseBlocks) == 0 {
				break
			}

			toolResults := h.executeTools(c.Request().Context(), toolUseBlocks, ws)
			h.conversation = append(h.conversation, anthropic.NewUserMessage(toolResults...))
		}
	}
	return nil
}

func (h *SessionHandler) runAgentTurn(ctx context.Context) ([]anthropic.ToolUseBlock, string, error) {
	req := anthropic.MessageNewParams{
		Model:     anthropic.ModelClaude3_5SonnetLatest,
		Messages:  h.conversation,
		System:    []anthropic.TextBlockParam{{Text: h.systemPrompt}},
		MaxTokens: 4096,
		Tools:     getMetaToolsDefinition(),
	}

	resp, err := h.anthropicClient.Messages.New(ctx, req)
	if err != nil {
		return nil, "", fmt.Errorf("calling Anthropic API: %w", err)
	}

	h.conversation = append(h.conversation, resp.ToParam())

	var toolUseBlocks []anthropic.ToolUseBlock
	var finalResponseText string

	for _, block := range resp.Content {
		switch b := block.AsAny().(type) {
		case anthropic.TextBlock:
			finalResponseText += b.Text
		case anthropic.ToolUseBlock:
			toolUseBlocks = append(toolUseBlocks, b)
		}
	}

	return toolUseBlocks, finalResponseText, nil
}

func (h *SessionHandler) executeTools(ctx context.Context, blocks []anthropic.ToolUseBlock, ws *websocket.Conn) []anthropic.ContentBlockParamUnion {
	var toolResults []anthropic.ContentBlockParamUnion

	for _, block := range blocks {
		var args map[string]any
		if err := json.Unmarshal(block.Input, &args); err != nil {
			log.Printf("Error parsing tool args: %v", err)
			resultText := fmt.Sprintf("Error: could not parse arguments: %v", err)
			sendWsMessage(ws, "system_error", "System", ToolResultInfo{Name: block.Name, Result: resultText, IsError: true})
			toolResults = append(toolResults, anthropic.NewToolResultBlock(block.ID, resultText, true))
			continue
		}

		toolNameToDisplay := block.Name
		toolArgsForDisplay := block.Input

		if block.Name == "routekit_execute" {
			if fqn, ok := args["tool_name"].(string); ok {
				toolNameToDisplay = fqn
			}
			if toolArgs, ok := args["tool_args"]; ok {
				toolArgsForDisplay, _ = json.MarshalIndent(toolArgs, "", "  ")
			}
		} else {
			toolArgsForDisplay, _ = json.MarshalIndent(block.Input, "", "  ")
		}

		sendWsMessage(ws, "tool_start", "Agent", ToolCallInfo{
			Name: toolNameToDisplay,
			Args: string(toolArgsForDisplay),
		})

		mcpReq := mcp.CallToolRequest{}
		mcpReq.Params.Name = block.Name
		mcpReq.Params.Arguments = args
		mcpReq.Params.Meta = &mcp.Meta{
			AdditionalFields: map[string]any{"jwt": h.userJWT},
		}
		result, err := h.gatewayClient.CallTool(ctx, mcpReq)

		var resultText string
		var isError bool
		if err != nil {
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
			isError = true
		} else {
			contentBytes, jsonErr := json.MarshalIndent(result.Content, "", "  ")
			if jsonErr != nil {
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

		toolResults = append(toolResults, anthropic.NewToolResultBlock(block.ID, resultText, isError))
	}

	return toolResults
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

	searchTool := anthropic.ToolParam{
		Name:        "routekit_search_tools",
		Description: anthropic.String("Search for available tools based on a natural language query."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Type: "object",
			Properties: map[string]any{
				"query": map[string]any{
					"type":        "string",
					"description": "A description of the task you want to perform.",
				},
				"services_to_search": map[string]any{
					"type":        "array",
					"description": "A list of service names (from 'routekit_get_connected_services') to search within.",
					"items": map[string]any{
						"type": "string",
					},
				},
			},
			Required: []string{"query", "services_to_search"},
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

	return []anthropic.ToolUnionParam{
		{OfTool: &getServicesTool},
		{OfTool: &searchTool},
		{OfTool: &executeTool},
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
