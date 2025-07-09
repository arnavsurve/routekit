package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/arnavsurve/routekit/pkg/llm"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sashabaranov/go-openai"
)

type OpenAIProvider struct {
	client *openai.Client
	config llm.ProviderConfig
}

func NewOpenAIProvider(config llm.ProviderConfig) *OpenAIProvider {
	client := openai.NewClient(config.APIKey)
	if config.BaseURL != "" {
		cfg := openai.DefaultConfig(config.APIKey)
		cfg.BaseURL = config.BaseURL
		client = openai.NewClientWithConfig(cfg)
	}

	return &OpenAIProvider{
		client: client,
		config: config,
	}
}

func (p *OpenAIProvider) SendMessage(ctx context.Context, req llm.MessageRequest) (*llm.MessageResponse, error) {
	openaiMessages := convertToOpenAIMessages(req.Messages)

	if req.SystemPrompt != "" {
		systemMsg := openai.ChatCompletionMessage{
			Role:    "system",
			Content: req.SystemPrompt,
		}
		openaiMessages = append([]openai.ChatCompletionMessage{systemMsg}, openaiMessages...)
	}

	model := "gpt-4o"
	if req.Model != "" {
		model = req.Model
	} else if p.config.Model != "" {
		model = p.config.Model
	}

	openaiReq := openai.ChatCompletionRequest{
		Model:    model,
		Messages: openaiMessages,
	}

	if req.MaxTokens > 0 {
		openaiReq.MaxTokens = req.MaxTokens
	}

	resp, err := p.client.CreateChatCompletion(ctx, openaiReq)
	if err != nil {
		return nil, fmt.Errorf("making openai API call: %w", err)
	}

	return convertFromOpenAIResponse(resp), nil
}

func (p *OpenAIProvider) SendMessageWithTools(ctx context.Context, req llm.MessageRequest, tools []mcp.Tool) (*llm.MessageResponse, error) {
	openaiMessages := convertToOpenAIMessages(req.Messages)

	if req.SystemPrompt != "" {
		systemMsg := openai.ChatCompletionMessage{
			Role:    "system",
			Content: req.SystemPrompt,
		}
		openaiMessages = append([]openai.ChatCompletionMessage{systemMsg}, openaiMessages...)
	}

	model := "gpt-4o"
	if req.Model != "" {
		model = req.Model
	} else if p.config.Model != "" {
		model = p.config.Model
	}

	// Create mapping from clean names to full names for tool call restoration
	toolNameMap := make(map[string]string)
	openaiTools := convertMCPToOpenAIToolsWithMapping(tools, toolNameMap)

	openaiReq := openai.ChatCompletionRequest{
		Model:    model,
		Messages: openaiMessages,
		Tools:    openaiTools,
	}

	if req.MaxTokens > 0 {
		openaiReq.MaxTokens = req.MaxTokens
	}

	resp, err := p.client.CreateChatCompletion(ctx, openaiReq)
	if err != nil {
		return nil, fmt.Errorf("making openai API call: %w", err)
	}

	return convertFromOpenAIResponseWithMapping(resp, toolNameMap), nil
}

func (p *OpenAIProvider) GetName() string {
	return "openai"
}

func (p *OpenAIProvider) GetSupportedModels() []string {
	return []string{
		"gpt-4o-2024-08-06",
		"gpt-4.1-2025-04-14",
		"o4-mini-2025-04-16",
		"o3-2025-04-16",
		"o3-pro-2025-06-10",
		"o3-mini-2025-01-31",
	}
}

func (p *OpenAIProvider) ValidateConfig(config llm.ProviderConfig) error {
	if config.APIKey == "" {
		return fmt.Errorf("API key is required for OpenAI provider")
	}
	if len(config.APIKey) < 40 || !strings.HasPrefix(config.APIKey, "sk-") {
		return fmt.Errorf("invalid OpenAI API key format - should start with 'sk-'")
	}
	return nil
}

func convertToOpenAIMessages(messages []llm.Message) []openai.ChatCompletionMessage {
	var openaiMessages []openai.ChatCompletionMessage

	for _, msg := range messages {
		openaiMsg := openai.ChatCompletionMessage{
			Role:    msg.Role,
			Content: msg.Content,
		}
		openaiMessages = append(openaiMessages, openaiMsg)
	}

	return openaiMessages
}

func convertFromOpenAIResponse(resp openai.ChatCompletionResponse) *llm.MessageResponse {
	var content string
	var toolCalls []llm.ToolCall

	if len(resp.Choices) > 0 {
		choice := resp.Choices[0]
		content = choice.Message.Content

		// Convert tool calls if present
		for _, tc := range choice.Message.ToolCalls {
			toolCall := llm.ToolCall{
				ID:   tc.ID,
				Name: tc.Function.Name,
				Args: make(map[string]any),
			}

			// Parse function arguments JSON
			if tc.Function.Arguments != "" {
				var args map[string]any
				if err := json.Unmarshal([]byte(tc.Function.Arguments), &args); err == nil {
					toolCall.Args = args
				}
			}

			toolCalls = append(toolCalls, toolCall)
		}
	}

	usage := llm.Usage{
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
		TotalTokens:  resp.Usage.TotalTokens,
	}

	var finishReason string
	if len(resp.Choices) > 0 {
		finishReason = string(resp.Choices[0].FinishReason)
	}

	return &llm.MessageResponse{
		Content:      content,
		ToolCalls:    toolCalls,
		Usage:        usage,
		FinishReason: finishReason,
	}
}

func convertMCPToOpenAITools(mcpTools []mcp.Tool) []openai.Tool {
	toolNameMap := make(map[string]string)
	return convertMCPToOpenAIToolsWithMapping(mcpTools, toolNameMap)
}

func convertMCPToOpenAIToolsWithMapping(mcpTools []mcp.Tool, toolNameMap map[string]string) []openai.Tool {
	var openaiTools []openai.Tool

	for _, mcpTool := range mcpTools {
		// Extract clean function name for OpenAI (remove service prefix)
		cleanName := mcpTool.Name
		if parts := strings.SplitN(mcpTool.Name, "__", 2); len(parts) == 2 {
			cleanName = parts[1]
		}
		
		// Store mapping from clean name back to full name
		toolNameMap[cleanName] = mcpTool.Name

		openaiTool := openai.Tool{
			Type: openai.ToolTypeFunction,
			Function: &openai.FunctionDefinition{
				Name:        cleanName, // Use clean name for OpenAI
				Description: mcpTool.Description,
				Parameters:  make(map[string]any),
			},
		}

		// Convert InputSchema from MCP format
		if mcpTool.InputSchema.Type != "" {
			params := map[string]any{
				"type": mcpTool.InputSchema.Type,
			}

			if mcpTool.InputSchema.Properties != nil {
				params["properties"] = mcpTool.InputSchema.Properties
			}

			if mcpTool.InputSchema.Required != nil {
				params["required"] = mcpTool.InputSchema.Required
			}

			openaiTool.Function.Parameters = params
		}

		openaiTools = append(openaiTools, openaiTool)
	}

	return openaiTools
}

func convertFromOpenAIResponseWithMapping(resp openai.ChatCompletionResponse, toolNameMap map[string]string) *llm.MessageResponse {
	var content string
	var toolCalls []llm.ToolCall

	if len(resp.Choices) > 0 {
		choice := resp.Choices[0]
		content = choice.Message.Content

		// Convert tool calls if present
		for _, tc := range choice.Message.ToolCalls {
			// Restore full tool name using mapping
			fullName := tc.Function.Name
			if mappedName, ok := toolNameMap[tc.Function.Name]; ok {
				fullName = mappedName
			}

			toolCall := llm.ToolCall{
				ID:   tc.ID,
				Name: fullName, // Use restored full name
				Args: make(map[string]any),
			}

			// Parse function arguments JSON
			if tc.Function.Arguments != "" {
				var args map[string]any
				if err := json.Unmarshal([]byte(tc.Function.Arguments), &args); err == nil {
					toolCall.Args = args
				}
			}

			toolCalls = append(toolCalls, toolCall)
		}
	}

	usage := llm.Usage{
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
		TotalTokens:  resp.Usage.TotalTokens,
	}

	var finishReason string
	if len(resp.Choices) > 0 {
		finishReason = string(resp.Choices[0].FinishReason)
	}

	return &llm.MessageResponse{
		Content:      content,
		ToolCalls:    toolCalls,
		Usage:        usage,
		FinishReason: finishReason,
	}
}
