package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/arnavsurve/routekit/pkg/llm"
	"github.com/mark3labs/mcp-go/mcp"
)

type AnthropicProvider struct {
	client anthropic.Client
	config llm.ProviderConfig
}

func NewAnthropicProvider(config llm.ProviderConfig) *AnthropicProvider {
	client := anthropic.NewClient(option.WithAPIKey(config.APIKey))
	return &AnthropicProvider{
		client: client,
		config: config,
	}
}

func (p *AnthropicProvider) SendMessage(ctx context.Context, req llm.MessageRequest) (*llm.MessageResponse, error) {
	anthropicMessages := convertToAnthropicMessages(req.Messages)

	model := anthropic.ModelClaude3_5SonnetLatest
	if req.Model != "" {
		model = anthropic.Model(req.Model)
	} else if p.config.Model != "" {
		model = anthropic.Model(p.config.Model)
	}

	maxTokens := int64(req.MaxTokens)
	if maxTokens <= 0 {
		maxTokens = 1024 // Default value
	}
	
	anthropicReq := anthropic.MessageNewParams{
		Model:     model,
		Messages:  anthropicMessages,
		MaxTokens: maxTokens,
	}

	if req.SystemPrompt != "" {
		systemPrompt := strings.TrimSpace(req.SystemPrompt)
		if systemPrompt != "" {
			anthropicReq.System = []anthropic.TextBlockParam{{Text: systemPrompt}}
		}
	}

	resp, err := p.client.Messages.New(ctx, anthropicReq)
	if err != nil {
		return nil, fmt.Errorf("making Anthropic API call: %w", err)
	}

	return convertFromAnthropicResponse(resp), nil
}

func (p *AnthropicProvider) SendMessageWithTools(ctx context.Context, req llm.MessageRequest, tools []mcp.Tool) (*llm.MessageResponse, error) {
	anthropicMessages := convertToAnthropicMessages(req.Messages)

	model := anthropic.ModelClaude3_5SonnetLatest
	if req.Model != "" {
		model = anthropic.Model(req.Model)
	} else if p.config.Model != "" {
		model = anthropic.Model(p.config.Model)
	}

	anthropicTools := convertMCPToAnthropicTools(tools)

	maxTokens := int64(req.MaxTokens)
	if maxTokens <= 0 {
		maxTokens = 1024 // Default value
	}

	anthropicReq := anthropic.MessageNewParams{
		Model:     model,
		Messages:  anthropicMessages,
		MaxTokens: maxTokens,
		Tools:     anthropicTools,
	}

	if req.SystemPrompt != "" {
		systemPrompt := strings.TrimSpace(req.SystemPrompt)
		if systemPrompt != "" {
			anthropicReq.System = []anthropic.TextBlockParam{{Text: systemPrompt}}
		}
	}

	resp, err := p.client.Messages.New(ctx, anthropicReq)
	if err != nil {
		return nil, fmt.Errorf("making Anthropic API call: %w", err)
	}

	return convertFromAnthropicResponse(resp), nil
}

func (p *AnthropicProvider) GetName() string {
	return "anthropic"
}

func (p *AnthropicProvider) GetSupportedModels() []string {
	return []string{
		"claude-opus-4-20250514",
		"claude-sonnet-4-20250514",
		"claude-3-7-sonnet-latest",
		"claude-3-5-sonnet-latest",
		"claude-3-5-haiku-latest",
	}
}

func (p *AnthropicProvider) ValidateConfig(config llm.ProviderConfig) error {
	if config.APIKey == "" {
		return fmt.Errorf("API key is required for Anthropic provider")
	}
	if len(config.APIKey) < 40 || !strings.HasPrefix(config.APIKey, "sk-ant-") {
		return fmt.Errorf("invalid Anthropic API key format - should start with 'sk-ant-'")
	}
	return nil
}

func convertToAnthropicMessages(messages []llm.Message) []anthropic.MessageParam {
	var anthropicMessages []anthropic.MessageParam

	for _, msg := range messages {
		// Trim whitespace to avoid Anthropic API errors
		content := strings.TrimSpace(msg.Content)
		if content == "" {
			continue // Skip empty messages
		}
		
		switch msg.Role {
		case "user":
			anthropicMessages = append(anthropicMessages, anthropic.NewUserMessage(anthropic.NewTextBlock(content)))
		case "assistant":
			anthropicMessages = append(anthropicMessages, anthropic.NewAssistantMessage(anthropic.NewTextBlock(content)))
			// Note: system messages are handled separately in Anthropic API
		}
	}

	return anthropicMessages
}

func convertFromAnthropicResponse(resp *anthropic.Message) *llm.MessageResponse {
	var content string
	var toolCalls []llm.ToolCall

	for _, block := range resp.Content {
		switch b := block.AsAny().(type) {
		case anthropic.TextBlock:
			content += b.Text

		// Convert tool calls if present
		case anthropic.ToolUseBlock:
			toolCall := llm.ToolCall{
				ID:   b.ID,
				Name: b.Name,
				Args: make(map[string]any),
			}
			if b.Input != nil {
				var args map[string]any
				if err := json.Unmarshal(b.Input, &args); err == nil {
					toolCall.Args = args
				}
			}
			toolCalls = append(toolCalls, toolCall)
		}
	}

	usage := llm.Usage{
		InputTokens:  int(resp.Usage.InputTokens),
		OutputTokens: int(resp.Usage.OutputTokens),
		TotalTokens:  int(resp.Usage.InputTokens + resp.Usage.OutputTokens),
	}

	return &llm.MessageResponse{
		Content:      content,
		ToolCalls:    toolCalls,
		Usage:        usage,
		FinishReason: string(resp.StopReason),
	}
}

func convertMCPToAnthropicTools(mcpTools []mcp.Tool) []anthropic.ToolUnionParam {
	var anthropicTools []anthropic.ToolUnionParam

	for _, mcpTool := range mcpTools {
		anthropicTool := anthropic.ToolParam{
			Name:        mcpTool.Name,
			Description: anthropic.String(mcpTool.Description),
			InputSchema: anthropic.ToolInputSchemaParam{
				Type:       "object",
				Properties: map[string]any{},
				Required:   []string{},
			},
		}

		// Convert InputSchema from MCP format
		if mcpTool.InputSchema.Type != "" {
			if mcpTool.InputSchema.Properties != nil {
				anthropicTool.InputSchema.Properties = mcpTool.InputSchema.Properties
			}
			if mcpTool.InputSchema.Required != nil {
				anthropicTool.InputSchema.Required = mcpTool.InputSchema.Required
			}
		}

		anthropicTools = append(anthropicTools, anthropic.ToolUnionParam{OfTool: &anthropicTool})
	}

	return anthropicTools
}
