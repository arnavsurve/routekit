package llm

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
)

type Provider interface {
	SendMessage(ctx context.Context, req MessageRequest) (*MessageResponse, error)
	SendMessageWithTools(ctx context.Context, req MessageRequest, tools []mcp.Tool) (*MessageResponse, error)
	GetName() string
	GetSupportedModels() []string
	ValidateConfig(config ProviderConfig) error
}

type MessageRequest struct {
	Messages     []Message
	SystemPrompt string
	MaxTokens    int
	Model        string
}

type MessageResponse struct {
	Content      string
	ToolCalls    []ToolCall
	Usage        Usage
	FinishReason string
}

type ProviderConfig struct {
	Type    string // "anthropic", "openai", "gemini", "ollama"
	APIKey  string
	BaseURL string // for self-hosted
	Model   string
}

type Message struct {
	Role    string // "user", "assistant", "system"
	Content string
}

type ToolCall struct {
	ID   string
	Name string
	Args map[string]any
}

type Usage struct {
	InputTokens  int
	OutputTokens int
	TotalTokens  int
}
