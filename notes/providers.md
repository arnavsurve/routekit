# Multi-Provider AI Support Roadmap

## Overview

This document outlines the roadmap for adding multi-provider AI support to routekit, allowing enterprise customers to use their own API keys and data privacy agreements with various AI providers.

## Business Case

- **Enterprise Privacy**: Customers can negotiate their own data privacy agreements with AI providers
- **Vendor Independence**: Avoid lock-in to a single AI provider
- **Cost Control**: Customers use their own API quotas and billing
- **Compliance**: Meet enterprise requirements for data handling and privacy

## Current Architecture

**Current State:**
- Single provider: Anthropic Claude via `anthropic-sdk-go`
- API key stored as environment variable (`ANTHROPIC_API_KEY`)
- MCP-based tool calling (provider-agnostic foundation)
- Located in: `apps/web/backend/agent/handler.go:89-93`

**Dependencies:**
- `github.com/anthropics/anthropic-sdk-go v1.4.0`
- `github.com/sashabaranov/go-openai v1.40.3` (already available)
- `github.com/mark3labs/mcp-go v0.32.0` (MCP foundation)

## Phase 1: Provider Interface & OpenAI Support

### 1.1 Design Provider Interface

**Current State**: You already have the foundation in `pkg/llm/provider.go`! 

**✅ DONE**: Types are already defined in `pkg/llm/provider.go`:
- `Message` - Role-based message structure
- `ToolCall` - Tool calling information 
- `Usage` - Token usage tracking
- `ProviderConfig` - Provider configuration

**Current Interface**: Your interface already uses `mcp.Tool` which is perfect since MCP is provider-agnostic.

### 1.2 Anthropic Provider Implementation

**Current State**: You already have the skeleton in `pkg/llm/providers/anthropic.go`!

**Next Steps**: Implement the methods by migrating logic from `apps/web/backend/agent/handler.go:175-204`:
- Extract the Anthropic API calling logic
- Convert `anthropic.MessageParam` to/from `llm.Message`
- Handle tool calling via MCP integration
- Map response to `llm.MessageResponse`

### 1.3 OpenAI Provider Implementation

**Current State**: You already have the skeleton in `pkg/llm/providers/openai.go`!

**Next Steps**: Implement OpenAI support:
- Convert `llm.Message` to `openai.ChatCompletionMessage`
- Handle function calling and map to MCP tools
- Map OpenAI response to `llm.MessageResponse`

### 1.4 Provider Factory

```go
// pkg/llm/factory.go
func NewProvider(config ProviderConfig) (Provider, error) {
    switch config.Type {
    case "anthropic":
        return NewAnthropicProvider(config)
    case "openai":
        return NewOpenAIProvider(config)
    default:
        return nil, fmt.Errorf("unsupported provider: %s", config.Type)
    }
}
```

### 1.5 Update Session Handler

Modify `apps/web/backend/agent/handler.go` to use provider interface:

```go
type SessionHandler struct {
    gatewayClient   *client.Client
    llmProvider     llm.Provider  // Replace anthropicClient
    conversation    []Message     // Provider-agnostic message format
    systemPrompt    string
    userJWT         string
}
```

## Phase 2: User Configuration System

### 2.1 Database Schema Updates

Add provider configuration to user settings:

```sql
-- Add to existing user table or create new table
ALTER TABLE users ADD COLUMN llm_provider_config JSONB;

-- Or separate table for multiple configs
CREATE TABLE user_llm_configs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    provider_type VARCHAR(50) NOT NULL,
    config JSONB NOT NULL,
    is_default BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW()
);
```

### 2.2 API Endpoints

Create a dedicated LLM configuration handler in `apps/web/backend/llm/handler.go`:

```go
// apps/web/backend/llm/handler.go
type LLMHandler struct {
    DBPool *pgxpool.Pool
}

// GET /api/user/llm-config
func (h *LLMHandler) HandleGetLLMConfig(c echo.Context) error

// POST /api/user/llm-config  
func (h *LLMHandler) HandleSetLLMConfig(c echo.Context) error

// DELETE /api/user/llm-config/:id
func (h *LLMHandler) HandleDeleteLLMConfig(c echo.Context) error

// POST /api/user/llm-config/test
func (h *LLMHandler) HandleTestLLMConfig(c echo.Context) error
```

Register in `apps/web/backend/main.go`:
```go
llmHandler := &llm.LLMHandler{
    DBPool: db.GetPool(),
}
api.GET("/user/llm-config", llmHandler.HandleGetLLMConfig)
api.POST("/user/llm-config", llmHandler.HandleSetLLMConfig)
api.DELETE("/user/llm-config/:id", llmHandler.HandleDeleteLLMConfig)
api.POST("/user/llm-config/test", llmHandler.HandleTestLLMConfig)
```

### 2.3 Frontend Configuration UI

Update `apps/web/backend/public/settings.html`:
- Provider selection dropdown (Anthropic, OpenAI)
- API key input (encrypted storage)
- Model selection per provider
- Test connection button

### 2.4 Secure Storage

Encrypt API keys using existing crypto package:
```go
// pkg/crypto/crypto.go - extend existing functionality
func EncryptProviderConfig(config ProviderConfig) ([]byte, error)
func DecryptProviderConfig(data []byte) (ProviderConfig, error)
```

## Phase 3: Advanced Features

### 3.1 Model Selection

Allow users to select specific models per provider:
- Anthropic: Claude 3.5 Sonnet, Claude 3 Haiku, etc.
- OpenAI: GPT-4, GPT-4 Turbo, GPT-3.5 Turbo
- Per-conversation model switching

### 3.2 Fallback & Load Balancing

- Primary/secondary provider configuration
- Automatic failover on errors or rate limits
- Cost-based routing (cheaper models for simple tasks)

### 3.3 Usage Tracking

Track usage per provider for cost management:
```go
type UsageMetrics struct {
    ProviderType string
    Model        string
    InputTokens  int
    OutputTokens int
    Cost         float64
    Timestamp    time.Time
}
```

## Phase 4: Extended Provider Support

### 4.1 Google Gemini Integration

Add Gemini support with native MCP integration:
```go
// pkg/llm/providers/gemini.go
type GeminiProvider struct {
    // Use Google's generative AI SDK
}
```

### 4.2 Self-Hosted Models (Ollama)

Support local/self-hosted models:
```go
// pkg/llm/providers/ollama.go  
type OllamaProvider struct {
    baseURL string // http://localhost:11434
    // Use Ollama API or OpenAI-compatible endpoint
}
```

### 4.3 Azure OpenAI

Enterprise-specific Azure OpenAI support:
```go
// pkg/llm/providers/azure.go
type AzureOpenAIProvider struct {
    // Azure-specific authentication and endpoints
}
```

## Implementation Timeline

### Week 1-2: Foundation
- [x] Design and implement provider interface ✅ DONE
- [ ] Refactor existing Anthropic code to use interface
- [ ] Add OpenAI provider implementation

### Week 3-4: User Configuration
- [ ] Database schema updates
- [ ] Backend API endpoints for provider config
- [ ] Frontend UI for provider selection
- [ ] Secure API key storage

### Week 5-6: Integration & Testing
- [ ] Update session handler to use configurable providers
- [ ] Test OpenAI + Anthropic side-by-side
- [ ] Error handling and fallback logic

### Week 7-8: Polish & Documentation
- [ ] Usage tracking and metrics
- [ ] Admin interface for provider management
- [ ] Documentation and migration guides

## Technical Considerations

### Tool Calling Compatibility

Different providers handle tool calling differently:
- **Anthropic**: Native MCP support, structured tool definitions
- **OpenAI**: Function calling API, needs adaptation to MCP format
- **Gemini**: Native MCP support (2025), function calling bridge needed
- **Ollama**: MCP bridge solutions, model-dependent capabilities

### Message Format Normalization

Create unified message format that can convert to/from provider-specific formats:
```go
type Message struct {
    Role    string // "user", "assistant", "system"
    Content string
    ToolCalls []ToolCall
    ToolResults []ToolResult
}
```

### Error Handling

Provider-specific error handling and retry logic:
- Rate limiting (different per provider)
- API key validation
- Model availability
- Token limits

## Security Considerations

1. **API Key Encryption**: All user API keys encrypted at rest
2. **Key Rotation**: Support for API key updates without service interruption  
3. **Audit Logging**: Track provider usage for security monitoring
4. **Access Control**: Role-based access to provider configurations
5. **Validation**: Strict validation of provider configurations and models

## Success Metrics

- [ ] Users can configure their own API keys for Anthropic/OpenAI
- [ ] Zero-downtime provider switching
- [ ] Tool calling works identically across providers
- [ ] Cost reduction from users providing their own API keys
- [ ] Enterprise adoption increase due to data privacy controls

## Future Considerations

- **Multi-modal support**: Images, audio, video across providers
- **Fine-tuned models**: Support for customer-trained models
- **Provider-specific optimizations**: Leverage unique features per provider
- **Cost optimization**: Intelligent model selection based on task complexity