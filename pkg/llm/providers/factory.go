package providers

import (
	"fmt"

	"github.com/arnavsurve/routekit/pkg/llm"
)

func NewProvider(config llm.ProviderConfig) (llm.Provider, error) {
	switch config.Type {
	case "anthropic":
		return NewAnthropicProvider(config), nil
	case "openai":
		return NewOpenAIProvider(config), nil
	}
	return nil, fmt.Errorf("unsupported provider: %s", config.Type)
}
