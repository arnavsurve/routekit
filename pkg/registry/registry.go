package registry

import "github.com/mark3labs/mcp-go/mcp"

type Service struct {
	Name string
	URL  string
}

type Capability struct {
	Tool      mcp.Tool
	TargetURL string
}

type Registry struct {
	// Map of capability name to its provider's URL
	capabilityToURL map[string]string

	services []Service
}

func New() *Registry {
	services := []Service{
		{Name: "user-service", URL: "http://localhost:8081/mcp"},
	}

	return &Registry{
		services:        services,
		capabilityToURL: make(map[string]string),
	}
}

func (r *Registry) GetServices() []Service {
	return r.services
}

func (r *Registry) RegisterCapabilities(serviceURL string, tools []mcp.Tool) {
	for _, tool := range tools {
		r.capabilityToURL[tool.Name] = serviceURL
	}
}

func (r *Registry) Resolve(capabilityName string) (string, bool) {
	url, found := r.capabilityToURL[capabilityName]
	return url, found
}
