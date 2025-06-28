package registry

import (
	"fmt"
	"log"

	"github.com/mark3labs/mcp-go/mcp"
)

type Service struct {
	Name string
	URL  string
}

type Capability struct {
	Name               string // Tool name
	Namespace          string // Service it belongs to
	FullyQualifiedName string // crm__search_contacts
	Tool               mcp.Tool
	TargetURL          string
}

type Registry struct {
	capabilityToURL map[string]string
	services        []Service
}

func New() *Registry {
	services := []Service{
		{Name: "user-service", URL: "http://localhost:8081/mcp"},
		{Name: "inventory-service", URL: "http://localhost:8082/mcp"},
		{Name: "crm-service", URL: "http://localhost:8083/mcp"},
		{Name: "kb-service", URL: "http://localhost:8084/mcp"},
		{Name: "devops-service", URL: "http://localhost:8085/mcp"},
		{Name: "bug-tracker-service", URL: "http://localhost:8087/mcp"},
	}

	return &Registry{
		services:        services,
		capabilityToURL: make(map[string]string),
	}
}

func (r *Registry) GetServices() []Service {
	return r.services
}

func (r *Registry) RegisterCapabilities(serviceName, serviceURL string, tools []mcp.Tool) {
	for _, tool := range tools {
		fqn := fmt.Sprintf("%s__%s", serviceName, tool.Name)
		r.capabilityToURL[fqn] = serviceURL
		log.Printf("Registry: Mapping FQN %q to URL %q", fqn, serviceURL)
	}
}

func (r *Registry) Resolve(fullyQualifiedName string) (string, bool) {
	url, found := r.capabilityToURL[fullyQualifiedName]
	return url, found
}
