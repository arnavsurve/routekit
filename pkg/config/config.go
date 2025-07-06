package config

import (
	"fmt"
)

type ServiceConfig struct {
	ID            string     `json:"id" db:"id"`
	UserID        string     `json:"user_id" db:"user_id"`
	Name          string     `json:"service_name" db:"service_name"`
	TransportType string     `json:"transport_type" db:"transport_type"`
	MCPServerURL  string     `json:"mcp_server_url" db:"mcp_server_url"`
	AuthType      string     `json:"auth_type" db:"auth_type"`
	AuthConfig    AuthConfig `json:"auth_config"`
	Scopes        []string   `json:"scopes" db:"scopes"`
	Audience      string     `json:"audience" db:"audience"`
}

type AuthConfig struct {
	Type             string `json:"type"`
	ClientID         string `json:"client_id,omitempty"`
	ClientSecret     string `json:"client_secret,omitempty"`
	AuthorizationURL string `json:"authorization_url,omitempty"`
	TokenURL         string `json:"token_url,omitempty"`
	Token            string `json:"token,omitempty"` // For PAT
}

// GenerateCommand creates the runtime command for SSE services using mcp-remote
func (s *ServiceConfig) GenerateCommand() []string {
	if s.TransportType == "sse" {
		return []string{"npx", "-y", "mcp-remote", s.MCPServerURL, "--host", "localhost"}
	}
	return nil
}

// GetTransport returns the effective transport type (stdio for SSE via mcp-remote)
func (s *ServiceConfig) GetTransport() string {
	if s.TransportType == "sse" {
		return "stdio" // mcp-remote facade
	}
	return s.TransportType
}

// GetURL returns the URL for streamable-http transports
func (s *ServiceConfig) GetURL() string {
	if s.TransportType == "streamable-http" {
		return s.MCPServerURL
	}
	return ""
}

func ValidateServiceConfig(s *ServiceConfig) error {
	if s.Name == "" {
		return fmt.Errorf("service name is required")
	}
	if s.MCPServerURL == "" {
		return fmt.Errorf("MCP server URL is required")
	}
	if s.TransportType != "streamable-http" && s.TransportType != "sse" {
		return fmt.Errorf("transport type must be 'streamable-http' or 'sse'")
	}
	if s.AuthType != "pat" && s.AuthType != "oauth2.1" && s.AuthType != "mcp_remote_managed" {
		return fmt.Errorf("auth type must be 'pat', 'oauth2.1', or 'mcp_remote_managed'")
	}
	if s.AuthType == "oauth2.1" {
		if s.AuthConfig.ClientID == "" || s.AuthConfig.ClientSecret == "" {
			return fmt.Errorf("client_id and client_secret are required for oauth2.1")
		}
		if s.AuthConfig.AuthorizationURL == "" || s.AuthConfig.TokenURL == "" {
			return fmt.Errorf("authorization_url and token_url are required for oauth2.1")
		}
	}
	return nil
}