package config

import (
	"errors"
	"fmt"
)

type ServiceConfig struct {
	ID              string            `json:"id"`
	UserID          string            `json:"user_id"`
	Name            string            `json:"service_name"`
	TransportType   string            `json:"transport_type"`
	MCPServerURL    *string           `json:"mcp_server_url,omitempty"`
	AuthType        string            `json:"auth_type"`
	AuthConfig      AuthConfig        `json:"auth_config"`
	Scopes          []string          `json:"scopes,omitempty"`
	Audience        *string           `json:"audience,omitempty"`
	Command         []string          `json:"command,omitempty"`
	WorkingDir      *string           `json:"working_dir,omitempty"`
	EnvironmentVars map[string]string `json:"environment_vars,omitempty"`
}

type AuthConfig struct {
	Type string `json:"type"`
	// For 'pat'
	Token string `json:"token,omitempty"`
	// For 'api_key_in_header'
	HeaderName string `json:"header_name,omitempty"`
	APIKey     string `json:"api_key,omitempty"`
	// For 'api_key_in_url'
	QueryParamName string `json:"query_param_name,omitempty"`
	// For 'oauth2.1'
	ClientID         string `json:"client_id,omitempty"`
	ClientSecret     string `json:"client_secret,omitempty"`
	AuthorizationURL string `json:"authorization_url,omitempty"`
	TokenURL         string `json:"token_url,omitempty"`
}

// GenerateCommand creates the runtime command for SSE services using mcp-remote
func (s *ServiceConfig) GenerateCommand() []string {
	if s.TransportType == "sse" && s.MCPServerURL != nil {
		return []string{"npx", "-y", "mcp-remote", *s.MCPServerURL, "--host", "localhost"}
	}
	if s.TransportType == "local_stdio" {
		return s.Command
	}
	return nil
}

// GetTransport returns the effective transport type (stdio for SSE via mcp-remote)
func (s *ServiceConfig) GetTransport() string {
	if s.TransportType == "sse" || s.TransportType == "local_stdio" {
		return "stdio" // mcp-remote facade
	}
	return s.TransportType
}

// GetURL returns the URL for streamable-http transports
func (s *ServiceConfig) GetURL() string {
	if s.TransportType == "streamable-http" && s.MCPServerURL != nil {
		return *s.MCPServerURL
	}
	return ""
}

func ValidateServiceConfig(s *ServiceConfig) error {
	if s.Name == "" {
		return errors.New("service name is required")
	}

	if (s.TransportType == "streamable-http" || s.TransportType == "sse") && (s.MCPServerURL == nil || *s.MCPServerURL == "") {
		return errors.New("MCP server URL is required for remote transports")
	}

	validTransports := map[string]bool{"streamable-http": true, "sse": true, "local_stdio": true}
	if !validTransports[s.TransportType] {
		return fmt.Errorf("transport type must be one of 'streamable-http', 'sse', or 'local_stdio'")
	}

	validAuthTypes := map[string]bool{
		"pat": true, "oauth2.1": true, "mcp_remote_managed": true,
		"api_key_in_header": true, "api_key_in_url": true, "no_auth": true,
	}
	if !validAuthTypes[s.AuthType] {
		return fmt.Errorf("invalid auth type: %s", s.AuthType)
	}

	switch s.AuthType {
	case "oauth2.1":
		if s.AuthConfig.ClientID == "" || s.AuthConfig.ClientSecret == "" {
			return errors.New("client_id and client_secret are required for oauth2.1")
		}
		if s.AuthConfig.AuthorizationURL == "" || s.AuthConfig.TokenURL == "" {
			return errors.New("authorization_url and token_url are required for oauth2.1")
		}
	case "api_key_in_header":
		if s.AuthConfig.HeaderName == "" || s.AuthConfig.APIKey == "" {
			return errors.New("header_name and api_key are required for api_key_in_header auth")
		}
	case "api_key_in_url":
		if s.AuthConfig.QueryParamName == "" || s.AuthConfig.APIKey == "" {
			return errors.New("query_param_name and api_key are required for api_key_in_url auth")
		}
	}

	if s.TransportType == "local_stdio" {
		if len(s.Command) == 0 {
			return errors.New("command is required for local_stdio transport")
		}
	}
	return nil
}

