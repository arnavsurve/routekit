package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type ServiceConfig struct {
	Name      string   `yaml:"name"`
	Transport string   `yaml:"transport"`
	URL       string   `yaml:"url,omitempty"`
	Command   []string `yaml:"command,omitempty"`
	Auth      struct {
		Type       string `yaml:"type"`
		HeaderName string `yaml:"header_name"`
	} `yaml:"auth,omitempty"`
}

type Config struct {
	Version  int             `yaml:"version"`
	Services []ServiceConfig `yaml:"services"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	for i := range cfg.Services {
		if cfg.Services[i].Transport == "" {
			cfg.Services[i].Transport = "streamable-http"
		}
		if err := validateServiceConfig(&cfg.Services[i]); err != nil {
			return nil, fmt.Errorf("invalid config for service %q: %w", cfg.Services[i].Name, err)
		}
	}
	return &cfg, nil
}

func validateServiceConfig(s *ServiceConfig) error {
	if s.Name == "" {
		return fmt.Errorf("service name is required")
	}
	switch s.Transport {
	case "streamable-http", "sse":
		if s.URL == "" {
			return fmt.Errorf("'url' is required for transport %q", s.Transport)
		}
	case "stdio":
		if len(s.Command) == 0 {
			return fmt.Errorf("'command' is required for transport 'stdio'")
		}
	default:
		return fmt.Errorf("unsupported transport type: %q", s.Transport)
	}
	return nil
}
