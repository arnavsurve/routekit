package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

type ServiceConfig struct {
	Name      string   `yaml:"name"`
	Transport string   `yaml:"transport"`
	URL       string   `yaml:"url,omitempty"`
	Command   []string `yaml:"command,omitempty"`
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
	}
	return &cfg, nil
}
