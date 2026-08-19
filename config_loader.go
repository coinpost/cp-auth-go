package cpauth

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const envConfigPath = "CP_AUTH_CONFIG"

var defaultConfigPaths = []string{
	"config.yaml",
	"config.yml",
	"application.yaml",
	"application.yml",
	"config/config.yaml",
	"config/config.yml",
	"configs/config.yaml",
	"configs/config.yml",
}

type configFile struct {
	CPAuth Config `json:"cp_auth" yaml:"cp_auth" mapstructure:"cp_auth"`
}

// LoadConfigFile reads Config from a YAML file with a top-level cp_auth block.
func LoadConfigFile(path string) (Config, error) {
	if path == "" {
		return Config{}, errors.New("cpauth: config path is required")
	}

	body, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("cpauth: read config file: %w", err)
	}

	var file configFile
	if err := yaml.Unmarshal(body, &file); err != nil {
		return Config{}, fmt.Errorf("cpauth: parse config file: %w", err)
	}
	if !file.CPAuth.configured() {
		return Config{}, errors.New("cpauth: cp_auth config is required")
	}
	return file.CPAuth, nil
}

// InitFromFile initializes the default Client from a YAML file.
func InitFromFile(path string) error {
	cfg, err := LoadConfigFile(path)
	if err != nil {
		return err
	}
	return SetDefault(cfg)
}

// InitFromDefaultConfig initializes the default Client from CP_AUTH_CONFIG or a common config file path.
func InitFromDefaultConfig() error {
	if path := os.Getenv(envConfigPath); path != "" {
		return InitFromFile(path)
	}

	path, err := findDefaultConfigFile()
	if err != nil {
		return err
	}
	return InitFromFile(path)
}

func findDefaultConfigFile() (string, error) {
	for _, path := range defaultConfigPaths {
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return path, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("cpauth: stat config file %q: %w", path, err)
		}
	}
	return "", errors.New("cpauth: config file not found; set CP_AUTH_CONFIG or create config.yaml")
}
