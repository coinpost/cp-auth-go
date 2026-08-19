package cpauth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config holds SDK configuration.
type Config struct {
	// Enabled controls whether authentication is enforced.
	// Nil keeps the default behavior: authentication is enabled.
	Enabled *bool `json:"enabled,omitempty" yaml:"enabled,omitempty" mapstructure:"enabled"`

	// BaseURL is the root URL of cp-api-auth, e.g. "http://10.10.10.183:8031/v1/"
	BaseURL string `json:"cp_auth_base_url" yaml:"cp_auth_base_url" mapstructure:"cp_auth_base_url"`

	// Scope is the auth scope to validate against, e.g. "terminal", "sourcefinder", or "feedstream".
	Scope string `json:"scope,omitempty" yaml:"scope,omitempty" mapstructure:"scope"`

	// Local enables local-first validation when Local.APIKey is configured.
	Local LocalConfig `json:"local,omitempty" yaml:"local,omitempty" mapstructure:"local"`

	// HTTPClient is the externally injected http.Client.
	// The caller is responsible for configuring timeouts, retries, transport, etc.
	HTTPClient *http.Client `json:"-" yaml:"-" mapstructure:"-"`
}

// LocalConfig holds the local API key used before remote fallback.
type LocalConfig struct {
	Name        string `json:"name,omitempty" yaml:"name,omitempty" mapstructure:"name"`
	Description string `json:"description,omitempty" yaml:"description,omitempty" mapstructure:"description"`
	APIKey      string `json:"api_key,omitempty" yaml:"api_key,omitempty" mapstructure:"api_key"`
}

func (c *Config) setDefaults() error {
	if !c.authEnabled() {
		if c.HTTPClient == nil {
			c.HTTPClient = &http.Client{Timeout: 10 * time.Second}
		}
		return nil
	}
	if c.BaseURL == "" {
		return errors.New("cpauth: BaseURL is required")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return fmt.Errorf("cpauth: invalid BaseURL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("cpauth: BaseURL scheme must be http or https")
	}
	if u.Host == "" {
		return errors.New("cpauth: BaseURL host is required")
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if !strings.HasSuffix(c.BaseURL, "/") {
		c.BaseURL += "/"
	}
	return nil
}

func (c Config) authEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}
