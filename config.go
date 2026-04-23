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
	// BaseURL is the root URL of cp-api-auth, e.g. "http://10.10.10.183:8031/v1/"
	BaseURL string

	// Scope is the auth scope to validate against, e.g. "terminal" or "sourcefinder".
	Scope string

	// HTTPClient is the externally injected http.Client.
	// The caller is responsible for configuring timeouts, retries, transport, etc.
	HTTPClient *http.Client
}

func (c *Config) setDefaults() error {
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
