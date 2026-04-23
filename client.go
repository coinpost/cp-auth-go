package cpauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
)

const (
	headerAPIKey             = "CP-X-API-KEY"
	headerLegacyCpTerminal   = "X-CP-TERMINAL-API-KEY"
	headerLegacySourceFinder = "X-SOURCEFINDER-KEY"

	scopeTerminal     = "terminal"
	scopeSourceFinder = "sourcefinder"
)

// extractAPIKey reads the API key from headers with legacy fallback.
// 1. Read CP-X-API-KEY. If present, return it.
// 2. If empty, use scope to determine legacy header:
//   - "terminal"    -> X-Cp-Terminal-Api-Key
//   - "sourcefinder" -> X-SOURCEFINDER-KEY
//
// 3. Return empty string if nothing found.
func extractAPIKey(r *http.Request, scope string) string {
	if v := r.Header.Get(headerAPIKey); v != "" {
		return v
	}
	switch strings.ToLower(scope) {
	case scopeTerminal:
		return r.Header.Get(headerLegacyCpTerminal)
	case scopeSourceFinder:
		return r.Header.Get(headerLegacySourceFinder)
	}
	return ""
}

var defaultClient atomic.Pointer[Client]

// InitFromEnv initializes the default Client from environment variables.
// Recognized variables:
//   - CP_AUTH_BASE_URL: required, the base URL of cp-api-auth.
func InitFromEnv() {
	baseURL := os.Getenv("CP_AUTH_BASE_URL")
	if baseURL == "" {
		panic("cpauth: CP_AUTH_BASE_URL environment variable is required")
	}
	MustSetDefault(Config{BaseURL: baseURL})
}

// SetDefault sets the package-level default Client.
func SetDefault(cfg Config) error {
	c, err := NewClient(cfg)
	if err != nil {
		return err
	}
	defaultClient.Store(c)
	return nil
}

// MustSetDefault sets the package-level default Client and panics on error.
func MustSetDefault(cfg Config) {
	if err := SetDefault(cfg); err != nil {
		panic(err)
	}
}

type contextKey string

const validateResponseCtxKey contextKey = "cpauth.validateResponse"

// ValidateResponseFromContext retrieves the ValidateResponse stored in the request context by Middleware.
func ValidateResponseFromContext(ctx context.Context) (ValidateResponse, bool) {
	resp, ok := ctx.Value(validateResponseCtxKey).(ValidateResponse)
	return resp, ok
}

// loadDefaultClient returns the current default client or nil if not set.
func loadDefaultClient() *Client {
	return defaultClient.Load()
}

// Validate uses the default Client to validate an API key.
func Validate(ctx context.Context, apiKey string, scope string) (ValidateResponse, error) {
	c := loadDefaultClient()
	if c == nil {
		panic("cpauth: default client not initialized")
	}
	return c.Validate(ctx, apiKey, scope)
}

// ValidateFromRequest uses the default Client to validate an API key extracted from the request header CP-X-API-KEY.
func ValidateFromRequest(r *http.Request, scope string) (ValidateResponse, error) {
	c := loadDefaultClient()
	if c == nil {
		panic("cpauth: default client not initialized")
	}
	return c.ValidateFromRequest(r, scope)
}

// Client communicates with the remote cp-api-auth service.
type Client struct {
	config Config
}

// NewClient creates a Client from Config.
func NewClient(cfg Config) (*Client, error) {
	if err := cfg.setDefaults(); err != nil {
		return nil, err
	}
	return &Client{config: cfg}, nil
}

// MustNewClient creates a Client from Config and panics on error.
func MustNewClient(cfg Config) *Client {
	c, err := NewClient(cfg)
	if err != nil {
		panic(err)
	}
	return c
}

// Validate calls POST /v1/validate and returns the parsed data or an AuthError.
func (c *Client) Validate(ctx context.Context, apiKey string, scope string) (ValidateResponse, error) {
	reqBody, err := json.Marshal(ValidateRequest{APIKey: apiKey, Scope: scope})
	if err != nil {
		return ValidateResponse{}, &AuthError{
			Code:       CodeInternalServerError,
			Message:    fmt.Sprintf("failed to marshal request: %v", err),
			HTTPStatus: http.StatusInternalServerError,
		}
	}

	u, err := url.Parse(c.config.BaseURL)
	if err != nil {
		return ValidateResponse{}, &AuthError{
			Code:       CodeInternalServerError,
			Message:    fmt.Sprintf("invalid base URL: %v", err),
			HTTPStatus: http.StatusInternalServerError,
		}
	}

	u = u.JoinPath("validate")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(reqBody))
	if err != nil {
		return ValidateResponse{}, &AuthError{
			Code:       CodeInternalServerError,
			Message:    fmt.Sprintf("failed to build request: %v", err),
			HTTPStatus: http.StatusInternalServerError,
		}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.config.HTTPClient.Do(req)
	if err != nil {
		return ValidateResponse{}, &AuthError{
			Code:       CodeInternalServerError,
			Message:    fmt.Sprintf("request failed: %v", err),
			HTTPStatus: http.StatusInternalServerError,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var envelope validateEnvelope
		if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
			return ValidateResponse{}, &AuthError{
				Code:       mapHTTPStatusToErrorCode(resp.StatusCode),
				Message:    fmt.Sprintf("upstream returned non-JSON response with status %d", resp.StatusCode),
				HTTPStatus: resp.StatusCode,
			}
		}
		code := ErrorCode(envelope.Code)
		if code == 0 {
			code = CodeInternalServerError
		}
		return ValidateResponse{}, &AuthError{
			Code:       code,
			Message:    envelope.Message,
			HTTPStatus: resp.StatusCode,
		}
	}

	var envelope validateEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return ValidateResponse{}, &AuthError{
			Code:       CodeInternalServerError,
			Message:    fmt.Sprintf("failed to decode response: %v", err),
			HTTPStatus: http.StatusInternalServerError,
		}
	}

	if envelope.Code != int(CodeSuccess) {
		return ValidateResponse{}, &AuthError{
			Code:       ErrorCode(envelope.Code),
			Message:    envelope.Message,
			HTTPStatus: mapErrorCodeToHTTPStatus(ErrorCode(envelope.Code)),
		}
	}

	if !envelope.Data.Valid {
		return ValidateResponse{}, &AuthError{
			Code:       CodeInvalidAPIKey,
			Message:    "invalid API key",
			HTTPStatus: http.StatusUnauthorized,
		}
	}

	return envelope.Data, nil
}

// ValidateFromRequest extracts the API key from the request header CP-X-API-KEY and validates it.
func (c *Client) ValidateFromRequest(r *http.Request, scope string) (ValidateResponse, error) {
	apiKey := extractAPIKey(r, scope)
	if apiKey == "" {
		return ValidateResponse{}, &AuthError{
			Code:       CodeInvalidAPIKey,
			Message:    "missing CP-X-API-KEY header",
			HTTPStatus: http.StatusUnauthorized,
		}
	}
	return c.Validate(r.Context(), apiKey, scope)
}
