package cpauth

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	headerAPIKey             = "CP-X-API-KEY"
	headerAuthorization      = "Authorization"
	headerLegacyCpTerminal   = "X-CP-TERMINAL-API-KEY"
	headerLegacySourceFinder = "X-SOURCEFINDER-KEY"
	headerLegacyFeedstream   = "X-FEEDSTREAM-KEY"
	headerHTTPMethod         = "http_method"
	headerURLPath            = "url_path"

	scopeTerminal     = "terminal"
	scopeSourceFinder = "sourcefinder"
	scopeOracle       = "oracle"
	scopeFeedstream   = "feedstream"
)

// HasAPIKeyHeader reports whether the request contains the standard API key header.
func HasAPIKeyHeader(r *http.Request) bool {
	if r == nil {
		return false
	}
	return r.Header.Get(headerAPIKey) != ""
}

func extractBearerToken(r *http.Request) string {
	fields := strings.Fields(r.Header.Get(headerAuthorization))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return ""
	}
	return fields[1]
}

// extractAPIKey reads the API key from headers with legacy fallback.
// 1. Read CP-X-API-KEY. If present, return it.
// 2. If scope is "oracle", read Authorization: Bearer <token>.
// 3. If empty, use scope to determine legacy header:
//   - "terminal"     -> X-Cp-Terminal-Api-Key
//   - "sourcefinder" -> X-SOURCEFINDER-KEY
//   - "feedstream"   -> X-FEEDSTREAM-KEY header, then X-FEEDSTREAM-KEY query parameter
//
// 4. Return empty string if nothing found.
func extractAPIKey(r *http.Request, scope string) string {
	if v := r.Header.Get(headerAPIKey); v != "" {
		return v
	}
	switch strings.ToLower(scope) {
	case scopeOracle:
		return extractBearerToken(r)
	case scopeTerminal:
		return r.Header.Get(headerLegacyCpTerminal)
	case scopeSourceFinder:
		return r.Header.Get(headerLegacySourceFinder)
	case scopeFeedstream:
		if v := r.Header.Get(headerLegacyFeedstream); v != "" {
			return v
		}
		return r.URL.Query().Get(headerLegacyFeedstream)
	}
	return ""
}

func extractHTTPMethod(r *http.Request) string {
	if v := r.Header.Get(headerHTTPMethod); v != "" {
		return v
	}
	return r.Method
}

func extractURLPath(r *http.Request) string {
	if v := r.Header.Get(headerURLPath); v != "" {
		return v
	}
	return r.URL.Path
}

var (
	defaultClient   atomic.Pointer[Client]
	defaultClientMu sync.Mutex
)

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
const validateModeCtxKey contextKey = "cpauth.validateMode"

// ValidateResponseFromContext retrieves the ValidateResponse stored in the request context by Middleware.
func ValidateResponseFromContext(ctx context.Context) (ValidateResponse, bool) {
	resp, ok := ctx.Value(validateResponseCtxKey).(ValidateResponse)
	return resp, ok
}

// ValidateModeFromContext retrieves the ValidateMode stored in the request context by Middleware.
func ValidateModeFromContext(ctx context.Context) (ValidateMode, bool) {
	mode, ok := ctx.Value(validateModeCtxKey).(ValidateMode)
	return mode, ok
}

// loadDefaultClient returns the current default client or nil if not set.
func loadDefaultClient() *Client {
	return defaultClient.Load()
}

func loadOrInitDefaultClient() (*Client, error) {
	if c := loadDefaultClient(); c != nil {
		return c, nil
	}

	defaultClientMu.Lock()
	defer defaultClientMu.Unlock()

	if c := loadDefaultClient(); c != nil {
		return c, nil
	}
	if err := InitFromDefaultConfig(); err != nil {
		return nil, err
	}
	return loadDefaultClient(), nil
}

func mustLoadDefaultClient() *Client {
	c, err := loadOrInitDefaultClient()
	if err != nil {
		panic(fmt.Sprintf("cpauth: default client not initialized: %v", err))
	}
	return c
}

// Validate uses the default Client to validate an API key.
func Validate(ctx context.Context, apiKey string, scope ...string) (ValidateResponse, error) {
	c := mustLoadDefaultClient()
	return c.Validate(ctx, apiKey, scope...)
}

// ValidateFromRequest uses the default Client to validate an API key extracted from the request header CP-X-API-KEY.
func ValidateFromRequest(r *http.Request, scope ...string) (ValidateResponse, error) {
	c := mustLoadDefaultClient()
	return c.ValidateFromRequest(r, scope...)
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
func (c *Client) Validate(ctx context.Context, apiKey string, scope ...string) (ValidateResponse, error) {
	if !c.authEnabled() {
		return c.disabledResponse(), nil
	}
	return c.validate(ctx, ValidateRequest{APIKey: apiKey, Scope: resolveScope(c.config.Scope, scope...)})
}

func (c *Client) validate(ctx context.Context, validateReq ValidateRequest) (ValidateResponse, error) {
	if !c.authEnabled() {
		return c.disabledResponse(), nil
	}
	if resp, ok := c.validateLocal(validateReq); ok {
		return resp, nil
	}

	reqBody, err := json.Marshal(validateReq)
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

	envelope.Data.ValidateMode = ValidateModeRemote
	return envelope.Data, nil
}

func (c *Client) validateLocal(validateReq ValidateRequest) (ValidateResponse, bool) {
	configuredAPIKey := c.config.Local.APIKey
	if configuredAPIKey == "" || subtle.ConstantTimeCompare([]byte(validateReq.APIKey), []byte(configuredAPIKey)) != 1 {
		return ValidateResponse{}, false
	}
	owner := c.config.Local.Name
	if owner == "" {
		owner = "local"
	}
	resp := ValidateResponse{
		Valid:        true,
		ID:           owner,
		Owner:        owner,
		ValidateMode: ValidateModeLocal,
	}
	if validateReq.Scope != "" {
		resp.Scopes = []string{validateReq.Scope}
	}
	return resp, true
}

func (c *Client) authEnabled() bool {
	return c.config.authEnabled()
}

func (c *Client) disabledResponse() ValidateResponse {
	return ValidateResponse{
		Valid: true,
		ID:    "disabled",
		Owner: "disabled",
	}
}

func (c *Client) validateRequest(ctx context.Context, apiKey, scope, httpMethod, urlPath string) (ValidateResponse, error) {
	return c.validate(ctx, ValidateRequest{
		APIKey:     apiKey,
		Scope:      scope,
		HTTPMethod: httpMethod,
		URLPath:    urlPath,
	})
}

// ValidateFromRequest extracts the API key from the request header CP-X-API-KEY and validates it.
func (c *Client) ValidateFromRequest(r *http.Request, scope ...string) (ValidateResponse, error) {
	if !c.authEnabled() {
		return c.disabledResponse(), nil
	}
	resolvedScope := resolveScope(c.config.Scope, scope...)
	apiKey := extractAPIKey(r, resolvedScope)
	if apiKey == "" {
		return ValidateResponse{}, &AuthError{
			Code:       CodeInvalidAPIKey,
			Message:    "missing API key header",
			HTTPStatus: http.StatusUnauthorized,
		}
	}
	return c.validateRequest(r.Context(), apiKey, resolvedScope, extractHTTPMethod(r), extractURLPath(r))
}

func resolveScope(defaultScope string, scope ...string) string {
	if len(scope) > 0 {
		return scope[0]
	}
	return defaultScope
}
