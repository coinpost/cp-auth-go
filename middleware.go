package cpauth

import (
	"context"
	"net/http"
	"strings"
)

// Middleware is the authentication middleware for net/http.
type Middleware struct {
	client         *Client
	errorHandler   ErrorHandler
	successHandler SuccessHandler
	ignoreError    bool
	scope          string
	skipAuthPaths  map[string]struct{}
}

// MiddlewareOption configures Middleware.
type MiddlewareOption func(*Middleware)

// SuccessHandler is called after authentication succeeds and before the next handler runs.
// It is intended for side effects such as logging, metrics, or audit work.
type SuccessHandler func(w http.ResponseWriter, r *http.Request, apiKey string, resp ValidateResponse)

// WithErrorHandler sets a custom error handler. Passing nil is a no-op.
func WithErrorHandler(fn ErrorHandler) MiddlewareOption {
	return func(m *Middleware) {
		if fn != nil {
			m.errorHandler = fn
		}
	}
}

// WithSuccessHandler sets a custom success handler. Passing nil is a no-op.
func WithSuccessHandler(fn SuccessHandler) MiddlewareOption {
	return func(m *Middleware) {
		if fn != nil {
			m.successHandler = fn
		}
	}
}

// WithIgnoreError bypasses authentication errors and lets the next handler run.
func WithIgnoreError() MiddlewareOption {
	return func(m *Middleware) {
		m.ignoreError = true
	}
}

// WithScope sets the scope used for legacy header fallback.
func WithScope(scope string) MiddlewareOption {
	return func(m *Middleware) {
		m.scope = scope
	}
}

// WithSkipAuthPaths sets route path suffixes that bypass authentication.
func WithSkipAuthPaths(paths []string) MiddlewareOption {
	return func(m *Middleware) {
		if len(paths) == 0 {
			return
		}
		if m.skipAuthPaths == nil {
			m.skipAuthPaths = make(map[string]struct{}, len(paths))
		}
		for _, path := range paths {
			if path == "" {
				continue
			}
			m.skipAuthPaths[path] = struct{}{}
		}
	}
}

// NewMiddleware creates a Middleware. Requires a non-nil Client.
func NewMiddleware(client *Client, opts ...MiddlewareOption) *Middleware {
	if client == nil {
		panic("cpauth: client is nil")
	}
	m := &Middleware{
		client:       client,
		errorHandler: defaultErrorHandler,
		scope:        client.config.Scope,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// DefaultMiddleware creates a Middleware using the default Client.
func DefaultMiddleware(opts ...MiddlewareOption) *Middleware {
	c := mustLoadDefaultClient()
	return NewMiddleware(c, opts...)
}

// Handler wraps an http.Handler with API key authentication.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.client.authEnabled() {
			next.ServeHTTP(w, r)
			return
		}

		if m.shouldSkipAuth(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		apiKey := extractAPIKey(r, m.scope)
		if apiKey == "" {
			if m.ignoreError {
				next.ServeHTTP(w, r)
				return
			}
			m.errorHandler(w, r, &AuthError{
				Code:       CodeInvalidAPIKey,
				Message:    "missing API key header",
				HTTPStatus: http.StatusUnauthorized,
			})
			return
		}

		resp, err := m.client.validateRequest(r.Context(), apiKey, m.scope, extractHTTPMethod(r), extractURLPath(r))
		if err != nil {
			if m.ignoreError {
				next.ServeHTTP(w, r)
				return
			}
			if authErr, ok := err.(*AuthError); ok {
				m.errorHandler(w, r, authErr)
			} else {
				m.errorHandler(w, r, &AuthError{
					Code:       CodeInternalServerError,
					Message:    err.Error(),
					HTTPStatus: http.StatusInternalServerError,
				})
			}
			return
		}

		ctx := context.WithValue(r.Context(), validateResponseCtxKey, resp)
		ctx = context.WithValue(ctx, validateModeCtxKey, resp.ValidateMode)
		r = r.WithContext(ctx)
		if m.successHandler != nil {
			m.successHandler(w, r, apiKey, resp)
		}
		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) shouldSkipAuth(path string) bool {
	for skipPath := range m.skipAuthPaths {
		if strings.HasSuffix(path, skipPath) {
			return true
		}
	}
	return false
}

// HandlerFunc is a convenience wrapper for http.HandlerFunc.
func (m *Middleware) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return m.Handler(next).ServeHTTP
}

// Auth returns a standard net/http middleware using the default Client.
// It is intended for routers like chi that accept func(http.Handler) http.Handler.
//
//	r.Use(cpauth.Auth())
//	r.Use(cpauth.Auth(cpauth.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err *AuthError) {
//	    // custom error response
//	})))
func Auth(opts ...MiddlewareOption) func(http.Handler) http.Handler {
	c := mustLoadDefaultClient()
	return NewMiddleware(c, opts...).Handler
}

// Auth returns a standard net/http middleware using this Client.
func (c *Client) Auth(opts ...MiddlewareOption) func(http.Handler) http.Handler {
	return NewMiddleware(c, opts...).Handler
}

// AuthWithErrHandle is like Auth but allows a custom error handler.
func (c *Client) AuthWithErrHandle(fn ErrorHandler, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	return NewMiddleware(c, append(opts, WithErrorHandler(fn))...).Handler
}
