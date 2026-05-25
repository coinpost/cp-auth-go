package cpauth

import (
	"context"
	"net/http"
	"strings"
)

// Middleware is the authentication middleware for net/http.
type Middleware struct {
	client        *Client
	errorHandler  ErrorHandler
	scope         string
	skipAuthPaths map[string]struct{}
}

// MiddlewareOption configures Middleware.
type MiddlewareOption func(*Middleware)

// WithErrorHandler sets a custom error handler. Passing nil is a no-op.
func WithErrorHandler(fn ErrorHandler) MiddlewareOption {
	return func(m *Middleware) {
		if fn != nil {
			m.errorHandler = fn
		}
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
	c := loadDefaultClient()
	if c == nil {
		panic("cpauth: default client not initialized")
	}
	return NewMiddleware(c, opts...)
}

// Handler wraps an http.Handler with API key authentication.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.shouldSkipAuth(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		apiKey := extractAPIKey(r, m.scope)
		if apiKey == "" {
			m.errorHandler(w, r, &AuthError{
				Code:       CodeInvalidAPIKey,
				Message:    "missing API key header",
				HTTPStatus: http.StatusUnauthorized,
			})
			return
		}

		resp, err := m.client.Validate(r.Context(), apiKey, m.scope)
		if err != nil {
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

		r = r.WithContext(context.WithValue(r.Context(), validateResponseCtxKey, resp))
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
	c := loadDefaultClient()
	if c == nil {
		panic("cpauth: default client not initialized")
	}
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
