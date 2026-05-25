package cpauth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware_MissingHeader(t *testing.T) {
	client, err := NewClient(Config{
		BaseURL:    "http://localhost:9999/v1/",
		HTTPClient: http.DefaultClient,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	mw := NewMiddleware(client)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	rec := httptest.NewRecorder()

	mw.Handler(next).ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("expected next handler NOT to be called")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestMiddleware_ValidKey(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/validate" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		var req ValidateRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("failed to unmarshal request: %v", err)
		}
		if req.APIKey != "good-key" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(validateEnvelope{Code: 1002, Message: "invalid key"})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(validateEnvelope{
			Code:    0,
			Message: "ok",
			Data: ValidateResponse{
				Valid:  true,
				ID:     "550e8400-e29b-41d4-a716-446655440000",
				Owner:  "test-user",
				Scopes: []string{"terminal"},
			},
		})
	}))
	defer remote.Close()

	client, err := NewClient(Config{
		BaseURL:    remote.URL + "/v1/",
		HTTPClient: http.DefaultClient,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	mw := NewMiddleware(client)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("CP-X-API-KEY", "good-key")
	rec := httptest.NewRecorder()

	mw.Handler(next).ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func TestMiddleware_RemoteError(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(validateEnvelope{
			Code:    1003,
			Message: "revoked",
		})
	}))
	defer remote.Close()

	client, err := NewClient(Config{
		BaseURL:    remote.URL + "/v1/",
		HTTPClient: http.DefaultClient,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	var captured *AuthError
	mw := NewMiddleware(client, WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err *AuthError) {
		captured = err
		w.WriteHeader(err.HTTPStatus)
	}))

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("CP-X-API-KEY", "revoked-key")
	rec := httptest.NewRecorder()

	mw.Handler(next).ServeHTTP(rec, req)

	if captured == nil {
		t.Fatal("expected error handler to be called")
	}
	if captured.Code != CodeKeyRevokedOrExpired {
		t.Fatalf("expected code 1003, got %d", captured.Code)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rec.Code)
	}
}

func TestMiddleware_WithSkipAuthPaths(t *testing.T) {
	client, err := NewClient(Config{
		BaseURL:    "http://localhost:9999/v1/",
		HTTPClient: http.DefaultClient,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	errorHandlerCalled := false
	mw := NewMiddleware(client,
		WithSkipAuthPaths([]string{"", "/health", "/metrics", "/health"}),
		WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err *AuthError) {
			errorHandlerCalled = true
			w.WriteHeader(err.HTTPStatus)
		}),
	)

	tests := []struct {
		name string
		path string
	}{
		{
			name: "same path",
			path: "/health",
		},
		{
			name: "suffix path",
			path: "/api/health",
		},
		{
			name: "query ignored",
			path: "/api/health?ready=1",
		},
		{
			name: "second skipped path",
			path: "/internal/metrics",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errorHandlerCalled = false
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				if _, ok := ValidateResponseFromContext(r.Context()); ok {
					t.Fatal("expected skipped request to have no validate response in context")
				}
				w.WriteHeader(http.StatusNoContent)
			})

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()

			mw.Handler(next).ServeHTTP(rec, req)

			if !nextCalled {
				t.Fatal("expected next handler to be called")
			}
			if errorHandlerCalled {
				t.Fatal("expected error handler not to be called")
			}
			if rec.Code != http.StatusNoContent {
				t.Fatalf("expected status 204, got %d", rec.Code)
			}
		})
	}
}

func TestMiddleware_WithSkipAuthPaths_SkipsRemoteValidationEvenWithAPIKey(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("remote should not be called")
	}))
	defer remote.Close()

	client, err := NewClient(Config{
		BaseURL:    remote.URL + "/v1/",
		HTTPClient: http.DefaultClient,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	mw := NewMiddleware(client, WithSkipAuthPaths([]string{"/health"}))

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		if _, ok := ValidateResponseFromContext(r.Context()); ok {
			t.Fatal("expected skipped request to have no validate response in context")
		}
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Header.Set("CP-X-API-KEY", "good-key")
	rec := httptest.NewRecorder()

	mw.Handler(next).ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", rec.Code)
	}
}

func TestMiddleware_WithSkipAuthPaths_NonMatchingPathRequiresAuth(t *testing.T) {
	client, err := NewClient(Config{
		BaseURL:    "http://localhost:9999/v1/",
		HTTPClient: http.DefaultClient,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	mw := NewMiddleware(client, WithSkipAuthPaths([]string{"/health"}))

	tests := []struct {
		name string
		path string
	}{
		{
			name: "similar prefix",
			path: "/healthz",
		},
		{
			name: "trailing slash",
			path: "/health/",
		},
		{
			name: "empty path ignored",
			path: "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
			})

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()

			mw.Handler(next).ServeHTTP(rec, req)

			if nextCalled {
				t.Fatal("expected next handler NOT to be called")
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected status 401, got %d", rec.Code)
			}
		})
	}
}

func TestAuth_MissingHeader(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("remote should not be called")
	}))
	defer remote.Close()

	MustSetDefault(Config{BaseURL: remote.URL + "/v1/"})
	defer func() { defaultClient.Store(nil) }()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	rec := httptest.NewRecorder()

	Auth()(next).ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("expected next handler NOT to be called")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestAuth_ValidKey(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(validateEnvelope{
			Code:    0,
			Message: "ok",
			Data: ValidateResponse{
				Valid:  true,
				ID:     "550e8400-e29b-41d4-a716-446655440000",
				Owner:  "test-user",
				Scopes: []string{"terminal"},
			},
		})
	}))
	defer remote.Close()

	MustSetDefault(Config{BaseURL: remote.URL + "/v1/"})
	defer func() { defaultClient.Store(nil) }()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("CP-X-API-KEY", "good-key")
	rec := httptest.NewRecorder()

	Auth()(next).ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func TestAuth_WithErrorHandler(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("remote should not be called")
	}))
	defer remote.Close()

	MustSetDefault(Config{BaseURL: remote.URL + "/v1/"})
	defer func() { defaultClient.Store(nil) }()

	var captured *AuthError
	mw := Auth(WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err *AuthError) {
		captured = err
		w.WriteHeader(err.HTTPStatus)
	}))

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	rec := httptest.NewRecorder()

	mw(next).ServeHTTP(rec, req)

	if captured == nil {
		t.Fatal("expected error handler to be called")
	}
	if captured.Code != CodeInvalidAPIKey {
		t.Fatalf("expected code %d, got %d", CodeInvalidAPIKey, captured.Code)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestClient_Auth(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(validateEnvelope{
			Code:    0,
			Message: "ok",
			Data: ValidateResponse{
				Valid:  true,
				ID:     "550e8400-e29b-41d4-a716-446655440000",
				Owner:  "test-user",
				Scopes: []string{"terminal"},
			},
		})
	}))
	defer remote.Close()

	client, err := NewClient(Config{
		BaseURL:    remote.URL + "/v1/",
		HTTPClient: http.DefaultClient,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("CP-X-API-KEY", "good-key")
	rec := httptest.NewRecorder()

	client.Auth()(next).ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func TestMiddleware_WithScope_LegacyFallback(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req ValidateRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("failed to unmarshal request: %v", err)
		}
		if req.APIKey != "legacy-cpt-key" {
			t.Fatalf("expected api_key 'legacy-cpt-key', got %q", req.APIKey)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(validateEnvelope{
			Code:    0,
			Message: "ok",
			Data: ValidateResponse{
				Valid:  true,
				ID:     "550e8400-e29b-41d4-a716-446655440000",
				Owner:  "test-user",
				Scopes: []string{"terminal"},
			},
		})
	}))
	defer remote.Close()

	client, err := NewClient(Config{
		BaseURL:    remote.URL + "/v1/",
		HTTPClient: http.DefaultClient,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	mw := NewMiddleware(client, WithScope("terminal"))

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("X-Cp-Terminal-Api-Key", "legacy-cpt-key")
	rec := httptest.NewRecorder()

	mw.Handler(next).ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}
