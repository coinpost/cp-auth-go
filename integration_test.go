//go:build integration

package cpauth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func skipIfMissingEnv(t *testing.T) (baseURL, apiKey string) {
	baseURL = os.Getenv("CP_AUTH_BASE_URL")
	apiKey = os.Getenv("CP_AUTH_API_KEY")
	if baseURL == "" || apiKey == "" {
		t.Skip("CP_AUTH_BASE_URL and CP_AUTH_API_KEY environment variables are required for integration tests")
	}
	return
}

func TestIntegration_EndToEnd(t *testing.T) {
	baseURL, apiKey := skipIfMissingEnv(t)

	client, err := NewClient(Config{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// 1. Direct client validation
	resp, err := client.Validate(t.Context(), apiKey, "")
	if err != nil {
		t.Fatalf("validate failed: %v", err)
	}

	t.Logf("Valid: %v", resp.Valid)
	t.Logf("ID: %s", resp.ID)
	t.Logf("Owner: %s", resp.Owner)
	t.Logf("Scopes: %v", resp.Scopes)
	t.Logf("RatePerMinute: %d", resp.RatePerMinute)
	t.Logf("DailyQuota: %d", resp.DailyQuota)

	if !resp.Valid {
		t.Fatal("expected valid=true")
	}

	// 2. Middleware validation (dedicated client)
	mw := NewMiddleware(client)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("CP-X-API-KEY", apiKey)
	rec := httptest.NewRecorder()

	mw.Handler(next).ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatalf("expected next handler to be called for valid key, got status %d, body: %s", rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	t.Logf("Middleware passed, body: %s", rec.Body.String())
}

func TestIntegration_DefaultClient(t *testing.T) {
	baseURL, apiKey := skipIfMissingEnv(t)

	// Configure default client for this test
	MustSetDefault(Config{BaseURL: baseURL})
	defer func() { defaultClient.Store(nil) }()

	// 1. Package-level Validate
	resp, err := Validate(t.Context(), apiKey)
	if err != nil {
		t.Fatalf("default Validate failed: %v", err)
	}
	if !resp.Valid {
		t.Fatal("expected valid=true")
	}
	t.Logf("Default Validate OK: owner=%s", resp.Owner)

	// 2. DefaultMiddleware
	mw := DefaultMiddleware()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("CP-X-API-KEY", apiKey)
	rec := httptest.NewRecorder()

	mw.Handler(next).ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatalf("expected next handler to be called for valid key, got status %d, body: %s", rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	t.Logf("DefaultMiddleware passed, body: %s", rec.Body.String())
}
