package cpauth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient_InvalidBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		wantErr bool
	}{
		{"missing scheme", "foo", true},
		{"missing host", "http://", true},
		{"ftp scheme", "ftp://auth.example.com/v1/", true},
		{"valid http", "http://auth.example.com/v1/", false},
		{"valid https", "https://auth.example.com/v1/", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClient(Config{
				BaseURL:    tt.baseURL,
				HTTPClient: http.DefaultClient,
			})
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestClient_Validate_DataValidFalse(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(validateEnvelope{
			Code:    0,
			Message: "ok",
			Data: ValidateResponse{
				Valid: false,
				ID:    "",
				Owner: "",
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

	_, err = client.Validate(t.Context(), "some-key", "")
	if err == nil {
		t.Fatal("expected error for valid=false response, got nil")
	}

	authErr, ok := err.(*AuthError)
	if !ok {
		t.Fatalf("expected *AuthError, got %T", err)
	}
	if authErr.Code != CodeInvalidAPIKey {
		t.Fatalf("expected code %d, got %d", CodeInvalidAPIKey, authErr.Code)
	}
	if authErr.HTTPStatus != http.StatusUnauthorized {
		t.Fatalf("expected http status %d, got %d", http.StatusUnauthorized, authErr.HTTPStatus)
	}
}

func TestClient_Validate_Non2xxNonJSON(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`<html>503 Service Unavailable</html>`))
	}))
	defer remote.Close()

	client, err := NewClient(Config{
		BaseURL:    remote.URL + "/v1/",
		HTTPClient: http.DefaultClient,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = client.Validate(t.Context(), "some-key", "")
	if err == nil {
		t.Fatal("expected error for non-2xx response, got nil")
	}

	authErr, ok := err.(*AuthError)
	if !ok {
		t.Fatalf("expected *AuthError, got %T", err)
	}
	if authErr.Code != CodeStorageUnavailable {
		t.Fatalf("expected code %d, got %d", CodeStorageUnavailable, authErr.Code)
	}
	if authErr.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("expected http status %d, got %d", http.StatusServiceUnavailable, authErr.HTTPStatus)
	}
}

func TestClient_ValidateFromRequest_MissingHeader(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	_, err = client.ValidateFromRequest(req, "")
	if err == nil {
		t.Fatal("expected error for missing header, got nil")
	}

	authErr, ok := err.(*AuthError)
	if !ok {
		t.Fatalf("expected *AuthError, got %T", err)
	}
	if authErr.Code != CodeInvalidAPIKey {
		t.Fatalf("expected code %d, got %d", CodeInvalidAPIKey, authErr.Code)
	}
}

func TestClient_ValidateFromRequest_ExtractsHeader(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req ValidateRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("failed to unmarshal request: %v", err)
		}
		if req.APIKey != "test-api-key" {
			t.Fatalf("expected api_key 'test-api-key', got %q", req.APIKey)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(validateEnvelope{
			Code:    0,
			Message: "ok",
			Data: ValidateResponse{
				Valid:  true,
				ID:     "id-123",
				Owner:  "owner",
				Scopes: []string{"read"},
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

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("CP-X-API-KEY", "test-api-key")
	resp, err := client.ValidateFromRequest(req, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Fatal("expected valid=true")
	}
	if resp.ID != "id-123" {
		t.Fatalf("expected id 'id-123', got %q", resp.ID)
	}
}

func TestClient_Validate_ScopePassed(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req ValidateRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("failed to unmarshal request: %v", err)
		}
		if req.APIKey != "test-key" {
			t.Fatalf("expected api_key 'test-key', got %q", req.APIKey)
		}
		if req.Scope != "terminal" {
			t.Fatalf("expected scope 'terminal', got %q", req.Scope)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(validateEnvelope{
			Code:    0,
			Message: "ok",
			Data: ValidateResponse{
				Valid: true,
				ID:    "id-scope",
				Owner: "owner",
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

	resp, err := client.Validate(t.Context(), "test-key", "terminal")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ID != "id-scope" {
		t.Fatalf("expected id 'id-scope', got %q", resp.ID)
	}
}

func TestClient_ValidateFromRequest_LegacySourceFinder(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req ValidateRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("failed to unmarshal request: %v", err)
		}
		if req.APIKey != "legacy-sfk-key" {
			t.Fatalf("expected api_key 'legacy-sfk-key', got %q", req.APIKey)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(validateEnvelope{
			Code:    0,
			Message: "ok",
			Data: ValidateResponse{
				Valid: true,
				ID:    "id-sfk",
				Owner: "owner",
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

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("X-SOURCEFINDER-KEY", "legacy-sfk-key")
	resp, err := client.ValidateFromRequest(req, "sourcefinder")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ID != "id-sfk" {
		t.Fatalf("expected id 'id-sfk', got %q", resp.ID)
	}
}

func TestClient_ValidateFromRequest_LegacyTerminal(t *testing.T) {
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
				Valid: true,
				ID:    "id-cpt",
				Owner: "owner",
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

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("X-Cp-Terminal-Api-Key", "legacy-cpt-key")
	resp, err := client.ValidateFromRequest(req, "terminal")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ID != "id-cpt" {
		t.Fatalf("expected id 'id-cpt', got %q", resp.ID)
	}
}

func TestClient_ValidateFromRequest_LegacyFallbackMissing(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	// CP-X-API-KEY missing and legacy header also missing for the given scope
	_, err = client.ValidateFromRequest(req, "terminal")
	if err == nil {
		t.Fatal("expected error for missing header, got nil")
	}
	authErr, ok := err.(*AuthError)
	if !ok {
		t.Fatalf("expected *AuthError, got %T", err)
	}
	if authErr.Code != CodeInvalidAPIKey {
		t.Fatalf("expected code %d, got %d", CodeInvalidAPIKey, authErr.Code)
	}
}
