package cpauth

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigFile_CPAuthBlock(t *testing.T) {
	path := writeConfigFile(t, `
cp_auth:
  enabled: true
  cp_auth_base_url: "http://127.0.0.1:8030/v1"
  local:
    name: "test-key"
    description: "only for testing env"
    api_key: "xxx"
`)

	cfg, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Enabled == nil || !*cfg.Enabled {
		t.Fatal("expected enabled=true")
	}
	if cfg.BaseURL != "http://127.0.0.1:8030/v1" {
		t.Fatalf("expected base url, got %q", cfg.BaseURL)
	}
	if cfg.Local.Name != "test-key" {
		t.Fatalf("expected local name, got %q", cfg.Local.Name)
	}
	if cfg.Local.Description != "only for testing env" {
		t.Fatalf("expected local description, got %q", cfg.Local.Description)
	}
	if cfg.Local.APIKey != "xxx" {
		t.Fatalf("expected local api key, got %q", cfg.Local.APIKey)
	}
}

func TestLoadConfigFile_RequiresCPAuthBlock(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: 8080
`)

	_, err := LoadConfigFile(path)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDefaultClientLoadsFromConfigFile(t *testing.T) {
	resetDefaultClient(t)

	path := writeConfigFile(t, `
cp_auth:
  enabled: true
  cp_auth_base_url: "http://127.0.0.1:8030/v1"
  local:
    name: "test-key"
    api_key: "xxx"
`)
	t.Setenv(envConfigPath, path)

	req, err := http.NewRequest(http.MethodGet, "/api/data", nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.Header.Set("CP-X-API-KEY", "xxx")

	resp, err := ValidateFromRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Fatal("expected valid response")
	}
	if resp.Owner != "test-key" {
		t.Fatalf("expected owner test-key, got %q", resp.Owner)
	}
}

func writeConfigFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	return path
}

func resetDefaultClient(t *testing.T) {
	t.Helper()

	defaultClientMu.Lock()
	old := defaultClient.Load()
	defaultClient.Store(nil)
	defaultClientMu.Unlock()

	t.Cleanup(func() {
		defaultClientMu.Lock()
		defaultClient.Store(old)
		defaultClientMu.Unlock()
	})
}
