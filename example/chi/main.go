package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	cpauth "github.com/coinpost/cp-auth-go"
	"github.com/go-chi/chi/v5"
)

func main() {
	// Initialize SDK.
	_ = cpauth.SetDefault(cpauth.Config{
		BaseURL:    "https://auth.example.com/v1/",
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	})

	// Dedicated client for a specific tenant (multi-tenant example).
	tenantClient, err := cpauth.NewClient(cpauth.Config{
		BaseURL:    "https://auth-tenant-b.example.com/v1/",
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	})
	if err != nil {
		log.Fatalf("failed to create tenant client: %v", err)
	}

	r := chi.NewRouter()

	// Public routes: no authentication.
	r.Get("/health", healthHandler)

	// Routes protected by default auth middleware.
	r.Group(func(r chi.Router) {
		r.Use(cpauth.Auth())

		r.Get("/api/data", dataHandler)
	})

	// Routes protected by auth middleware with custom error handler.
	r.Group(func(r chi.Router) {
		r.Use(cpauth.Auth(cpauth.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err *cpauth.AuthError) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(err.HTTPStatus)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   err.Message,
				"code":    err.Code,
			})
		})))

		r.Get("/api/custom-error", dataHandler)
	})

	// Route protected by a dedicated client middleware.
	r.Group(func(r chi.Router) {
		r.Use(tenantClient.Auth())

		r.Get("/api/tenant", dataHandler)
	})

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
	resp, ok := cpauth.ValidateResponseFromContext(r.Context())
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "validation response not found in context",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"owner":   resp.Owner,
		"scopes":  resp.Scopes,
	})
}
