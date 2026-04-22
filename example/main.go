package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	cpauth "github.com/coinpost/cp-auth-go"
)

func main() {
	// Initialize the SDK. Options:
	//   1. cpauth.InitFromEnv()          // reads CP_AUTH_BASE_URL from environment
	//   2. cpauth.SetDefault(cfg)        // explicit configuration
	_ = cpauth.SetDefault(cpauth.Config{
		BaseURL:    "https://auth.example.com/v1/",
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	})

	// --- Standard library style ---
	// Build a Middleware instance and wrap handlers individually.
	auth := cpauth.DefaultMiddleware(
		cpauth.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err *cpauth.AuthError) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(err.HTTPStatus)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   err.Message,
				"code":    err.Code,
			})
		}),
	)
	// --- Router-style middleware (e.g. chi) ---
	// cpauth.Auth() returns a standard func(http.Handler) http.Handler.
	// Use it directly with routers that support r.Use(...):
	//
	//   r.Use(cpauth.Auth())
	//   r.Use(cpauth.Auth(cpauth.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err *cpauth.AuthError) {
	//       // custom error handling
	//   })))
	//
	// You can also obtain the middleware from a dedicated client:
	//   client := cpauth.NewClient(cpauth.Config{BaseURL: "https://auth.example.com/v1/"})
	//   r.Use(client.Auth())

	// Protect routes
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Standard library: wrap a single handler with a pre-built Middleware instance.
	mux.Handle("/api/data", auth.Handler(http.HandlerFunc(dataHandler)))

	// Direct validation in handler (no middleware).
	mux.HandleFunc("/api/validate-direct", validateHandler)

	// cpauth.Auth() style: use the returned func(http.Handler) http.Handler directly.
	// This works with any router that supports standard middleware signatures (chi, gorilla, etc.)
	// and also with http.Handle because Go's Handle accepts http.Handler.
	mux.Handle("/api/protected", cpauth.Auth(cpauth.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err *cpauth.AuthError) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(err.HTTPStatus)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Message,
			"code":    err.Code,
		})
	}))(http.HandlerFunc(protectedHandler)))

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"data":"sensitive"}`))
}

// protectedHandler is reached only when cpauth.Auth() middleware allows the request.
// The validation result can be retrieved from context if needed.
func protectedHandler(w http.ResponseWriter, r *http.Request) {
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

// validateHandler demonstrates direct usage of ValidateFromRequest without middleware.
// It reads CP-X-API-KEY from the request header and validates it explicitly.
func validateHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := cpauth.ValidateFromRequest(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if authErr, ok := err.(*cpauth.AuthError); ok {
			w.WriteHeader(authErr.HTTPStatus)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
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
