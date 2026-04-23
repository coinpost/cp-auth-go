package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	cpauth "github.com/coinpost/cp-auth-go"
	"github.com/gin-gonic/gin"
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

	r := gin.Default()

	// Public routes: no authentication.
	r.GET("/health", healthHandler)

	// Routes protected by default auth middleware.
	api := r.Group("/api")
	api.Use(ginAuth(cpauth.Auth()))
	api.GET("/data", dataHandler)

	// Routes protected by auth middleware with scope for legacy header fallback.
	sf := r.Group("/api/sourcefinder")
	sf.Use(ginAuth(cpauth.Auth(cpauth.WithScope("sourcefinder"))))
	sf.GET("", dataHandler)

	// Routes protected by auth middleware with custom error handler.
	custom := r.Group("/api/custom-error")
	custom.Use(ginAuth(cpauth.Auth(cpauth.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err *cpauth.AuthError) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(err.HTTPStatus)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Message,
			"code":    err.Code,
		})
	}))))
	custom.GET("", dataHandler)

	// Route protected by a dedicated client middleware.
	tenant := r.Group("/api/tenant")
	tenant.Use(ginAuth(tenantClient.Auth()))
	tenant.GET("", dataHandler)

	log.Println("Server starting on :8080")
	log.Fatal(r.Run(":8080"))
}

// ginAuth adapts a standard net/http middleware to a Gin middleware.
func ginAuth(middleware func(http.Handler) http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		nextCalled := false
		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			c.Request = r
			c.Next()
		})).ServeHTTP(c.Writer, c.Request)
		if !nextCalled {
			c.Abort()
		}
	}
}

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func dataHandler(c *gin.Context) {
	resp, ok := cpauth.ValidateResponseFromContext(c.Request.Context())
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "validation response not found in context",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"owner":   resp.Owner,
		"scopes":  resp.Scopes,
	})
}
