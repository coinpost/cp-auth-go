# cp-auth-sdk

Go SDK for the cp-api-auth service. Provides API key validation via HTTP and ready-to-use `net/http` middleware.

## Features

- **API key validation** via remote auth service
- **Middleware** for `net/http` and routers like chi/gorilla
- **Direct validation** from request headers without middleware
- **Structured errors** with business codes and HTTP status mapping
- **Thread-safe** default client via `atomic.Pointer`
- **Context propagation** of validation results for downstream authorization

## Installation

```bash
go get github.com/coinpost/cp-auth-go
```

## Quick Start

### Chi

```go
package main

import (
    "log"
    "net/http"
    "time"

    cpauth "github.com/coinpost/cp-auth-go"
    "github.com/go-chi/chi/v5"
)

func main() {
    _ = cpauth.SetDefault(cpauth.Config{
        BaseURL:    "https://auth.example.com/v1/",
        HTTPClient: &http.Client{Timeout: 10 * time.Second},
    })

    r := chi.NewRouter()
    r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte(`{"status":"ok"}`))
    })

    r.Group(func(r chi.Router) {
        r.Use(cpauth.Auth())
        r.Get("/api/data", dataHandler)
    })

    log.Fatal(http.ListenAndServe(":8080", r))
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
    resp, _ := cpauth.ValidateResponseFromContext(r.Context())
    w.Write([]byte("owner: " + resp.Owner))
}
```

### Gin

```go
package main

import (
    "net/http"
    "time"

    cpauth "github.com/coinpost/cp-auth-go"
    "github.com/gin-gonic/gin"
)

func main() {
    _ = cpauth.SetDefault(cpauth.Config{
        BaseURL:    "https://auth.example.com/v1/",
        HTTPClient: &http.Client{Timeout: 10 * time.Second},
    })

    r := gin.Default()
    r.GET("/health", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"status": "ok"})
    })

    api := r.Group("/api")
    api.Use(ginAuth(cpauth.Auth()))
    api.GET("/data", dataHandler)

    r.Run(":8080")
}

func dataHandler(c *gin.Context) {
    resp, _ := cpauth.ValidateResponseFromContext(c.Request.Context())
    c.JSON(http.StatusOK, gin.H{"owner": resp.Owner})
}

// ginAuth adapts cpauth.Auth to a Gin middleware.
func ginAuth(mw func(http.Handler) http.Handler) gin.HandlerFunc {
    return func(c *gin.Context) {
        mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            c.Request = r
            c.Next()
        })).ServeHTTP(c.Writer, c.Request)
    }
}
```

## Configuration

`BaseURL` is **required**. There is no hardcoded default.

### From environment variables

```go
cpauth.InitFromEnv() // reads CP_AUTH_BASE_URL
```

### Explicit configuration

```go
// Returns error
_ = cpauth.SetDefault(cpauth.Config{
    BaseURL:    "https://auth.example.com/v1/",
    HTTPClient: &http.Client{Timeout: 5 * time.Second},
})

// Or panic on error
cpauth.MustSetDefault(cpauth.Config{BaseURL: "https://auth.example.com/v1/"})
```

### Dedicated client (multi-tenant)

```go
client, err := cpauth.NewClient(cpauth.Config{
    BaseURL: "https://tenant-b.example.com/v1/",
})
if err != nil {
    log.Fatal(err)
}
```

## Validation

### Validate an API key directly

```go
resp, err := cpauth.Validate(ctx, "cp_prod_v1_xxx")
if err != nil {
    // handle AuthError
}
fmt.Println(resp.Owner, resp.Scopes)
```

### Validate from request header

Reads `CP-X-API-KEY` from the request header automatically:

```go
resp, err := cpauth.ValidateFromRequest(r)
```

## Middleware

### Standard library style

```go
client, _ := cpauth.NewClient(cpauth.Config{BaseURL: "https://auth.example.com/v1/"})
mw := cpauth.NewMiddleware(client)

mux.Handle("/api/data", mw.Handler(http.HandlerFunc(dataHandler)))
```

### Router style (chi, gorilla, etc.)

```go
r.Use(cpauth.Auth())

// With custom error handler
r.Use(cpauth.Auth(cpauth.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err *cpauth.AuthError) {
    w.WriteHeader(err.HTTPStatus)
    json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Message})
})))
```

### Per-client middleware

```go
tenantClient, _ := cpauth.NewClient(cpauth.Config{BaseURL: "https://tenant-b.example.com/v1/"})
r.Use(tenantClient.Auth())
```

## Error Handling

All SDK errors implement `error`. Authentication errors are returned as `*AuthError`:

```go
resp, err := cpauth.Validate(ctx, apiKey)
if err != nil {
    if authErr, ok := err.(*cpauth.AuthError); ok {
        fmt.Println(authErr.Code)       // business error code (1001-1009)
        fmt.Println(authErr.HTTPStatus) // mapped HTTP status
        fmt.Println(authErr.Message)    // human-readable message
    }
}
```

### Error codes

| Code | Meaning | HTTP Status |
|---|---|---|
| 0 | Success | 200 |
| 1001 | Bad Request | 400 |
| 1002 | Invalid API Key | 401 |
| 1003 | Key Revoked or Expired | 403 |
| 1004 | Key Not Found | 404 |
| 1005 | Rate Limit Exceeded | 429 |
| 1006 | Daily Quota Exceeded | 429 |
| 1007 | Resource Conflict | 409 |
| 1008 | Internal Server Error | 500 |
| 1009 | Storage Unavailable | 503 |

## Context Values

After middleware validation succeeds, `ValidateResponse` is stored in the request context. Downstream handlers can retrieve it for scope-based authorization or audit logging:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    resp, ok := cpauth.ValidateResponseFromContext(r.Context())
    if !ok {
        // not set; should not happen if middleware is active
    }
    fmt.Println(resp.Owner, resp.Scopes, resp.RatePerMinute, resp.DailyQuota)
}
```

## Response Fields

```go
type ValidateResponse struct {
    Valid         bool     // true if key is valid
    ID            string   // key UUID
    Owner         string   // key owner identifier
    Scopes        []string // granted scopes
    RatePerMinute int      // rate limit per minute
    DailyQuota    int      // daily request quota
}
```

## Thread Safety

- `defaultClient` is protected by `atomic.Pointer[Client]`
- `SetDefault` / `MustSetDefault` are safe to call during initialization
- Individual `*Client` instances should not be mutated after creation

## Examples

See the [`example/`](example/) directory:

- [`example/main.go`](example/main.go) — standard library `net/http` usage
- [`example/chi/main.go`](example/chi/main.go) — chi router with group-level middleware
- [`example/gin/main.go`](example/gin/main.go) — gin router with adapter middleware

## Security Notes

- `BaseURL` must be configured explicitly. There is no default endpoint.
- Always prefer HTTPS in production.
- The SDK does not log or persist API keys.

## License

MIT
