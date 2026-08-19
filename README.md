# cp-auth-sdk

Go SDK for the cp-api-auth service. Provides API key validation via HTTP and ready-to-use `net/http` middleware.

## Features

- **API key validation** via remote auth service
- **Local-first API key validation** with remote fallback
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

    cpauth "github.com/coinpost/cp-auth-go"
    "github.com/go-chi/chi/v5"
)

func main() {
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

    cpauth "github.com/coinpost/cp-auth-go"
    "github.com/gin-gonic/gin"
)

func main() {
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
        nextCalled := false
        mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            nextCalled = true
            c.Request = r
            c.Next()
        })).ServeHTTP(c.Writer, c.Request)
        if !nextCalled {
            c.Abort()
        }
    }
}
```

## Configuration

The default client loads its own config from a YAML file when `Auth`,
`DefaultMiddleware`, `Validate`, or `ValidateFromRequest` is first used.

By default, the SDK reads the first existing file from:

- `config.yaml`
- `config.yml`
- `application.yaml`
- `application.yml`
- `config/config.yaml`
- `config/config.yml`
- `configs/config.yaml`
- `configs/config.yml`

Set `CP_AUTH_CONFIG` to use a specific file path.

`cp_auth_base_url` is **required** when authentication is enabled. There is no hardcoded default.

The SDK config can be mapped from a `cp_auth` block:

```yaml
cp_auth:
  enabled: false
  cp_auth_base_url: "http://127.0.0.1:8030/v1"
  local:
    name: "test-key"
    description: "only for testing env"
    api_key: "xxx"
```

Set `local.api_key` to enable local-first validation. If the incoming API key
matches `local.api_key`, validation succeeds without calling the remote auth
service. If `local.api_key` is empty or does not match, the SDK falls back to
remote validation.

If `enabled` is omitted, authentication is enabled. If `enabled` is explicitly
set to `false`, middleware bypasses authentication.

### Load Explicitly

```go
// Optional. Auth() and Validate() call this automatically when the default client is unset.
_ = cpauth.InitFromDefaultConfig()

// Or load a specific file.
_ = cpauth.InitFromFile("config.yaml")
```

### Explicit configuration

```go
// This is only needed when callers want to override file-based configuration.
_ = cpauth.SetDefault(cpauth.Config{
    BaseURL: "https://auth.example.com/v1/",
    Local: cpauth.LocalConfig{
        Name:        "test-key",
        Description: "only for testing env",
        APIKey:      "local-dev-key",
    },
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

`ValidateFromRequest` also sends `http_method` and `url_path` to cp-api-auth. These values are read from request headers named `http_method` and `url_path`; if those headers are absent, the SDK falls back to the current request method and path-only URL.
For legacy fallback, pass a scope such as `terminal`, `sourcefinder`, or `feedstream`.
The `feedstream` scope reads `X-FEEDSTREAM-KEY` from the request header, then from the URL query parameter with the same name.

## Middleware

### Standard library style

```go
client, _ := cpauth.NewClient(cpauth.Config{BaseURL: "https://auth.example.com/v1/"})
mw := cpauth.NewMiddleware(client, cpauth.WithSkipAuthPaths([]string{"/health", "/metrics"}))

mux.Handle("/api/data", mw.Handler(http.HandlerFunc(dataHandler)))
```

`WithSkipAuthPaths` matches URL path suffixes, so `/api/health` matches `/health`.
Authenticated middleware requests send `http_method` and `url_path` to cp-api-auth. These values are read from request headers named `http_method` and `url_path`; if those headers are absent, the SDK falls back to the current request method and path-only URL.

### Router style (chi, gorilla, etc.)

```go
r.Use(cpauth.Auth())

// With custom error handler
r.Use(cpauth.Auth(cpauth.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err *cpauth.AuthError) {
    w.WriteHeader(err.HTTPStatus)
    json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Message})
})))

// With success hook for audit/logging; next handler still runs afterward.
r.Use(cpauth.Auth(cpauth.WithSuccessHandler(func(w http.ResponseWriter, r *http.Request, apiKey string, resp cpauth.ValidateResponse) {
    log.Printf("authenticated api_key=%s owner=%s scopes=%v", apiKey, resp.Owner, resp.Scopes)
})))

// Ignore authentication errors and continue to the next handler.
r.Use(cpauth.Auth(cpauth.WithIgnoreError()))
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
- The default client is loaded lazily from config if callers do not set it explicitly
- `SetDefault` / `MustSetDefault` are safe to call during initialization
- Individual `*Client` instances should not be mutated after creation

## Examples

See the [`example/`](example/) directory:

- [`example/main.go`](example/main.go) — standard library `net/http` usage
- [`example/chi/main.go`](example/chi/main.go) — chi router with group-level middleware
- [`example/gin/main.go`](example/gin/main.go) — gin router with adapter middleware

## Security Notes

- `cp_auth_base_url` must be configured explicitly when authentication is enabled. There is no default endpoint.
- Always prefer HTTPS in production.
- The SDK does not log or persist API keys.

## License

MIT
