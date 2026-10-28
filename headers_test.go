package cpauth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestRequestHeadersReachAuthService(t *testing.T) {
	for _, middleware := range []bool{false, true} {
		name := "ValidateFromRequest"
		if middleware {
			name = "Middleware"
		}
		t.Run(name, func(t *testing.T) {
			for _, forwardedFor := range []string{"198.51.100.10, 192.0.2.1", ""} {
				t.Run("X-Forwarded-For="+forwardedFor, func(t *testing.T) {
					incoming := httptest.NewRequest(http.MethodPatch, "/api/data?limit=1", nil)
					incoming.RemoteAddr = "192.0.2.20:1234"
					incoming.Header = http.Header{
						"Cp-X-Api-Key":        {"test-key"},
						"User-Agent":          {"caller/1.0"},
						"X-Real-Ip":           {"198.51.100.10"},
						"Forwarded":           {"for=198.51.100.10;proto=https"},
						"Authorization":       {"Bearer caller-token"},
						"Cookie":              {"session=test"},
						"X-Request-Id":        {"request-1", "request-2"},
						"Connection":          {"keep-alive, X-Internal", "X-Other"},
						"X-Internal":          {"connection-only"},
						"X-Other":             {"connection-only"},
						"Keep-Alive":          {"timeout=5"},
						"Proxy-Connection":    {"keep-alive"},
						"Proxy-Authenticate":  {"Basic"},
						"Proxy-Authorization": {"Basic secret"},
						"Te":                  {"trailers"},
						"Trailer":             {"X-Checksum"},
						"Transfer-Encoding":   {"chunked"},
						"Upgrade":             {"websocket"},
						"Host":                {"caller.example"},
						"Content-Type":        {"text/plain"},
						"Content-Length":      {"99999"},
						"Content-Encoding":    {"gzip"},
						"Expect":              {"100-continue"},
						"Accept-Encoding":     {"br"},
					}
					if forwardedFor != "" {
						incoming.Header.Set("X-Forwarded-For", forwardedFor)
					}
					original := incoming.Header.Clone()
					called := false
					remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						called = true
						for _, key := range []string{"CP-X-API-KEY", "User-Agent", "X-Real-IP", "Forwarded", "Authorization", "Cookie", "X-Request-ID"} {
							if !reflect.DeepEqual(r.Header.Values(key), incoming.Header.Values(key)) {
								t.Errorf("%s: got %q, want %q", key, r.Header.Values(key), incoming.Header.Values(key))
							}
						}
						wantIP := forwardedFor
						if wantIP == "" {
							wantIP = "192.0.2.20"
						}
						if got := r.Header.Get("X-Forwarded-For"); got != wantIP {
							t.Errorf("X-Forwarded-For: got %q, want %q", got, wantIP)
						}
						for _, key := range []string{"Connection", "X-Internal", "X-Other", "Keep-Alive", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Content-Encoding", "Expect"} {
							if r.Header.Get(key) != "" {
								t.Errorf("unexpected forwarded header %s", key)
							}
						}
						if r.Host == "caller.example" || r.Header.Get("Accept-Encoding") == "br" {
							t.Error("original host or compression settings were forwarded")
						}
						body, err := io.ReadAll(r.Body)
						if err != nil {
							t.Error(err)
						}
						var payload ValidateRequest
						if err := json.Unmarshal(body, &payload); err != nil {
							t.Errorf("invalid JSON body: %v", err)
						}
						if payload.APIKey != "test-key" || payload.Scope != "terminal" || payload.HTTPMethod != http.MethodPatch || payload.URLPath != "/api/data" {
							t.Errorf("unexpected payload: %+v", payload)
						}
						if r.Header.Get("Content-Type") != "application/json" || r.ContentLength != int64(len(body)) {
							t.Error("auth request must have its own content type and length")
						}
						_ = json.NewEncoder(w).Encode(validateEnvelope{Data: ValidateResponse{Valid: true}})
					}))
					defer remote.Close()
					client := MustNewClient(Config{BaseURL: remote.URL + "/v1/", Scope: "terminal"})
					if middleware {
						recorder := httptest.NewRecorder()
						NewMiddleware(client).Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							w.WriteHeader(http.StatusNoContent)
						})).ServeHTTP(recorder, incoming)
						if recorder.Code != http.StatusNoContent {
							t.Fatalf("unexpected middleware status: %d", recorder.Code)
						}
					} else if _, err := client.ValidateFromRequest(incoming); err != nil {
						t.Fatal(err)
					}
					if !called {
						t.Error("auth service was not called")
					}
					if !reflect.DeepEqual(incoming.Header, original) {
						t.Error("incoming headers were modified")
					}
				})
			}
		})
	}
}

func TestForwardRequestHeadersRemoteAddr(t *testing.T) {
	for _, tt := range []struct{ remoteAddr, want string }{
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"198.51.100.1", "198.51.100.1"},
		{"", ""},
		{"invalid:address", ""},
	} {
		t.Run(tt.remoteAddr, func(t *testing.T) {
			r := &http.Request{RemoteAddr: tt.remoteAddr}
			if got := forwardRequestHeaders(r).Get("X-Forwarded-For"); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestForwardRequestHeadersClonesValues(t *testing.T) {
	r := &http.Request{Header: http.Header{"X-Request-Id": {"original", "second"}}}
	headers := forwardRequestHeaders(r)
	headers["X-Request-Id"][0] = "changed"
	if r.Header.Get("X-Request-ID") != "original" {
		t.Error("forwarded header values share storage with incoming headers")
	}
}
