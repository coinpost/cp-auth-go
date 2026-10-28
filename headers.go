package cpauth

import (
	"net"
	"net/http"
	"strings"
)

func forwardRequestHeaders(r *http.Request) http.Header {
	headers := r.Header.Clone()
	if headers == nil {
		headers = make(http.Header)
	}

	// Connection can name additional headers that apply only to this connection.
	for _, value := range headers.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			headers.Del(strings.TrimSpace(name))
		}
	}
	// The auth request has its own connection and JSON body.
	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
		"Host", "Content-Type", "Content-Length", "Content-Encoding", "Expect",
		"Accept-Encoding",
	} {
		headers.Del(name)
	}

	if headers.Get("X-Forwarded-For") == "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if ip := net.ParseIP(host); ip != nil {
			headers.Set("X-Forwarded-For", ip.String())
		}
	}
	return headers
}
