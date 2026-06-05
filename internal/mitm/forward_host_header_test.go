package mitm

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

func TestHostHeaderForScheme(t *testing.T) {
	cases := []struct {
		name   string
		scheme string
		target string
		want   string
	}{
		{"https default port stripped", "https", "api.example.com:443", "api.example.com"},
		{"http default port stripped", "http", "k8s-svc:80", "k8s-svc"},
		{"http non-default preserved", "http", "k8s-svc:8080", "k8s-svc:8080"},
		{"https non-default preserved", "https", "internal.example:8443", "internal.example:8443"},
		{"https with :80 preserved", "https", "example.com:80", "example.com:80"},
		{"http with :443 preserved", "http", "example.com:443", "example.com:443"},
		{"scheme case-insensitive", "HTTPS", "host:443", "host"},
		{"ipv6 default port stripped, brackets restored", "https", "[::1]:443", "[::1]"},
		{"ipv6 non-default preserved with brackets", "http", "[::1]:8080", "[::1]:8080"},
		{"no port unchanged", "https", "example.com", "example.com"},
		{"empty scheme unchanged", "", "example.com:443", "example.com:443"},
		{"unknown scheme unchanged", "ftp", "example.com:21", "example.com:21"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hostHeaderForScheme(tc.scheme, tc.target)
			if got != tc.want {
				t.Errorf("hostHeaderForScheme(%q, %q) = %q, want %q", tc.scheme, tc.target, got, tc.want)
			}
		})
	}
}

// TestHostHeaderForSchemeProducesPortlessWireHost closes the helper→wire
// chain: prove that net/http's Request.Write emits the helper's output
// verbatim as the Host: line, with no port re-introduced by Go.
func TestHostHeaderForSchemeProducesPortlessWireHost(t *testing.T) {
	cases := []struct {
		name     string
		scheme   string
		urlStr   string
		target   string
		wantHost string
	}{
		{"https :443 strip", "https", "https://api.example.com:443/x", "api.example.com:443", "api.example.com"},
		{"http :80 strip", "http", "http://internal.example:80/x", "internal.example:80", "internal.example"},
		{"ipv6 :443 strip", "https", "https://[::1]:443/x", "[::1]:443", "[::1]"},
		{"non-default preserve", "http", "http://k8s-svc:8080/x", "k8s-svc:8080", "k8s-svc:8080"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", tc.urlStr, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Host = hostHeaderForScheme(tc.scheme, tc.target)

			var buf bytes.Buffer
			if err := req.Write(&buf); err != nil {
				t.Fatalf("req.Write: %v", err)
			}
			wantLine := "Host: " + tc.wantHost + "\r\n"
			if !strings.Contains(buf.String(), wantLine) {
				t.Errorf("wire missing %q\nwire:\n%s", wantLine, buf.String())
			}
		})
	}
}
