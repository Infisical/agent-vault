package cmd

import (
	"os"
	"strconv"
)

const (
	DefaultPort     = 14321
	DefaultHost     = "127.0.0.1"
	DefaultAddress  = "http://127.0.0.1:14321"
	DefaultMITMPort = 14322
)

// defaultPort returns the PORT env var (if set and valid), otherwise DefaultPort.
// This lets PaaS platforms like Fly.io, Cloud Run, and Heroku inject their
// preferred port without requiring --port in the CMD.
func defaultPort() int {
	if v := os.Getenv("PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p <= 65535 {
			return p
		}
	}
	return DefaultPort
}

func defaultMaxResponseBytes() int64 {
	if v := os.Getenv("AGENT_VAULT_MAX_RESPONSE_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			return n
		}
	}
	return 0
}

// defaultUIBasePath returns the AGENT_VAULT_UI_BASE_PATH env var, otherwise
// "" (serve at the domain root). Validation happens in the server command
// via server.NormalizeBasePath.
func defaultUIBasePath() string {
	return os.Getenv("AGENT_VAULT_UI_BASE_PATH")
}

func defaultMaxRequestBytes() int64 {
	if v := os.Getenv("AGENT_VAULT_MAX_REQUEST_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return 1 << 30 // 1 GiB — matches brokercore.DefaultMaxRequestBytes
}
