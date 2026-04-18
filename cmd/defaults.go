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
