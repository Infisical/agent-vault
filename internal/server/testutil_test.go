package server

import (
	"log/slog"

	"github.com/Infisical/agent-vault/internal/notify"
)

// testServerOption configures a Server created by newTestServer.
type testServerOption func(*Server)

// newTestServer creates a Server with sensible test defaults:
//
//	addr: "127.0.0.1:0", store: newMockStore(), encKey: 32 zero bytes,
//	notifier: nil, initialized: true, baseURL: "http://127.0.0.1:14321".
//
// Use option functions (withStore, withEncKey, etc.) to override defaults.
func newTestServer(opts ...testServerOption) *Server {
	return newTestServerWithBasePath("", opts...)
}

// newTestServerWithBasePath creates a Server mounted under the given UI
// base path ("" = root). A separate constructor rather than an option
// because route registration happens inside New.
func newTestServerWithBasePath(basePath string, opts ...testServerOption) *Server {
	srv := New("127.0.0.1:0", newMockStore(), make([]byte, 32), nil, true, "http://127.0.0.1:14321", basePath, slog.New(slog.DiscardHandler))
	for _, opt := range opts {
		opt(srv)
	}
	return srv
}

// withStore overrides the default mock store.
func withStore(s Store) testServerOption {
	return func(srv *Server) {
		srv.store = s
	}
}

// withEncKey overrides the default encryption key.
func withEncKey(key []byte) testServerOption {
	return func(srv *Server) {
		srv.encKey = key
	}
}

// withNotifier overrides the default nil notifier.
func withNotifier(n *notify.Notifier) testServerOption {
	return func(srv *Server) {
		srv.notifier = n
	}
}

// withBaseURL overrides the default base URL.
func withBaseURL(url string) testServerOption {
	return func(srv *Server) {
		srv.baseURL = url
	}
}
