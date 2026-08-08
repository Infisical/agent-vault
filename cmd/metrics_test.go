package cmd

import (
	"log/slog"
	"testing"

	"github.com/Infisical/agent-vault/internal/server"
)

func TestAttachMetricsIfEnabled_Disabled(t *testing.T) {
	t.Setenv("AGENT_VAULT_METRICS_ENABLED", "")
	db := openTestDB(t)
	srv := server.New("127.0.0.1:0", db, make([]byte, 32), nil, true, "http://127.0.0.1:14321", slog.New(slog.DiscardHandler))

	if sink := attachMetricsIfEnabled(srv, db); sink != nil {
		t.Fatal("expected a nil requestlog.Sink when AGENT_VAULT_METRICS_ENABLED is unset")
	}
}

func TestAttachMetricsIfEnabled_Enabled(t *testing.T) {
	t.Setenv("AGENT_VAULT_METRICS_ENABLED", "true")
	db := openTestDB(t)
	srv := server.New("127.0.0.1:0", db, make([]byte, 32), nil, true, "http://127.0.0.1:14321", slog.New(slog.DiscardHandler))

	if sink := attachMetricsIfEnabled(srv, db); sink == nil {
		t.Fatal("expected a non-nil requestlog.Sink when AGENT_VAULT_METRICS_ENABLED=true")
	}
}
