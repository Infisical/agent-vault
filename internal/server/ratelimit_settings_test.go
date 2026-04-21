package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/Infisical/agent-vault/internal/ratelimit"
)

// fakeSettingsStore exercises the GetSetting/SetSetting path only.
type fakeSettingsStore struct {
	Store
	settings map[string]string
}

func newFakeSettingsStore() *fakeSettingsStore {
	return &fakeSettingsStore{settings: make(map[string]string)}
}

func (f *fakeSettingsStore) GetSetting(_ context.Context, key string) (string, error) {
	v, ok := f.settings[key]
	if !ok {
		return "", sql.ErrNoRows
	}
	return v, nil
}
func (f *fakeSettingsStore) SetSetting(_ context.Context, key, value string) error {
	f.settings[key] = value
	return nil
}

func TestResolveRateLimitConfigDefault(t *testing.T) {
	t.Setenv("AGENT_VAULT_RATELIMIT_PROFILE", "")
	t.Setenv("AGENT_VAULT_RATELIMIT_LOCK", "")
	store := newFakeSettingsStore()
	cfg, _, hasPayload, _, err := resolveRateLimitConfig(context.Background(), store)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if hasPayload {
		t.Fatalf("expected no payload when setting is absent")
	}
	if cfg.Profile != ratelimit.ProfileDefault {
		t.Fatalf("want default profile, got %q", cfg.Profile)
	}
	if cfg.Tiers[ratelimit.TierAuth].Max < 5 {
		t.Fatalf("AUTH max below floor, cfg misbuilt: %+v", cfg.Tiers[ratelimit.TierAuth])
	}
}

func TestResolveRateLimitConfigWithOverride(t *testing.T) {
	t.Setenv("AGENT_VAULT_RATELIMIT_PROFILE", "")
	t.Setenv("AGENT_VAULT_RATELIMIT_LOCK", "")
	store := newFakeSettingsStore()
	payload := rateLimitSettingPayload{
		Profile: "default",
		Overrides: map[string]rateLimitTierOverride{
			"AUTHED": {Rate: float64Ptr(3.5), Burst: intPtr(25)},
		},
	}
	b, _ := json.Marshal(payload)
	store.settings[settingRateLimitConfig] = string(b)

	cfg, _, hasPayload, _, err := resolveRateLimitConfig(context.Background(), store)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !hasPayload {
		t.Fatalf("expected payload to be loaded")
	}
	if cfg.Tiers[ratelimit.TierAuthed].Rate != 3.5 {
		t.Fatalf("override rate not applied: %v", cfg.Tiers[ratelimit.TierAuthed].Rate)
	}
	if cfg.Tiers[ratelimit.TierAuthed].Burst != 25 {
		t.Fatalf("override burst not applied: %v", cfg.Tiers[ratelimit.TierAuthed].Burst)
	}
}

func TestResolveRateLimitConfigHonorsEnvLock(t *testing.T) {
	t.Setenv("AGENT_VAULT_RATELIMIT_PROFILE", "strict")
	t.Setenv("AGENT_VAULT_RATELIMIT_LOCK", "true")
	store := newFakeSettingsStore()
	payload := rateLimitSettingPayload{
		Profile: "loose",
		Overrides: map[string]rateLimitTierOverride{
			"AUTHED": {Rate: float64Ptr(999)},
		},
	}
	b, _ := json.Marshal(payload)
	store.settings[settingRateLimitConfig] = string(b)

	cfg, _, hasPayload, _, err := resolveRateLimitConfig(context.Background(), store)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if hasPayload {
		t.Fatalf("locked config should ignore stored payload")
	}
	// Strict profile halves the default rate (1.0 → 0.5); should NOT be 999.
	if cfg.Tiers[ratelimit.TierAuthed].Rate == 999 {
		t.Fatalf("stored override leaked through env lock")
	}
	if cfg.Profile != ratelimit.ProfileStrict {
		t.Fatalf("want strict from env, got %q", cfg.Profile)
	}
}

func TestRateLimitSourceForTier(t *testing.T) {
	t.Setenv("AGENT_VAULT_RATELIMIT_PROXY_BURST", "42")
	_, envMask := ratelimit.LoadFromEnv()
	payload := rateLimitSettingPayload{
		Overrides: map[string]rateLimitTierOverride{"AUTHED": {Rate: float64Ptr(1)}},
	}
	if got := rateLimitSourceForTier(ratelimit.TierProxy, payload, true, envMask); got != "env" {
		t.Fatalf("env knob should win: got %q", got)
	}
	if got := rateLimitSourceForTier(ratelimit.TierAuthed, payload, true, envMask); got != "override" {
		t.Fatalf("override should win when no env knob: got %q", got)
	}
	if got := rateLimitSourceForTier(ratelimit.TierAuth, payload, true, envMask); got != "default" {
		t.Fatalf("want default when no env/override: got %q", got)
	}
}

func float64Ptr(f float64) *float64 { return &f }
func intPtr(i int) *int             { return &i }
