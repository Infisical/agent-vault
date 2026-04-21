package requestlog

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// Defaults shipped with the built-in SQLite sink. Both limits apply;
// whichever is hit first trims rows. Owner can tune via the
// "logs_retention" instance setting or pin via env vars.
const (
	DefaultMaxAge          = 7 * 24 * time.Hour
	DefaultMaxRowsPerVault = 10_000
	DefaultRetentionTick   = 15 * time.Minute

	// SettingKey is the instance_settings key holding the JSON payload.
	SettingKey = "logs_retention"

	envMaxAgeHours  = "AGENT_VAULT_LOGS_MAX_AGE_HOURS"
	envMaxRows      = "AGENT_VAULT_LOGS_MAX_ROWS_PER_VAULT"
	envRetentionLock = "AGENT_VAULT_LOGS_RETENTION_LOCK"
)

// RetentionConfig controls the background cleanup job. Zero-valued
// limits disable that dimension (e.g. MaxAge == 0 skips time-based
// trimming).
type RetentionConfig struct {
	MaxAge          time.Duration
	MaxRowsPerVault int64
	Tick            time.Duration
}

// retentionSettingPayload is the JSON blob persisted at SettingKey.
type retentionSettingPayload struct {
	MaxAgeHours     *float64 `json:"max_age_hours,omitempty"`
	MaxRowsPerVault *int64   `json:"max_rows_per_vault,omitempty"`
}

// retentionStore is the narrow store surface the retention loop needs.
type retentionStore interface {
	GetSetting(ctx context.Context, key string) (string, error)
	DeleteOldRequestLogs(ctx context.Context, before time.Time) (int64, error)
	TrimRequestLogsToCap(ctx context.Context, vaultID string, cap int64) (int64, error)
	VaultIDsWithLogs(ctx context.Context) ([]string, error)
}

// ResolveRetention returns the effective RetentionConfig. Precedence:
// env (when lock is set) > instance setting > env defaults > built-in
// defaults. Absent setting is not an error.
func ResolveRetention(ctx context.Context, s retentionStore) RetentionConfig {
	cfg := RetentionConfig{
		MaxAge:          DefaultMaxAge,
		MaxRowsPerVault: DefaultMaxRowsPerVault,
		Tick:            DefaultRetentionTick,
	}
	envCfg, envSet := loadRetentionFromEnv()
	applyEnv := func(base *RetentionConfig) {
		if envSet.age {
			base.MaxAge = envCfg.MaxAge
		}
		if envSet.rows {
			base.MaxRowsPerVault = envCfg.MaxRowsPerVault
		}
	}

	if os.Getenv(envRetentionLock) == "true" {
		applyEnv(&cfg)
		return cfg
	}

	// Instance setting layers on top of env defaults; env-set values
	// still win when present.
	payload, present, _ := loadRetentionSetting(ctx, s)
	if present {
		if payload.MaxAgeHours != nil {
			cfg.MaxAge = time.Duration(*payload.MaxAgeHours * float64(time.Hour))
		}
		if payload.MaxRowsPerVault != nil {
			cfg.MaxRowsPerVault = *payload.MaxRowsPerVault
		}
	}
	applyEnv(&cfg)
	return cfg
}

type envRetentionMask struct {
	age, rows bool
}

func loadRetentionFromEnv() (RetentionConfig, envRetentionMask) {
	var (
		cfg  RetentionConfig
		mask envRetentionMask
	)
	if raw := os.Getenv(envMaxAgeHours); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil && v >= 0 {
			cfg.MaxAge = time.Duration(v * float64(time.Hour))
			mask.age = true
		}
	}
	if raw := os.Getenv(envMaxRows); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil && v >= 0 {
			cfg.MaxRowsPerVault = v
			mask.rows = true
		}
	}
	return cfg, mask
}

func loadRetentionSetting(ctx context.Context, s retentionStore) (retentionSettingPayload, bool, error) {
	raw, err := s.GetSetting(ctx, SettingKey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return retentionSettingPayload{}, false, nil
		}
		return retentionSettingPayload{}, false, err
	}
	if raw == "" {
		return retentionSettingPayload{}, false, nil
	}
	var p retentionSettingPayload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return retentionSettingPayload{}, false, err
	}
	return p, true, nil
}

// RunRetention ticks on cfg.Tick and trims request_logs until ctx is
// done. Blocks; callers typically run it in a goroutine.
func RunRetention(ctx context.Context, s store.Store, logger *slog.Logger) {
	cfg := ResolveRetention(ctx, s)
	tick := cfg.Tick
	if tick <= 0 {
		tick = DefaultRetentionTick
	}
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	trimOnce(ctx, s, logger, cfg)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cfg = ResolveRetention(ctx, s)
			trimOnce(ctx, s, logger, cfg)
		}
	}
}

func trimOnce(ctx context.Context, s store.Store, logger *slog.Logger, cfg RetentionConfig) {
	if cfg.MaxAge > 0 {
		before := time.Now().Add(-cfg.MaxAge)
		if n, err := s.DeleteOldRequestLogs(ctx, before); err != nil {
			if logger != nil {
				logger.Warn("request_logs ttl trim failed", "err", err.Error())
			}
		} else if n > 0 && logger != nil {
			logger.Debug("request_logs ttl trimmed", "rows", n, "before", before)
		}
	}

	if cfg.MaxRowsPerVault > 0 {
		vaults, err := s.VaultIDsWithLogs(ctx)
		if err != nil {
			if logger != nil {
				logger.Warn("request_logs cap list vaults failed", "err", err.Error())
			}
			return
		}
		for _, v := range vaults {
			if n, err := s.TrimRequestLogsToCap(ctx, v, cfg.MaxRowsPerVault); err != nil {
				if logger != nil {
					logger.Warn("request_logs cap trim failed", "vault", v, "err", err.Error())
				}
			} else if n > 0 && logger != nil {
				logger.Debug("request_logs cap trimmed", "vault", v, "rows", n)
			}
		}
	}
}
