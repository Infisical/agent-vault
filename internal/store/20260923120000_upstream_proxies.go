package store

import "gorm.io/gorm"

// Upstream proxies are operator-defined egress profiles that Agent Vault uses
// to reach the real upstream after credentials have been injected. They are
// instance-scoped and referenced by name from service rules, so a single
// proxy (and its credentials) can be shared by many services and rotated in
// one place.
//
// Proxy passwords are stored encrypted with the same data-encryption key that
// protects credentials — never in plaintext, and never returned by the API.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Migrator().HasTable("upstream_proxies") {
			return nil
		}
		if db.Name() == "postgres" {
			return db.Exec(`CREATE TABLE upstream_proxies (
				id                TEXT PRIMARY KEY,
				name              TEXT NOT NULL UNIQUE,
				scheme            TEXT NOT NULL,
				host              TEXT NOT NULL,
				username_ct       BYTEA,
				username_nonce    BYTEA,
				password_ct       BYTEA,
				password_nonce    BYTEA,
				no_proxy          TEXT NOT NULL DEFAULT '',
				proxy_ca_pem      TEXT NOT NULL DEFAULT '',
				on_failure        TEXT NOT NULL DEFAULT 'fail_closed',
				is_default        BOOLEAN NOT NULL DEFAULT FALSE,
				enabled           BOOLEAN NOT NULL DEFAULT TRUE,
				created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
			)`).Error
		}
		return db.Exec(`CREATE TABLE upstream_proxies (
				id                TEXT PRIMARY KEY,
				name              TEXT NOT NULL UNIQUE,
				scheme            TEXT NOT NULL,
				host              TEXT NOT NULL,
				username_ct       BLOB,
				username_nonce    BLOB,
				password_ct       BLOB,
				password_nonce    BLOB,
				no_proxy          TEXT NOT NULL DEFAULT '',
				proxy_ca_pem      TEXT NOT NULL DEFAULT '',
				on_failure        TEXT NOT NULL DEFAULT 'fail_closed',
				is_default        INTEGER NOT NULL DEFAULT 0,
				enabled           INTEGER NOT NULL DEFAULT 1,
				created_at        TEXT NOT NULL DEFAULT (datetime('now')),
				updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
			)`).Error
	})
}
