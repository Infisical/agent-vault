package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Name() == "sqlite" {
			return nil
		}
		if db.Migrator().HasTable("vaults") {
			return nil
		}
		return db.Exec(postgresBaselineSQL).Error
	})
}
// postgresBaselineSQL creates the full Postgres schema equivalent to
// SQLite migrations 001-050. Embedded as a raw SQL string because
// defining 20+ GORM model structs just for a one-time baseline is
// unnecessary overhead.
const postgresBaselineSQL = `
CREATE TABLE vaults (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE credentials (
    id         TEXT PRIMARY KEY,
    vault_id   TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    key        TEXT NOT NULL,
    type       TEXT NOT NULL DEFAULT 'static',
    ciphertext BYTEA NOT NULL,
    nonce      BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(vault_id, key)
);

CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash BYTEA NOT NULL,
    password_salt BYTEA NOT NULL,
    role          TEXT NOT NULL DEFAULT 'owner' CHECK(role IN ('owner', 'member', 'no-access')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    kdf_time      INTEGER NOT NULL DEFAULT 3,
    kdf_memory    INTEGER NOT NULL DEFAULT 65536,
    kdf_threads   INTEGER NOT NULL DEFAULT 4,
    is_active     BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE agents (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    status     TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    role       TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('owner', 'member', 'no-access'))
);

CREATE TABLE sessions (
    id                    TEXT PRIMARY KEY,
    expires_at            TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    vault_id              TEXT REFERENCES vaults(id) ON DELETE CASCADE,
    user_id               TEXT REFERENCES users(id) ON DELETE CASCADE,
    agent_id              TEXT REFERENCES agents(id) ON DELETE CASCADE,
    vault_role            TEXT CHECK(vault_role IN ('proxy', 'member', 'admin')),
    label                 TEXT,
    last_used_at          TIMESTAMPTZ,
    idle_ttl_seconds      INTEGER,
    device_label          TEXT,
    last_ip               TEXT,
    last_user_agent       TEXT,
    public_id             TEXT,
    created_by_actor_id   TEXT,
    created_by_actor_type TEXT
);

CREATE TABLE master_key (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    sentinel       BYTEA NOT NULL,
    sentinel_nonce BYTEA NOT NULL,
    dek_ciphertext BYTEA,
    dek_nonce      BYTEA,
    dek_plaintext  BYTEA,
    salt           BYTEA,
    kdf_time       INTEGER,
    kdf_memory     INTEGER,
    kdf_threads    INTEGER,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE broker_configs (
    id            TEXT PRIMARY KEY,
    vault_id      TEXT NOT NULL UNIQUE REFERENCES vaults(id) ON DELETE CASCADE,
    services_json TEXT NOT NULL DEFAULT '[]',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE proposals (
    id                        INTEGER NOT NULL,
    vault_id                  TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    session_id                TEXT NOT NULL,
    status                    TEXT NOT NULL DEFAULT 'pending'
                              CHECK(status IN ('pending','applied','rejected','expired')),
    services_json             TEXT NOT NULL DEFAULT '[]',
    credentials_json          TEXT NOT NULL DEFAULT '[]',
    message                   TEXT NOT NULL DEFAULT '',
    user_message              TEXT NOT NULL DEFAULT '',
    review_note               TEXT NOT NULL DEFAULT '',
    reviewed_at               TIMESTAMPTZ,
    approval_token_hash       TEXT,
    approval_token_expires_at TIMESTAMPTZ,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (vault_id, id)
);

CREATE TABLE proposal_credentials (
    vault_id    TEXT NOT NULL,
    proposal_id INTEGER NOT NULL,
    key         TEXT NOT NULL,
    ciphertext  BYTEA NOT NULL,
    nonce       BYTEA NOT NULL,
    FOREIGN KEY (vault_id, proposal_id) REFERENCES proposals(vault_id, id) ON DELETE CASCADE,
    PRIMARY KEY (vault_id, proposal_id, key)
);

CREATE TABLE vault_grants (
    actor_id   TEXT NOT NULL,
    actor_type TEXT NOT NULL CHECK(actor_type IN ('user', 'agent')),
    vault_id   TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('proxy', 'member', 'admin')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (actor_id, vault_id)
);

CREATE TABLE email_verifications (
    id         SERIAL PRIMARY KEY,
    email      TEXT NOT NULL,
    code_hash  TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'verified', 'expired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE instance_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE password_resets (
    id         SERIAL PRIMARY KEY,
    email      TEXT NOT NULL,
    code_hash  TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'used', 'expired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE user_invites (
    id          SERIAL PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    email       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','expired','revoked')),
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    role        TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('owner', 'member', 'no-access'))
);

CREATE TABLE user_invite_vaults (
    user_invite_id  INTEGER NOT NULL REFERENCES user_invites(id) ON DELETE CASCADE,
    vault_id        TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    vault_role      TEXT NOT NULL DEFAULT 'member' CHECK(vault_role IN ('admin', 'member')),
    PRIMARY KEY (user_invite_id, vault_id)
);

CREATE TABLE request_logs (
    id              BIGSERIAL PRIMARY KEY,
    vault_id        TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    actor_type      TEXT NOT NULL DEFAULT '',
    actor_id        TEXT NOT NULL DEFAULT '',
    ingress         TEXT NOT NULL,
    method          TEXT NOT NULL,
    host            TEXT NOT NULL,
    path            TEXT NOT NULL,
    matched_service TEXT NOT NULL DEFAULT '',
    credential_keys TEXT NOT NULL DEFAULT '[]',
    status          INTEGER NOT NULL DEFAULT 0,
    latency_ms      INTEGER NOT NULL DEFAULT 0,
    error_code      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    auth_scheme     TEXT NOT NULL DEFAULT '',
    auth_header     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE vault_settings (
    vault_id   TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (vault_id, key)
);

CREATE TABLE vault_credential_stores (
    vault_id              TEXT PRIMARY KEY REFERENCES vaults(id) ON DELETE CASCADE,
    kind                  TEXT NOT NULL CHECK(kind IN ('infisical')),
    config_json           TEXT NOT NULL,
    poll_interval_seconds INTEGER NOT NULL DEFAULT 60 CHECK(poll_interval_seconds >= 10),
    last_synced_at        TIMESTAMPTZ,
    last_sync_status      TEXT CHECK(last_sync_status IS NULL OR last_sync_status IN ('ok','error')),
    last_sync_error       TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE credential_oauth (
    vault_id              TEXT NOT NULL,
    credential_key        TEXT NOT NULL,
    authorization_url     TEXT,
    token_url             TEXT NOT NULL,
    client_id             TEXT NOT NULL,
    client_secret_ct      BYTEA,
    client_secret_nonce   BYTEA,
    scopes                TEXT,
    scope_separator       TEXT DEFAULT ' ',
    disable_pkce          BOOLEAN NOT NULL DEFAULT FALSE,
    token_auth_method     TEXT DEFAULT 'client_secret_post',
    refresh_token_ct      BYTEA,
    refresh_token_nonce   BYTEA,
    token_expires_at      TIMESTAMPTZ,
    connected_at          TIMESTAMPTZ,
    last_refreshed_at     TIMESTAMPTZ,
    last_refresh_error    TEXT,
    last_refresh_error_at TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (vault_id, credential_key),
    FOREIGN KEY (vault_id, credential_key) REFERENCES credentials(vault_id, key) ON DELETE CASCADE
);

CREATE TABLE credential_oauth_states (
    id              TEXT PRIMARY KEY,
    state_hash      TEXT NOT NULL UNIQUE,
    code_verifier   TEXT NOT NULL,
    vault_id        TEXT NOT NULL,
    credential_key  TEXT NOT NULL,
    redirect_url    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE TABLE dynamic_secret_leases (
    lease_id            TEXT PRIMARY KEY,
    vault_id            TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    dynamic_secret_name TEXT NOT NULL,
    project_id          TEXT NOT NULL,
    environment         TEXT NOT NULL,
    secret_path         TEXT NOT NULL,
    expire_at           TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_agent_id              ON sessions(agent_id);
CREATE INDEX idx_sessions_user_id               ON sessions(user_id);
CREATE UNIQUE INDEX idx_sessions_public_id      ON sessions(public_id);
CREATE INDEX idx_sessions_vault_id              ON sessions(vault_id);
CREATE INDEX idx_proposals_vault_status         ON proposals(vault_id, status);
CREATE INDEX idx_proposals_approval_token_hash  ON proposals(approval_token_hash);
CREATE INDEX idx_email_verifications_email      ON email_verifications(email, status);
CREATE INDEX idx_email_verifications_code_hash  ON email_verifications(code_hash);
CREATE INDEX idx_vault_grants_vault             ON vault_grants(vault_id);
CREATE INDEX idx_vault_grants_actor             ON vault_grants(actor_id);
CREATE INDEX idx_vault_grants_type              ON vault_grants(actor_type);
CREATE INDEX idx_password_resets_email          ON password_resets(email, status);
CREATE INDEX idx_password_resets_code_hash      ON password_resets(code_hash);
CREATE INDEX idx_user_invites_token_hash        ON user_invites(token_hash);
CREATE INDEX idx_user_invites_email_status      ON user_invites(email, status);
CREATE INDEX idx_user_invite_vaults_vault       ON user_invite_vaults(vault_id);
CREATE INDEX idx_request_logs_vault_id_desc     ON request_logs(vault_id, id DESC);
CREATE INDEX idx_request_logs_id_desc           ON request_logs(id DESC);
CREATE INDEX idx_credential_oauth_states_expires ON credential_oauth_states(expires_at);
CREATE INDEX idx_dynamic_secret_leases_vault    ON dynamic_secret_leases(vault_id);

INSERT INTO vaults (id, name, created_at, updated_at)
VALUES ('00000000-0000-0000-0000-000000000000', 'default', NOW(), NOW());

INSERT INTO broker_configs (id, vault_id, services_json, created_at, updated_at)
VALUES ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000000', '[]', NOW(), NOW());
`
