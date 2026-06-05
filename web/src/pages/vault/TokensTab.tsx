import { useState, useEffect } from "react";
import {
  useVaultParams,
  LoadingSpinner,
  ErrorBanner,
  timeAgo,
  timeUntil,
} from "./shared";
import DataTable, { type Column } from "../../components/DataTable";
import Modal from "../../components/Modal";
import DropdownMenu from "../../components/DropdownMenu";
import Button from "../../components/Button";
import Select from "../../components/Select";
import Input from "../../components/Input";
import FormField from "../../components/FormField";
import CopyButton from "../../components/CopyButton";
import ConfirmDeleteModal from "../../components/ConfirmDeleteModal";
import { apiFetch } from "../../lib/api";

type VaultRole = "proxy" | "member" | "admin";

interface CreatedBy {
  id: string;
  type: "user" | "agent";
  display_name: string;
}

// Mirrors GET /v1/sessions's row shape (handle_sessions.go scopedSessionView).
// `created_by` is populated server-side but not currently rendered in the
// table; kept on the type so the API contract is faithful and a future
// column or tooltip can read it without a schema change.
interface VaultToken {
  id: string;
  label?: string;
  vault_role: VaultRole;
  created_by?: CreatedBy;
  created_at: string;
  expires_at?: string;
}

const TTL_PRESETS: { label: string; seconds: number | "custom" }[] = [
  { label: "1 hour", seconds: 3600 },
  { label: "24 hours (default)", seconds: 86400 },
  { label: "7 days", seconds: 604800 },
  { label: "Custom", seconds: "custom" },
];

const MIN_TTL_SECONDS = 300;
const MAX_TTL_SECONDS = 604800;

function roleSatisfies(callerRole: string, requested: VaultRole): boolean {
  const order: Record<string, number> = { proxy: 0, member: 1, admin: 2 };
  return (order[callerRole] ?? -1) >= order[requested];
}

function RowActions({
  token,
  vaultName,
  onRevoked,
}: {
  token: VaultToken;
  vaultName: string;
  onRevoked: () => void;
}) {
  const [confirmOpen, setConfirmOpen] = useState(false);

  async function handleRevoke() {
    const resp = await apiFetch(
      `/v1/sessions/${encodeURIComponent(token.id)}?vault=${encodeURIComponent(vaultName)}`,
      { method: "DELETE" }
    );
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.error || "Failed to revoke token");
    }
    setConfirmOpen(false);
    onRevoked();
  }

  return (
    <>
      <DropdownMenu
        width={160}
        items={[
          {
            label: "Revoke",
            onClick: () => setConfirmOpen(true),
            variant: "danger" as const,
          },
        ]}
      />
      <ConfirmDeleteModal
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        onConfirm={handleRevoke}
        title="Revoke token"
        description={
          token.label
            ? `Revoke "${token.label}"? Any agent using this token will immediately lose access.`
            : "Revoke this token? Any agent using it will immediately lose access."
        }
        confirmLabel="Revoke token"
        confirmValue={token.label || token.id}
        inputLabel={
          token.label
            ? `Type the label "${token.label}" to confirm`
            : `Type the token id to confirm`
        }
      />
    </>
  );
}

export default function TokensTab() {
  const { vaultName, vaultRole } = useVaultParams();
  const [rows, setRows] = useState<VaultToken[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const canManageTokens = roleSatisfies(vaultRole, "member");

  const columns: Column<VaultToken>[] = [
    {
      key: "label",
      header: "Label",
      render: (t) => (
        <span className="text-sm text-text">
          {t.label || <span className="text-text-dim">&mdash;</span>}
        </span>
      ),
    },
    {
      key: "vault_role",
      header: "Role",
      render: (t) => (
        <span className="text-sm text-text-muted capitalize">{t.vault_role}</span>
      ),
    },
    {
      key: "created_at",
      header: "Created",
      render: (t) => (
        <span className="text-sm text-text-muted">{timeAgo(t.created_at)}</span>
      ),
    },
    {
      key: "expires_at",
      header: "Expires",
      render: (t) => (
        <span className="text-sm text-text-muted">
          {t.expires_at ? timeUntil(t.expires_at) : "never"}
        </span>
      ),
    },
    ...(canManageTokens
      ? [
          {
            key: "actions" as const,
            header: "",
            align: "right" as const,
            render: (t: VaultToken) => (
              <RowActions token={t} vaultName={vaultName} onRevoked={fetchTokens} />
            ),
          },
        ]
      : []),
  ];

  useEffect(() => {
    fetchTokens();
  }, []);

  async function fetchTokens() {
    try {
      const resp = await apiFetch(
        `/v1/sessions?vault=${encodeURIComponent(vaultName)}`
      );
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        setError(data.error || "Failed to load tokens.");
        return;
      }
      const data = await resp.json();
      setRows(data.sessions ?? []);
      setError("");
    } catch {
      setError("Network error.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-8 w-full max-w-[960px]">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-[22px] font-semibold text-text tracking-tight mb-1">
            Tokens
          </h2>
          <p className="text-sm text-text-muted">
            Vault-scoped session tokens for agents and one-off workflows.
          </p>
        </div>
        {canManageTokens && (
          <MintTokenButton vaultName={vaultName} onMinted={fetchTokens} />
        )}
      </div>

      {loading ? (
        <LoadingSpinner />
      ) : error ? (
        <ErrorBanner message={error} />
      ) : (
        <DataTable
          columns={columns}
          data={rows}
          rowKey={(t) => t.id}
          emptyTitle="No tokens yet"
          emptyDescription="Mint a token to scope a session for a specific agent or workflow."
        />
      )}
    </div>
  );
}

function MintTokenButton({
  vaultName,
  onMinted,
}: {
  vaultName: string;
  onMinted: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [label, setLabel] = useState("");
  const [ttlPreset, setTtlPreset] = useState<number | "custom">(86400);
  const [customTtl, setCustomTtl] = useState<string>("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [mintedToken, setMintedToken] = useState<string | null>(null);

  function close() {
    // Block all close paths (ESC, backdrop, X, Cancel) while a mint is
    // in flight. Otherwise the post-await setMintedToken would write into
    // a hidden modal and the freshly-minted token would only surface on
    // the next "Mint token" click — looking like an orphan to the user.
    if (submitting) return;
    setOpen(false);
    setLabel("");
    setTtlPreset(86400);
    setCustomTtl("");
    setError("");
    setMintedToken(null);
    if (mintedToken) onMinted();
  }

  async function handleMint() {
    setError("");

    let ttlSeconds: number;
    if (ttlPreset === "custom") {
      const parsed = parseInt(customTtl, 10);
      if (!Number.isFinite(parsed) || parsed < MIN_TTL_SECONDS || parsed > MAX_TTL_SECONDS) {
        setError(`Custom TTL must be between ${MIN_TTL_SECONDS} and ${MAX_TTL_SECONDS} seconds.`);
        return;
      }
      ttlSeconds = parsed;
    } else {
      ttlSeconds = ttlPreset;
    }

    setSubmitting(true);
    try {
      const resp = await apiFetch("/v1/sessions", {
        method: "POST",
        body: JSON.stringify({
          vault: vaultName,
          vault_role: "proxy",
          ttl_seconds: ttlSeconds,
          label: label.trim(),
        }),
      });
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        setError(data.error || "Failed to mint token.");
        return;
      }
      const data = await resp.json();
      setMintedToken(data.token as string);
    } catch {
      setError("Network error.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <Button onClick={() => setOpen(true)}>
        <svg
          className="w-4 h-4"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <line x1="12" y1="5" x2="12" y2="19" />
          <line x1="5" y1="12" x2="19" y2="12" />
        </svg>
        Mint token
      </Button>

      <Modal
        open={open}
        onClose={close}
        title={mintedToken ? "Token created" : "Mint vault-scoped token"}
        description={
          mintedToken
            ? "Copy the token now — this is the only time it will be shown."
            : "Routes outbound requests through this vault. Cannot manage credentials, services, or members."
        }
        footer={
          mintedToken ? (
            <Button onClick={close}>Done</Button>
          ) : (
            <>
              <Button variant="secondary" onClick={close}>Cancel</Button>
              <Button onClick={handleMint} loading={submitting}>
                Mint token
              </Button>
            </>
          )
        }
      >
        {mintedToken ? (
          <div className="space-y-3">
            <div className="relative">
              <textarea
                readOnly
                value={mintedToken}
                rows={3}
                className="w-full px-4 py-3 bg-bg border border-border rounded-lg text-text text-sm font-mono outline-none select-all resize-none break-all"
                onFocus={(e) => e.target.select()}
              />
              <CopyButton
                value={mintedToken}
                className="absolute top-2 right-2 px-3 py-1.5 bg-primary text-primary-text rounded-md text-xs font-semibold hover:bg-primary-hover transition-colors"
              />
            </div>
            <p className="text-xs text-text-dim">
              Use with <code className="text-text-muted">AGENT_VAULT_TOKEN</code>, or in
              an <code className="text-text-muted">HTTPS_PROXY</code> URL as the userinfo.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            <FormField label="Label (optional)">
              <Input
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="claude-code"
                maxLength={100}
                autoFocus
              />
            </FormField>

            <FormField label="Lifetime">
              <Select
                value={String(ttlPreset)}
                onChange={(e) => {
                  const v = e.target.value;
                  setTtlPreset(v === "custom" ? "custom" : parseInt(v, 10));
                }}
              >
                {TTL_PRESETS.map((p) => (
                  <option key={String(p.seconds)} value={String(p.seconds)}>
                    {p.label}
                  </option>
                ))}
              </Select>
            </FormField>

            {ttlPreset === "custom" && (
              <FormField label={`Custom TTL (seconds, ${MIN_TTL_SECONDS}–${MAX_TTL_SECONDS})`}>
                <Input
                  type="number"
                  value={customTtl}
                  onChange={(e) => setCustomTtl(e.target.value)}
                  min={MIN_TTL_SECONDS}
                  max={MAX_TTL_SECONDS}
                  placeholder={String(MIN_TTL_SECONDS)}
                />
              </FormField>
            )}

            {error && <ErrorBanner message={error} />}
          </div>
        )}
      </Modal>
    </>
  );
}
