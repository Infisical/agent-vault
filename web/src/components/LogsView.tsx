import { useEffect, useMemo, useRef, useState } from "react";
import { apiFetch, isAbortError } from "../lib/api";
import { applyHistoryPage, applyLiveBatch, type ViewWindowPolicy } from "../lib/logsWindow";
import { ErrorBanner, LoadingSpinner, timeAgo } from "./shared";
import DataTable, { type Column } from "./DataTable";
import Button from "./Button";
import Modal from "./Modal";

export interface LogEntry {
  id: number;
  ingress: string;
  method: string;
  host: string;
  path: string;
  matched_service: string;
  credential_keys: string[];
  status: number;
  latency_ms: number;
  error_code: string;
  actor_type: string;
  actor_id: string;
  actor_name?: string;
  created_at: string;
}

interface LogsResponse {
  logs: LogEntry[];
  next_cursor: number | null;
  latest_id: number;
}

type StatusFilter = "all" | "errors";

interface LogsViewProps {
  /** Absolute URL the view hits; e.g. `/v1/vaults/my-vault/logs`. */
  endpoint: string;
  /** Page size. Defaults to 50 (server caps at 200). */
  limit?: number;
  /** How often to poll for new rows. Defaults to 3000 ms; set to 0 to disable. */
  pollMs?: number;
  /**
   * Live tail window: the newest rows kept while polling appends; older
   * rows fall off. Without a bound the page grows DOM and heap for as
   * long as it stays open. Defaults to 1000.
   */
  tailRows?: number;
  /**
   * Rows explicitly loaded via "Load more" that live traffic will not
   * evict; loading even older rows trims beyond this. Defaults to 1000.
   */
  historyRows?: number;
  /** Max rows rendered at once; overflow is summarized in a counter. Defaults to 300. */
  maxRenderRows?: number;
  title?: string;
  description?: string;
}

export default function LogsView({
  endpoint,
  limit = 50,
  pollMs = 3000,
  tailRows = 1000,
  historyRows = 1000,
  maxRenderRows = 300,
  title = "Request Logs",
  description = "Recent proxied requests. Bodies and query strings are never recorded.",
}: LogsViewProps) {
  // Bounded view window: rows (newest-first) plus the count of rows in the
  // trailing loaded-history segment. Kept in ONE state atom so every
  // updater is pure and StrictMode-safe.
  const [view, setView] = useState<{ rows: LogEntry[]; historyCount: number }>({
    rows: [],
    historyCount: 0,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  // False once a "Load more" page comes back short: the server has no
  // rows older than what the window already holds.
  const [hasMoreHistory, setHasMoreHistory] = useState(false);
  // While true the table shows the oldest retained rows (the pages the
  // user loaded) instead of the live tail; "Back to latest" returns.
  const [browsingHistory, setBrowsingHistory] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [paused, setPaused] = useState(false);
  const [selected, setSelected] = useState<LogEntry | null>(null);

  const latestIdRef = useRef<number>(0);
  const initializedRef = useRef<boolean>(false);
  const abortRef = useRef<AbortController | null>(null);
  // Bumped on every endpoint/filter reset so in-flight responses (polls
  // and Load-more fetches alike) from the previous view are discarded
  // instead of polluting the new one.
  const epochRef = useRef<number>(0);
  // One poll at a time: a slow response must not stack overlapping polls.
  const pollInFlightRef = useRef<boolean>(false);

  const policy: ViewWindowPolicy = useMemo(
    () => ({ tailRows, historyRows }),
    [tailRows, historyRows],
  );

  const filterQS = useMemo(() => {
    const parts: string[] = [`limit=${limit}`];
    if (statusFilter === "errors") parts.push("status_bucket=err");
    return parts.join("&");
  }, [statusFilter, limit]);

  // Reset when filters change.
  useEffect(() => {
    latestIdRef.current = 0;
    initializedRef.current = false;
    epochRef.current += 1;
    // The new view owns the single-flight flag: an in-flight poll from the
    // previous view must not block live updates here (its response is
    // epoch-discarded on arrival anyway).
    pollInFlightRef.current = false;
    setView({ rows: [], historyCount: 0 });
    setHasMoreHistory(false);
    setBrowsingHistory(false);
    setError("");
    setLoading(true);
    loadInitial();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [endpoint, filterQS]);

  // Poll for new rows (tailing).
  useEffect(() => {
    if (pollMs <= 0 || paused) return;
    const id = setInterval(() => {
      pollNew();
    }, pollMs);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [endpoint, filterQS, pollMs, paused]);

  async function loadInitial() {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      const resp = await apiFetch(`${endpoint}?${filterQS}`, { signal: controller.signal });
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        setError(data.error || "Failed to load logs.");
        return;
      }
      const data: LogsResponse = await resp.json();
      setView({ rows: (data.logs ?? []).slice(0, tailRows), historyCount: 0 });
      setHasMoreHistory((data.logs ?? []).length >= limit);
      latestIdRef.current = data.latest_id || 0;
      initializedRef.current = true;
    } catch (err) {
      if (isAbortError(err)) return;
      setError("Network error.");
    } finally {
      setLoading(false);
    }
  }

  async function pollNew() {
    // Gate on the initial load completing, not on cursor > 0 — an empty
    // vault legitimately reports latest_id=0 and still needs polls so
    // the first row shows up without a reload.
    if (!initializedRef.current || pollInFlightRef.current) return;
    const epoch = epochRef.current;
    // Single-flight: a hung connection would otherwise stall tailing for
    // as long as the browser holds the socket. Accepted trade-off — the
    // pre-fix behavior stacked overlapping polls instead.
    pollInFlightRef.current = true;
    try {
      // Timeout so a hung connection cannot hold the single-flight flag
      // (and stall tailing) for as long as the browser keeps the socket.
      const resp = await apiFetch(`${endpoint}?${filterQS}&after=${latestIdRef.current}`, {
        signal: AbortSignal.timeout(Math.max(pollMs * 5, 15_000)),
      });
      if (!resp.ok) return;
      const data: LogsResponse = await resp.json();
      // The view may have been reset (endpoint/filter change) while this
      // poll was in flight; its rows and cursor belong to the old view.
      if (epoch !== epochRef.current) return;
      const fresh = data.logs ?? [];
      if (fresh.length > 0) {
        setView((w) => applyLiveBatch(w.rows, fresh, policy, w.historyCount));
      }
      // Guard against out-of-order poll responses rolling the cursor back.
      if (data.latest_id > latestIdRef.current) {
        latestIdRef.current = data.latest_id;
      }
    } catch {
      // ignore; poll errors are silent
    } finally {
      // Only this view's own poll may release the flag; a stale response
      // from before a reset must not unlock a newer poll's flight.
      if (epoch === epochRef.current) pollInFlightRef.current = false;
    }
  }

  async function loadMore() {
    // Continue paging from the OLDEST row the window currently retains —
    // never from a stale server cursor — so the loaded page always lands
    // directly below the retained window and live eviction cannot open a
    // gap between them.
    const oldestRetained = view.rows[view.rows.length - 1];
    if (!hasMoreHistory || !oldestRetained) return;
    const epoch = epochRef.current;
    setLoadingMore(true);
    try {
      const resp = await apiFetch(`${endpoint}?${filterQS}&before=${oldestRetained.id}`, {
        signal: AbortSignal.timeout(30_000),
      });
      if (!resp.ok) return;
      const data: LogsResponse = await resp.json();
      // Same stale-view discipline as pollNew: rows fetched for the old
      // endpoint/filter must not leak into the new view.
      if (epoch !== epochRef.current) return;
      const older = data.logs ?? [];
      if (older.length > 0) {
        setView((w) => applyHistoryPage(w.rows, older, policy, w.historyCount));
        // Show the user what they just loaded.
        setBrowsingHistory(true);
      }
      // A short page means the server has no rows older than the window.
      setHasMoreHistory(older.length >= limit);
    } finally {
      setLoadingMore(false);
    }
  }

  // Which slice of the bounded window is on screen: the newest rows while
  // tailing, or the oldest rows (the loaded history pages) while browsing.
  const renderOffset = browsingHistory
    ? Math.max(0, view.rows.length - maxRenderRows)
    : 0;

  const columns: Column<LogEntry>[] = [
    {
      key: "time",
      header: "Time",
      render: (r) => (
        <span className="text-sm text-text-muted" title={new Date(r.created_at).toLocaleString()}>
          {timeAgo(r.created_at)}
        </span>
      ),
    },
    {
      key: "method",
      header: "Method",
      render: (r) => (
        <span className="text-xs font-mono font-semibold text-text">{r.method}</span>
      ),
    },
    {
      key: "endpoint",
      header: "Endpoint",
      render: (r) => (
        <div className="min-w-0">
          <div className="text-sm font-medium text-text truncate">{r.host}</div>
          <div className="text-xs text-text-muted font-mono truncate max-w-[380px]">
            {r.path || "/"}
          </div>
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (r) => <StatusPill status={r.status} errorCode={r.error_code} />,
    },
    {
      key: "latency",
      header: "Latency",
      align: "right",
      render: (r) => (
        <span className="text-sm text-text-muted font-mono tabular-nums">
          {r.latency_ms} ms
        </span>
      ),
    },
  ];

  return (
    <div className="p-8 w-full max-w-[960px]">
      <div className="mb-6">
        <h2 className="text-[22px] font-semibold text-text tracking-tight mb-1">{title}</h2>
        <p className="text-sm text-text-muted">{description}</p>
      </div>

      <div className="flex flex-wrap items-center gap-3 mb-6">
        <FilterGroup label="Status">
          <FilterPill active={statusFilter === "all"} onClick={() => setStatusFilter("all")}>
            All
          </FilterPill>
          <FilterPill active={statusFilter === "errors"} onClick={() => setStatusFilter("errors")}>
            Errors
          </FilterPill>
        </FilterGroup>

        {browsingHistory && (
          <button
            onClick={() => setBrowsingHistory(false)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-text border border-border rounded-md hover:bg-bg transition-colors"
            title="Return to the live tail"
          >
            ← Back to latest
          </button>
        )}
        {pollMs > 0 && (
          <button
            onClick={() => setPaused((p) => !p)}
            className="ml-auto inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-text-muted border border-border rounded-md hover:bg-bg transition-colors"
            title={paused ? "Resume live updates" : "Pause live updates"}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                paused ? "bg-text-dim" : "bg-success animate-pulse"
              }`}
            />
            {paused ? "Paused" : "Live"}
          </button>
        )}
      </div>

      {loading ? (
        <LoadingSpinner />
      ) : error ? (
        <ErrorBanner message={error} />
      ) : (
        <>
          <DataTable
            columns={columns}
            data={view.rows}
            rowKey={(r) => r.id}
            maxRenderRows={maxRenderRows}
            renderOffset={renderOffset}
            onRowClick={(r) => setSelected(r)}
            emptyTitle="No requests yet"
            emptyDescription="Requests proxied through this vault will appear here in real time."
          />
          {hasMoreHistory && (
            <div className="flex justify-center mt-4">
              <Button
                variant="secondary"
                onClick={loadMore}
                loading={loadingMore}
                disabled={loadingMore}
              >
                Load more
              </Button>
            </div>
          )}
        </>
      )}

      {selected && <LogDetailModal log={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function FilterGroup({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-[11px] font-semibold text-text-dim uppercase tracking-wider">
        {label}
      </span>
      <div className="flex border border-border rounded-lg overflow-hidden">{children}</div>
    </div>
  );
}

function FilterPill({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`px-3 py-1.5 text-xs font-medium transition-colors border-l border-border first:border-l-0 ${
        active ? "bg-surface text-text" : "bg-bg text-text-muted hover:text-text"
      }`}
    >
      {children}
    </button>
  );
}

function StatusPill({ status, errorCode }: { status: number; errorCode: string }) {
  if (status === 0 && errorCode) {
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-danger-bg text-danger border border-danger/20 font-mono">
        {errorCode}
      </span>
    );
  }
  const tone =
    status >= 500
      ? "bg-danger-bg text-danger border-danger/20"
      : status >= 400
        ? "bg-warning-bg text-warning border-warning/20"
        : status >= 300
          ? "bg-bg text-text-muted border-border"
          : status >= 200
            ? "bg-success-bg text-success border-success/20"
            : "bg-bg text-text-dim border-border";
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border font-mono tabular-nums ${tone}`}
    >
      {status || "—"}
    </span>
  );
}

function LogDetailModal({ log, onClose }: { log: LogEntry; onClose: () => void }) {
  const rows: [string, React.ReactNode][] = [
    ["Time", new Date(log.created_at).toLocaleString()],
    ["Ingress", log.ingress],
    ["Method", <code className="font-mono">{log.method}</code>],
    ["Host", <code className="font-mono">{log.host}</code>],
    ["Path", <code className="font-mono break-all">{log.path || "/"}</code>],
    ["Status", <StatusPill status={log.status} errorCode={log.error_code} />],
    ["Latency", `${log.latency_ms} ms`],
    ["Matched service", log.matched_service || "—"],
    [
      "Credential keys",
      log.credential_keys && log.credential_keys.length > 0 ? (
        <span className="font-mono text-xs">{log.credential_keys.join(", ")}</span>
      ) : (
        "—"
      ),
    ],
    [
      "Actor",
      log.actor_type
        ? log.actor_name
          ? (
              <span>
                <span className="font-medium">{log.actor_name}</span>
                <span className="text-text-muted ml-1.5 text-xs font-mono">({log.actor_type}:{log.actor_id})</span>
              </span>
            )
          : `${log.actor_type}:${log.actor_id}`
        : "—",
    ],
    ["Error code", log.error_code || "—"],
    ["ID", <span className="font-mono">{log.id}</span>],
  ];
  return (
    <Modal open onClose={onClose} title="Request details" description="Metadata for this proxied request.">
      <dl className="space-y-2.5">
        {rows.map(([k, v]) => (
          <div key={k} className="flex gap-4 text-sm">
            <dt className="w-36 shrink-0 text-text-muted">{k}</dt>
            <dd className="flex-1 text-text break-words">{v}</dd>
          </div>
        ))}
      </dl>
    </Modal>
  );
}
