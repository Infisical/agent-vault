export type AcquisitionState =
  | "queued"
  | "running"
  | "awaiting_user"
  | "succeeded"
  | "failed"
  | "cancelled"
  | "expired";

export interface AcquisitionDeclaration {
  handler: string;
  profile: string;
  mode: "native" | "guided" | "oauth" | "device" | "server_passthrough";
}

export interface VaultAcquisitionPolicy {
  enabled_handlers: string[];
  browser_dom_enabled: boolean;
}

export interface VaultAcquisitionHandlerSummary {
  id: string;
  kind: string;
  allowed_keys: string[];
  allowed_profiles: string[];
}

export interface ProposalAcquisition {
  id: string;
  proposal_id: number;
  key: string;
  attempt: number;
  handler_id: string;
  profile: string;
  mode: string;
  state: AcquisitionState;
  source?: string;
  error_code?: string;
  credential_expires_at?: string;
  continuation_expires_at?: string;
  started_at?: string;
  completed_at?: string;
  created_at: string;
  updated_at: string;
}

export interface AcquisitionRequest {
  path: string;
  init: RequestInit;
}

const activeStates = new Set<AcquisitionState>([
  "queued",
  "running",
  "awaiting_user",
]);

const terminalStates = new Set<AcquisitionState>([
  "succeeded",
  "failed",
  "cancelled",
  "expired",
]);

const allStates = new Set<AcquisitionState>([
  ...activeStates,
  ...terminalStates,
]);

export function isAcquisitionActive(state: string): boolean {
  return activeStates.has(state as AcquisitionState);
}

export function isAcquisitionTerminal(state: string): boolean {
  return terminalStates.has(state as AcquisitionState);
}

export function shouldPollAcquisitions(
  jobs: ReadonlyArray<Pick<ProposalAcquisition, "state">>,
): boolean {
  return jobs.some((job) => isAcquisitionActive(job.state));
}

export function nextAcquisitionPollDelay({
  hasActiveJobs,
  failureCount,
  elapsedMs,
}: {
  hasActiveJobs: boolean;
  failureCount: number;
  elapsedMs: number;
}): number | null {
  if (elapsedMs >= 300_000 || failureCount > 3) return null;
  if (failureCount > 0 || hasActiveJobs) return 2500;
  return null;
}

type AcquisitionPollOptions = {
  signal: AbortSignal;
  fetchStatus: (signal: AbortSignal) => Promise<unknown>;
  onJobs: (jobs: ProposalAcquisition[]) => void;
  onError: (error: Error) => void;
  wait?: (delayMs: number, signal: AbortSignal) => Promise<void>;
  now?: () => number;
  maxDurationMs?: number;
};

function waitForAcquisitionPoll(delayMs: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const timer = setTimeout(done, delayMs);
    signal.addEventListener("abort", done, { once: true });
    function done() {
      clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve();
    }
  });
}

export async function pollAcquisitionStatuses({
  signal,
  fetchStatus,
  onJobs,
  onError,
  wait = waitForAcquisitionPoll,
  now = Date.now,
  maxDurationMs = 300_000,
}: AcquisitionPollOptions): Promise<void> {
  const startedAt = now();
  let failureCount = 0;
  let hasActiveJobs = false;
  while (!signal.aborted) {
    const elapsedBeforeRequest = now() - startedAt;
    const remainingForRequest = maxDurationMs - elapsedBeforeRequest;
    if (remainingForRequest <= 0) return;
    const requestController = new AbortController();
    let deadlineReached = false;
    const abortRequest = () => requestController.abort();
    signal.addEventListener("abort", abortRequest, { once: true });
    const deadline = setTimeout(() => {
      deadlineReached = true;
      requestController.abort();
    }, remainingForRequest);
    try {
      const raw = await fetchStatus(requestController.signal);
      if (signal.aborted || deadlineReached) return;
      const jobs = normalizeAcquisitionList(raw);
      if (!jobs) throw new Error("Invalid acquisition status response");
      failureCount = 0;
      hasActiveJobs = shouldPollAcquisitions(jobs);
      onJobs(jobs);
      if (!hasActiveJobs) return;
    } catch (err) {
      if (signal.aborted || deadlineReached) return;
      failureCount += 1;
      onError(err instanceof Error ? err : new Error("Failed to load acquisition status"));
    } finally {
      clearTimeout(deadline);
      signal.removeEventListener("abort", abortRequest);
    }
    const elapsedMs = now() - startedAt;
    if (elapsedMs >= maxDurationMs) return;
    const delay = nextAcquisitionPollDelay({
      hasActiveJobs,
      failureCount,
      elapsedMs,
    });
    if (delay === null) return;
    await wait(Math.min(delay, maxDurationMs - elapsedMs), signal);
  }
}

export function buildApprovalCredentialPayload(
  slots: ReadonlyArray<{ key: string; type?: string }>,
  values: Readonly<Record<string, string>>,
  jobsByKey: ReadonlyMap<string, { state: string }>,
): Record<string, string> {
  const payload: Record<string, string> = {};
  for (const slot of slots) {
    if (slot.type === "oauth") continue;
    const value = (values[slot.key] ?? "").trim();
    if (jobsByKey.get(slot.key)?.state === "succeeded" && value === "") continue;
    payload[slot.key] = value;
  }
  return payload;
}

export function acquisitionStartRequest(
  vault: string,
  proposalID: number,
  key: string,
  handler: string,
  profile: string,
): AcquisitionRequest {
  return {
    path: `/v1/admin/proposals/${proposalID}/acquisitions/${encodeURIComponent(key)}/start`,
    init: {
      method: "POST",
      body: JSON.stringify({ vault, handler, profile }),
    },
  };
}

export function acquisitionCancelRequest(
  vault: string,
  proposalID: number,
  key: string,
): AcquisitionRequest {
  return {
    path: `/v1/admin/proposals/${proposalID}/acquisitions/${encodeURIComponent(key)}/cancel`,
    init: { method: "POST", body: JSON.stringify({ vault }) },
  };
}

export function acquisitionStatusPath(
  vault: string,
  proposalID: number,
  key?: string,
): string {
  const query = new URLSearchParams({ vault });
  if (key) query.set("key", key);
  return `/v1/admin/proposals/${proposalID}/acquisitions?${query.toString()}`;
}

export function serializeAcquisitionPolicy(policy: VaultAcquisitionPolicy): string {
  return JSON.stringify({
    enabled_handlers: policy.enabled_handlers,
    browser_dom_enabled: policy.browser_dom_enabled,
  });
}

export function serializeInstanceAcquisitionSetting(enabled: boolean): string {
  return JSON.stringify({ credential_acquisition_enabled: enabled });
}

export function instanceAcquisitionSettingRequest(enabled: boolean): AcquisitionRequest {
  return {
    path: "/v1/admin/settings",
    init: {
      method: "PUT",
      body: serializeInstanceAcquisitionSetting(enabled),
    },
  };
}

export function canEditAcquisitionPolicy({
  canManage,
  loading,
  policyLoaded,
  catalogReady,
}: {
  canManage: boolean;
  loading: boolean;
  policyLoaded: boolean;
  catalogReady: boolean;
}): boolean {
  return canManage && !loading && policyLoaded && catalogReady;
}

function asObject(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

function stringArray(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    return null;
  }
  return value.slice();
}

export function normalizeVaultAcquisitionPolicy(value: unknown): VaultAcquisitionPolicy | null {
  const body = asObject(value);
  if (!body || typeof body.browser_dom_enabled !== "boolean") return null;
  const enabledHandlers = stringArray(body.enabled_handlers);
  if (!enabledHandlers) return null;
  return {
    enabled_handlers: enabledHandlers,
    browser_dom_enabled: body.browser_dom_enabled,
  };
}

export function normalizeHandlerCatalog(value: unknown): VaultAcquisitionHandlerSummary[] | null {
  const body = asObject(value);
  if (!body || !Array.isArray(body.handlers)) return null;
  const result: VaultAcquisitionHandlerSummary[] = [];
  for (const value of body.handlers) {
    const handler = asObject(value);
    if (!handler || typeof handler.id !== "string" || typeof handler.kind !== "string") return null;
    const allowedKeys = stringArray(handler.allowed_keys);
    const allowedProfiles = stringArray(handler.allowed_profiles);
    if (!allowedKeys || !allowedProfiles) return null;
    result.push({
      id: handler.id,
      kind: handler.kind,
      allowed_keys: allowedKeys,
      allowed_profiles: allowedProfiles,
    });
  }
  return result;
}

export function normalizeAcquisitionRecord(value: unknown): ProposalAcquisition | null {
  const row = asObject(value);
  if (!row || typeof row.id !== "string" || typeof row.proposal_id !== "number" ||
      typeof row.key !== "string" || typeof row.attempt !== "number" ||
      typeof row.handler_id !== "string" || typeof row.profile !== "string" ||
      typeof row.mode !== "string" || typeof row.state !== "string" ||
      !allStates.has(row.state as AcquisitionState) ||
      typeof row.created_at !== "string" || typeof row.updated_at !== "string") {
    return null;
  }
  return {
    id: row.id,
    proposal_id: row.proposal_id,
    key: row.key,
    attempt: row.attempt,
    handler_id: row.handler_id,
    profile: row.profile,
    mode: row.mode,
    state: row.state as AcquisitionState,
    source: optionalString(row.source),
    error_code: optionalString(row.error_code),
    credential_expires_at: optionalString(row.credential_expires_at),
    continuation_expires_at: optionalString(row.continuation_expires_at),
    started_at: optionalString(row.started_at),
    completed_at: optionalString(row.completed_at),
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

export function normalizeAcquisitionList(value: unknown): ProposalAcquisition[] | null {
  const body = asObject(value);
  if (!body || !Array.isArray(body.acquisitions)) return null;
  const jobs: ProposalAcquisition[] = [];
  for (const value of body.acquisitions) {
    const job = normalizeAcquisitionRecord(value);
    if (!job) return null;
    jobs.push(job);
  }
  return jobs;
}
