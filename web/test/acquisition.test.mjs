import test from "node:test";
import assert from "node:assert/strict";

import {
  acquisitionCancelRequest,
  acquisitionStartRequest,
  acquisitionStatusPath,
  buildApprovalCredentialPayload,
  canEditAcquisitionPolicy,
  isAcquisitionActive,
  isAcquisitionTerminal,
  normalizeAcquisitionList,
  normalizeHandlerCatalog,
  normalizeVaultAcquisitionPolicy,
  nextAcquisitionPollDelay,
  pollAcquisitionStatuses,
  serializeAcquisitionPolicy,
  shouldPollAcquisitions,
} from "../src/lib/acquisition.ts";

test("acquisition requests contain identifiers only", () => {
  assert.deepEqual(
    acquisitionStartRequest("demo vault", 17, "TOKEN/ONE", "github-cli", "github.com"),
    {
      path: "/v1/admin/proposals/17/acquisitions/TOKEN%2FONE/start",
      init: {
        method: "POST",
        body: JSON.stringify({ vault: "demo vault", handler: "github-cli", profile: "github.com" }),
      },
    },
  );
  assert.deepEqual(acquisitionCancelRequest("demo vault", 17, "TOKEN/ONE"), {
    path: "/v1/admin/proposals/17/acquisitions/TOKEN%2FONE/cancel",
    init: { method: "POST", body: JSON.stringify({ vault: "demo vault" }) },
  });
  assert.equal(
    acquisitionStatusPath("demo vault", 17, "TOKEN/ONE"),
    "/v1/admin/proposals/17/acquisitions?vault=demo+vault&key=TOKEN%2FONE",
  );
});

test("policy serialization keeps browser DOM explicit and default-off", () => {
  assert.equal(
    serializeAcquisitionPolicy({ enabled_handlers: ["github-cli"], browser_dom_enabled: false }),
    JSON.stringify({ enabled_handlers: ["github-cli"], browser_dom_enabled: false }),
  );
  assert.deepEqual(normalizeVaultAcquisitionPolicy({ enabled_handlers: [], browser_dom_enabled: false }), {
    enabled_handlers: [], browser_dom_enabled: false,
  });
  assert.equal(normalizeVaultAcquisitionPolicy({ enabled_handlers: null, browser_dom_enabled: false }), null);
});

test("handler catalog discards registry-only metadata", () => {
  const sentinel = "registry-secret-metadata";
  const handlers = normalizeHandlerCatalog({ handlers: [{
    id: "github-cli",
    kind: "executable",
    allowed_keys: ["GITHUB_TOKEN"],
    allowed_profiles: ["github.com"],
    executable_path: sentinel,
    sha256: sentinel,
    signing_identity: sentinel,
  }] });
  assert.deepEqual(handlers, [{
    id: "github-cli",
    kind: "executable",
    allowed_keys: ["GITHUB_TOKEN"],
    allowed_profiles: ["github.com"],
  }]);
  assert.equal(JSON.stringify(handlers).includes(sentinel), false);
  assert.equal(normalizeHandlerCatalog({}), null);
  assert.equal(normalizeHandlerCatalog({ handlers: [{ id: "broken" }] }), null);
});

test("policy editing requires a successfully loaded handler catalog", () => {
  assert.equal(canEditAcquisitionPolicy({ canManage: true, loading: false, policyLoaded: true, catalogReady: true }), true);
  assert.equal(canEditAcquisitionPolicy({ canManage: true, loading: false, policyLoaded: true, catalogReady: false }), false);
  assert.equal(canEditAcquisitionPolicy({ canManage: true, loading: true, policyLoaded: true, catalogReady: true }), false);
  assert.equal(canEditAcquisitionPolicy({ canManage: false, loading: false, policyLoaded: true, catalogReady: true }), false);
});

test("status normalization projects only the safe response contract", () => {
  const sentinel = "sentinel-secret-must-not-render";
  const jobs = normalizeAcquisitionList({
    acquisitions: [{
      id: "job-1",
      proposal_id: 17,
      key: "GITHUB_TOKEN",
      attempt: 1,
      handler_id: "github-cli",
      profile: "github.com",
      mode: "native",
      state: "awaiting_user",
      source: "github-cli",
      continuation_expires_at: "2026-09-24T00:05:00Z",
      created_at: "2026-09-24T00:00:00Z",
      updated_at: "2026-09-24T00:00:01Z",
      secret: sentinel,
      credential: sentinel,
      continuation_ticket_hash: sentinel,
      context_binding_id: sentinel,
      executable_path: sentinel,
      sha256: sentinel,
    }],
  });

  assert.equal(jobs.length, 1);
  assert.equal(jobs[0].state, "awaiting_user");
  assert.equal(JSON.stringify(jobs).includes(sentinel), false);
  assert.deepEqual(Object.keys(jobs[0]).sort(), [
    "attempt", "completed_at", "continuation_expires_at", "created_at",
    "credential_expires_at", "error_code", "handler_id", "id", "key",
    "mode", "profile", "proposal_id", "source", "started_at", "state", "updated_at",
  ]);
  assert.equal(normalizeAcquisitionList({}), null);
  assert.equal(normalizeAcquisitionList({ acquisitions: [{ state: "running" }] }), null);
});

test("polling is bounded to active jobs", () => {
  for (const state of ["queued", "running", "awaiting_user"]) {
    assert.equal(isAcquisitionActive(state), true);
    assert.equal(isAcquisitionTerminal(state), false);
  }
  for (const state of ["succeeded", "failed", "cancelled", "expired"]) {
    assert.equal(isAcquisitionActive(state), false);
    assert.equal(isAcquisitionTerminal(state), true);
  }
  assert.equal(shouldPollAcquisitions([{ state: "running" }]), true);
  assert.equal(shouldPollAcquisitions([{ state: "succeeded" }]), false);
  assert.equal(shouldPollAcquisitions([]), false);
  assert.equal(nextAcquisitionPollDelay({ hasActiveJobs: true, failureCount: 0, elapsedMs: 1000 }), 2500);
  assert.equal(nextAcquisitionPollDelay({ hasActiveJobs: false, failureCount: 0, elapsedMs: 1000 }), null);
  assert.equal(nextAcquisitionPollDelay({ hasActiveJobs: false, failureCount: 1, elapsedMs: 1000 }), 2500);
  assert.equal(nextAcquisitionPollDelay({ hasActiveJobs: true, failureCount: 4, elapsedMs: 1000 }), null);
  assert.equal(nextAcquisitionPollDelay({ hasActiveJobs: true, failureCount: 0, elapsedMs: 300000 }), null);
});

test("approval payload omits provider-satisfied and OAuth slots", () => {
  assert.deepEqual(
    buildApprovalCredentialPayload(
      [
        { key: "ACQUIRED", type: "static" },
        { key: "MANUAL", type: "static" },
        { key: "OAUTH", type: "oauth" },
      ],
      { ACQUIRED: "  ", MANUAL: " manual-value ", OAUTH: "must-not-send" },
      new Map([["ACQUIRED", { state: "succeeded" }]]),
    ),
    { MANUAL: "manual-value" },
  );
});

test("poll lifecycle retries transient failures and stops on a terminal state", async () => {
  const rows = [
    new Error("temporary"),
    { acquisitions: [{
      id: "job-1", proposal_id: 17, key: "TOKEN", attempt: 1,
      handler_id: "provider", profile: "default", mode: "native", state: "running",
      created_at: "2026-09-24T00:00:00Z", updated_at: "2026-09-24T00:00:01Z",
    }] },
    { acquisitions: [{
      id: "job-1", proposal_id: 17, key: "TOKEN", attempt: 1,
      handler_id: "provider", profile: "default", mode: "native", state: "succeeded",
      created_at: "2026-09-24T00:00:00Z", updated_at: "2026-09-24T00:00:02Z",
    }] },
  ];
  const seen = [];
  const errors = [];
  await pollAcquisitionStatuses({
    signal: new AbortController().signal,
    fetchStatus: async () => {
      const next = rows.shift();
      if (next instanceof Error) throw next;
      return next;
    },
    onJobs: (jobs) => seen.push(jobs[0].state),
    onError: (error) => errors.push(error.message),
    wait: async () => {},
    now: () => 0,
  });
  assert.deepEqual(errors, ["temporary"]);
  assert.deepEqual(seen, ["running", "succeeded"]);
});

test("poll lifecycle ignores a response delivered after abort", async () => {
  const controller = new AbortController();
  let resolveResponse;
  const seen = [];
  const running = pollAcquisitionStatuses({
    signal: controller.signal,
    fetchStatus: () => new Promise((resolve) => { resolveResponse = resolve; }),
    onJobs: (jobs) => seen.push(jobs),
    onError: () => assert.fail("abort must not surface as an error"),
    wait: async () => {},
    now: () => 0,
  });
  controller.abort();
  resolveResponse({ acquisitions: [] });
  await running;
  assert.deepEqual(seen, []);
});

test("poll lifecycle aborts a hung status request at its deadline", async () => {
  let requestSignal;
  const poll = pollAcquisitionStatuses({
    signal: new AbortController().signal,
    fetchStatus: (signal) => {
      requestSignal = signal;
      return new Promise((_, reject) => {
        signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
      });
    },
    onJobs: () => assert.fail("hung request must not publish jobs"),
    onError: () => assert.fail("deadline abort must not surface as a request error"),
    maxDurationMs: 5,
  }).then(() => "completed");
  const outcome = await Promise.race([
    poll,
    new Promise((resolve) => setTimeout(() => resolve("timeout"), 100)),
  ]);
  assert.equal(outcome, "completed");
  assert.equal(requestSignal.aborted, true);
});
