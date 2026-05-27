// agent-vault openclaw compat preload
//
// Injected by `agent-vault run` for binaries that auto-mode detects as
// OpenClaw (today: bare `openclaw` base-name, or `node`/`nodejs` invoking
// an `/openclaw/`-pathed entrypoint .js). Loaded via
// NODE_OPTIONS=--require=<path> before any user code in the child Node
// process.
//
// Two issues this patches, neither of which Agent Vault can fix from the
// proxy side without invasive surgery:
//
//   1. axios v1.x mis-parses TLS-wrapped HTTPS_PROXY URLs.
//      `https://broker:14322` is interpreted as the origin server, not
//      as the proxy, so requests get sent *to* the broker as their
//      destination and the broker correctly rejects them as a self-loop.
//      Fix: disable axios's built-in proxy logic; Node's
//      NODE_USE_ENV_PROXY=1 path via undici handles TLS proxies correctly.
//
//   2. @slack/web-api puts the bot token in the form body when called
//      with a method-arg shape (`client.auth.test({token})`), which is
//      exactly how Bolt's per-event `buildAuthorizeResult` invokes it.
//      Agent Vault's substitution surfaces are path/query/header only;
//      body is reserved for a future version. When the placeholder lives
//      in the body, AV doesn't see it, the literal `__slack_bot_token__`
//      reaches Slack, and Slack returns `invalid_auth`.
//      Fix: an axios request interceptor that detects
//      `token=__placeholder__` in the form body, moves it to
//      `Authorization: Bearer __placeholder__`, strips the body token,
//      and recomputes Content-Length so Slack sees a consistent shape.
//
// Hook strategy: Module._load is patched to detect the moment axios is
// `require`'d by openclaw's own modules. On first hit we attach the
// interceptor to the imported instance and patch axios.create so every
// instance openclaw spawns later (Slack's WebClient uses axios.create
// with a baseURL) inherits the same interceptor.
//
// Idempotent: harmless if axios is never loaded; no-op for any module
// that isn't axios.

'use strict';

const Module = require('module');
const origLoad = Module._load;
let axiosPatched = false;

// Header access helpers — axios v1.x wraps `config.headers` in an
// AxiosHeaders instance whose canonical store is case-insensitive and
// only reliably accessed via `.set` / `.get` / `.has` / `.delete`. Older
// axios versions and some downstream-mutated objects use plain object
// shape with mixed casing. These helpers cover both.

function setHeader(headers, name, value) {
  if (!headers) return;
  if (typeof headers.set === 'function') {
    headers.set(name, String(value));
    return;
  }
  headers[name] = String(value);
}

function delHeader(headers, name) {
  if (!headers) return;
  if (typeof headers.delete === 'function') {
    headers.delete(name);
    return;
  }
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) {
      try {
        delete headers[key];
      } catch (_) {
        // Frozen / sealed objects in strict mode throw on delete. The
        // interceptor must never bring down the agent process, so a
        // failed delete is logged-and-ignored — the subsequent setHeader
        // will overwrite via the canonical key anyway.
      }
    }
  }
}

function hasHeader(headers, name) {
  if (!headers) return false;
  if (typeof headers.has === 'function') {
    return headers.has(name);
  }
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return true;
  }
  return false;
}

// Placeholder shape: `__<name>__` where <name> matches the same
// characters credential keys can hold today (letters, digits,
// underscore). Original was [a-z_]+ which silently failed for any
// placeholder containing a digit (e.g. `__slack_bot_token_v2__`).
const PLACEHOLDER_RE = /(?:^|&)token=(__[A-Za-z0-9_]+__)/;
const PLACEHOLDER_STRIP_RE = /(?:^|&)token=__[A-Za-z0-9_]+__/g;

function attach(instance) {
  if (!instance || typeof instance.interceptors !== 'object' || instance.interceptors === null) {
    return;
  }
  // Disable axios's broken https:// proxy parsing. Node's
  // NODE_USE_ENV_PROXY=1 / undici picks up HTTPS_PROXY natively.
  if (instance.defaults) instance.defaults.proxy = false;
  instance.interceptors.request.use((config) => {
    try {
      if (typeof config.data === 'string') {
        const m = config.data.match(PLACEHOLDER_RE);
        if (m) {
          config.headers = config.headers || {};
          delHeader(config.headers, 'Authorization');
          setHeader(config.headers, 'Authorization', 'Bearer ' + m[1]);
          config.data = config.data
            .replace(PLACEHOLDER_STRIP_RE, '')
            .replace(/^&/, '');
          if (hasHeader(config.headers, 'Content-Length')) {
            setHeader(config.headers, 'Content-Length', Buffer.byteLength(config.data));
          }
        }
      }
    } catch (_) {
      // Never let interceptor errors take down the request pipeline —
      // the worst case is the placeholder isn't rewritten and the
      // upstream returns 401, which is more recoverable than crashing
      // openclaw at boot.
    }
    return config;
  });
}

function patchAxios(axios) {
  attach(axios);
  if (typeof axios.create === 'function') {
    const origCreate = axios.create.bind(axios);
    axios.create = function (...args) {
      const inst = origCreate(...args);
      attach(inst);
      return inst;
    };
  }
}

Module._load = function patchedLoad(request, parent, isMain) {
  const mod = origLoad.apply(this, arguments);
  // Exact-match only: `endsWith('/axios')` would false-positive on
  // vendored shims, test doubles, and forks like `@my-org/axios-foo`,
  // patching the wrong module and latching axiosPatched so the real
  // axios is never reached.
  if (!axiosPatched && request === 'axios') {
    if (mod && typeof mod.create === 'function') {
      patchAxios(mod);
      axiosPatched = true;
    }
  }
  return mod;
};
