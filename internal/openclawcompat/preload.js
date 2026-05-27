// agent-vault openclaw compat preload
//
// Injected by `agent-vault run` for binaries listed in
// nodeCompatAutoBases (today: openclaw) via NODE_OPTIONS=--require=<path>.
// Runs before any user code in the child Node process.
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
//      and recomputes Content-Length so Slack sees consistent shape.
//
// Hook strategy: Module._load is patched to detect the moment axios is
// `require`'d (by openclaw's own modules, wherever it's installed). On
// first hit we attach the interceptor to the imported instance and patch
// axios.create so every instance openclaw spawns later (Slack's WebClient
// uses axios.create with a baseURL) inherits the same interceptor.
//
// Idempotent: harmless if axios is never loaded; no-op for any module
// that isn't axios.

'use strict';

const Module = require('module');
const origLoad = Module._load;
let axiosPatched = false;

function attach(instance) {
  if (!instance || typeof instance.interceptors !== 'object') return;
  // Disable axios's broken https:// proxy parsing. Node's
  // NODE_USE_ENV_PROXY=1 / undici picks up HTTPS_PROXY natively.
  if (instance.defaults) instance.defaults.proxy = false;
  instance.interceptors.request.use((config) => {
    if (typeof config.data === 'string') {
      const m = config.data.match(/(?:^|&)token=(__[a-z_]+__)/i);
      if (m) {
        config.headers = config.headers || {};
        // Force-overwrite: @slack/web-api sets its own Authorization on
        // method-arg calls (often `Bearer undefined`); without the
        // delete it leaks through and AV substitutes the wrong value.
        delete config.headers.authorization;
        config.headers.Authorization = 'Bearer ' + m[1];
        config.data = config.data
          .replace(/(?:^|&)token=__[a-z_]+__/i, '')
          .replace(/^&/, '');
        if (config.headers['Content-Length']) {
          config.headers['Content-Length'] = Buffer.byteLength(config.data);
        }
      }
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
  if (
    !axiosPatched &&
    typeof request === 'string' &&
    (request === 'axios' || request.endsWith('/axios'))
  ) {
    if (mod && typeof mod.create === 'function') {
      patchAxios(mod);
      axiosPatched = true;
    }
  }
  return mod;
};
