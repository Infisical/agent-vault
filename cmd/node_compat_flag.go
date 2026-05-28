package cmd

import (
	"fmt"
	"path/filepath"
	"strings"
)

// nodeCompatAutoBases lists binary base-names that need the Node
// compatibility preload injected by `agent-vault run`. Each entry is a
// confirmed-in-the-wild incompatibility that AV can't fix proxy-side:
//
//   - "openclaw": (1) axios v1.x mis-parses TLS-wrapped HTTPS_PROXY URLs
//     and routes the request *to* the broker as the origin server; (2)
//     @slack/web-api places tokens in the request body when used via the
//     method-arg shape Bolt's per-event authorize triggers, but AV's
//     substitution surfaces are path/query/header only. The preload
//     in internal/openclawcompat patches both in-process.
//
// Add new entries here with the same evidence bar — a documented incident
// pinned to a specific library version. Speculative entries make the
// auto-mode harder to reason about.
var nodeCompatAutoBases = map[string]struct{}{
	"openclaw": {},
}

// NodeCompatMode is the value type for --node-compat, mirroring the
// IsolationMode pattern. Three states: auto (detect by binary base-name),
// on (force-inject), off (force-skip; escape hatch for users who patch
// axios themselves or are wrapping a custom OpenClaw fork).
type NodeCompatMode string

const (
	NodeCompatAuto NodeCompatMode = "auto"
	NodeCompatOn   NodeCompatMode = "on"
	NodeCompatOff  NodeCompatMode = "off"
)

// String / Type / Set implement pflag.Value so cobra can bind this as a
// flag with validated values.

func (m NodeCompatMode) String() string { return string(m) }
func (m NodeCompatMode) Type() string   { return "node-compat" }
func (m *NodeCompatMode) Set(v string) error {
	switch strings.ToLower(v) {
	case "auto":
		*m = NodeCompatAuto
	case "on", "true":
		*m = NodeCompatOn
	case "off", "false":
		*m = NodeCompatOff
	default:
		return fmt.Errorf("invalid --node-compat value %q (accepted: auto, on, off)", v)
	}
	return nil
}

// nodeWrapperBases lists binary base-names that frequently shell out
// another Node script (the openclaw user-systemd unit, for example,
// invokes `/usr/bin/node /usr/lib/node_modules/openclaw/dist/index.js
// gateway --port 18789`). When the wrapping binary is one of these,
// auto-mode also scans the remaining argv for a known-incompatible
// entrypoint path before deciding whether to inject the preload.
var nodeWrapperBases = map[string]struct{}{
	"node":   {},
	"nodejs": {},
}

// nodeCompatPathHints lists path substrings that identify an OpenClaw
// entrypoint script being passed as a positional arg to `node`. Hits on
// any of these (combined with a .js suffix) tell auto-mode to treat the
// invocation as "this is OpenClaw, even though args[0] is just `node`."
// Conservative on purpose — the alternative is over-injecting the
// preload for any random Node script, which is a no-op but pollutes the
// startup log and surprises operators.
var nodeCompatPathHints = []string{
	"/openclaw/",   // matches /usr/lib/node_modules/openclaw/dist/index.js, /opt/homebrew/lib/node_modules/openclaw/dist/index.js, /root/.openclaw/npm/node_modules/openclaw/dist/index.js, etc.
	"/@openclaw/", // future-proof for scoped npm packages like @openclaw/cli
}

// nodeCompatEnabled returns true when `agent-vault run` should inject the
// OpenClaw compat preload for the given invocation under the given mode.
//
//   - "on":   inject regardless of args
//   - "off":  never inject
//   - "auto" (zero value): inject when either
//     (a) the wrapping binary's base-name is in nodeCompatAutoBases
//     (e.g. invoked directly as `openclaw …`), OR
//     (b) the wrapping binary is `node` / `nodejs` AND a subsequent
//     positional arg matches one of nodeCompatPathHints AND ends
//     in `.js` (e.g. the user-systemd ExecStart shape OpenClaw
//     writes: `node /usr/lib/node_modules/openclaw/dist/index.js
//     gateway --port 18789`).
//
// args is the full argv (args[0] is the binary). Absolute paths in
// args[0] are accepted; filepath.Base strips the directory.
func nodeCompatEnabled(mode NodeCompatMode, args []string) bool {
	switch mode {
	case NodeCompatOn:
		return true
	case NodeCompatOff:
		return false
	}
	if len(args) == 0 {
		return false
	}

	base := filepath.Base(args[0])
	if _, ok := nodeCompatAutoBases[base]; ok {
		return true
	}
	if _, ok := nodeWrapperBases[base]; !ok {
		return false
	}
	// node-wrapper case: scan positional args for a known openclaw
	// entrypoint path. Bare flags (e.g. `--max-old-space-size=…`) are
	// skipped — they can't be the entrypoint.
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if !strings.HasSuffix(a, ".js") {
			continue
		}
		for _, hint := range nodeCompatPathHints {
			if strings.Contains(a, hint) {
				return true
			}
		}
	}
	return false
}

// appendNodeOptionsRequire appends "--require=<path>" to whatever
// NODE_OPTIONS value already exists in env, preserving operator-set
// preloads so layered patches still load. If NODE_OPTIONS isn't set,
// the key is appended fresh.
//
// Idempotency check is tokenized (split on whitespace + exact match)
// rather than substring-based. A raw strings.Contains would
// false-positive on prefix-overlapping paths — e.g. an operator-set
// "NODE_OPTIONS=--require=/x/preload.js.bak" would mask a new
// "--require=/x/preload.js" injection, silently disabling the preload.
func appendNodeOptionsRequire(env []string, path string) []string {
	addition := "--require=" + path
	for i, kv := range env {
		if strings.HasPrefix(kv, "NODE_OPTIONS=") {
			existing := kv[len("NODE_OPTIONS="):]
			for _, tok := range strings.Fields(existing) {
				if tok == addition {
					return env
				}
			}
			env[i] = "NODE_OPTIONS=" + strings.TrimSpace(existing+" "+addition)
			return env
		}
	}
	return append(env, "NODE_OPTIONS="+addition)
}
