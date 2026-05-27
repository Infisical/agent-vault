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

// nodeCompatEnabled returns true when `agent-vault run` should inject the
// OpenClaw compat preload for the given target binary, under the given
// mode.
//
// - "on":   inject regardless of binary
// - "off":  never inject
// - "auto" (and the zero value): inject iff the binary's base-name is in
//   nodeCompatAutoBases. Absolute paths are accepted; filepath.Base
//   strips the directory so /usr/local/bin/openclaw matches "openclaw".
func nodeCompatEnabled(mode NodeCompatMode, cmd string) bool {
	switch mode {
	case NodeCompatOn:
		return true
	case NodeCompatOff:
		return false
	default:
		_, ok := nodeCompatAutoBases[filepath.Base(cmd)]
		return ok
	}
}

// appendNodeOptionsRequire appends "--require=<path>" to whatever
// NODE_OPTIONS value already exists in env, preserving operator-set
// preloads so layered patches still load. If NODE_OPTIONS isn't set,
// the key is appended fresh. Idempotent: a second call with the same
// path is a no-op (defensive against repeat-injection across forked
// child processes that re-invoke agent-vault).
func appendNodeOptionsRequire(env []string, path string) []string {
	addition := "--require=" + path
	for i, kv := range env {
		if strings.HasPrefix(kv, "NODE_OPTIONS=") {
			existing := kv[len("NODE_OPTIONS="):]
			if strings.Contains(existing, addition) {
				return env
			}
			env[i] = "NODE_OPTIONS=" + strings.TrimSpace(existing+" "+addition)
			return env
		}
	}
	return append(env, "NODE_OPTIONS="+addition)
}
