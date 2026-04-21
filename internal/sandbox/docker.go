package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config describes everything BuildRunArgs needs to produce a fully
// resolved `docker run` argv. All values are already decided (mode,
// session ID, network, TTY) — this type does no I/O.
type Config struct {
	ImageRef         string   // "agent-vault/sandbox:<hash>" or user --image
	SessionID        string   // 16 hex chars; names the network and per-invocation volume
	WorkDir          string   // host path bound at /workspace
	HostCAPath       string   // host path bound read-only at ContainerCAPath
	NetworkName      string   // "agent-vault-<SessionID>" — must not be empty
	AttachTTY        bool     // true if stdin is a TTY; adds -t
	Keep             bool     // true → omit --rm
	NoFirewall       bool     // true → container skips init-firewall.sh (debug only)
	HomeVolumeShared bool     // true → shared volume, false → per-invocation
	Mounts           []string // raw --mount "src:dst[:ro]" strings
	Env              []string // from BuildContainerEnv
	CommandArgs      []string // claude + any agent args
}

type parsedMount struct {
	Src, Dst string
	ReadOnly bool
}

// reservedContainerDsts are bind-mount destinations agent-vault owns.
// A user --mount landing on one of these would silently replace our
// own mount and undo the sandbox guarantees.
var reservedContainerDsts = []string{
	"/workspace",
	ContainerCAPath,
	ContainerClaudeHome,
}

// BuildRunArgs produces the argv for `docker run …`. Pure apart from
// os.UserHomeDir + filepath.EvalSymlinks on user --mount sources.
func BuildRunArgs(cfg Config) ([]string, error) {
	if cfg.ImageRef == "" {
		return nil, errors.New("BuildRunArgs: ImageRef required")
	}
	if cfg.NetworkName == "" {
		return nil, errors.New("BuildRunArgs: NetworkName required (container must never land on the default bridge)")
	}
	if cfg.SessionID == "" {
		return nil, errors.New("BuildRunArgs: SessionID required")
	}
	if cfg.WorkDir == "" {
		return nil, errors.New("BuildRunArgs: WorkDir required")
	}
	if cfg.HostCAPath == "" {
		return nil, errors.New("BuildRunArgs: HostCAPath required")
	}
	if len(cfg.CommandArgs) == 0 {
		return nil, errors.New("BuildRunArgs: CommandArgs required")
	}

	home, _ := os.UserHomeDir()

	// The CWD is bind-mounted read-write at /workspace. Subject it to
	// the same host-src validation as user --mount flags so running
	// `vault run --sandbox=container` from inside ~/.agent-vault (which
	// holds the encrypted CA key + vault database) does not expose
	// that dir to the container.
	resolvedWorkDir, err := filepath.EvalSymlinks(cfg.WorkDir)
	if err != nil {
		return nil, fmt.Errorf("resolving workdir: %w", err)
	}
	if err := validateHostSrc(resolvedWorkDir, home); err != nil {
		return nil, fmt.Errorf("workspace: %w", err)
	}
	cfg.WorkDir = resolvedWorkDir

	parsed := make([]parsedMount, 0, len(cfg.Mounts))
	for _, raw := range cfg.Mounts {
		pm, err := parseAndValidateMount(raw, home)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, pm)
	}

	args := []string{"run"}
	if !cfg.Keep {
		args = append(args, "--rm")
	}
	args = append(args, "-i")
	if cfg.AttachTTY {
		args = append(args, "-t")
	}
	args = append(args,
		"--init",
		"--network", cfg.NetworkName,
		// NET_ADMIN/NET_RAW: init-firewall.sh installs iptables rules.
		// SETUID/SETGID: gosu(8) drops root to the claude user in entrypoint.sh.
		// Docker does not grant these as *ambient* caps to non-root processes,
		// so claude post-gosu has an empty effective cap set — it cannot
		// exercise any of them.
		"--cap-drop", "ALL",
		"--cap-add", "NET_ADMIN",
		"--cap-add", "NET_RAW",
		"--cap-add", "SETUID",
		"--cap-add", "SETGID",
		"--security-opt", "no-new-privileges",
		"--add-host", "host.docker.internal:host-gateway",
	)

	for _, kv := range cfg.Env {
		args = append(args, "-e", kv)
	}
	if cfg.NoFirewall {
		args = append(args, "-e", "AGENT_VAULT_NO_FIREWALL=1")
	}

	args = append(args, "-v", cfg.WorkDir+":/workspace")
	args = append(args, "-v", cfg.HostCAPath+":"+ContainerCAPath+":ro")

	homeVolume := "agent-vault-claude-home-" + cfg.SessionID
	if cfg.HomeVolumeShared {
		homeVolume = "agent-vault-claude-home"
	}
	args = append(args, "-v", homeVolume+":"+ContainerClaudeHome)

	for _, m := range parsed {
		spec := m.Src + ":" + m.Dst
		if m.ReadOnly {
			spec += ":ro"
		}
		args = append(args, "-v", spec)
	}

	args = append(args, "-w", "/workspace", cfg.ImageRef)
	args = append(args, cfg.CommandArgs...)
	return args, nil
}

// parseAndValidateMount parses a --mount "src:dst[:ro|rw]" value, resolves
// symlinks on the host src, and rejects reserved paths. homeDir may be
// empty (e.g. in tests without $HOME); the $HOME-based check is skipped
// in that case.
func parseAndValidateMount(raw, homeDir string) (parsedMount, error) {
	parts := strings.Split(raw, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return parsedMount{}, fmt.Errorf("--mount %q: want src:dst[:ro]", raw)
	}
	m := parsedMount{Src: parts[0], Dst: parts[1]}
	if len(parts) == 3 {
		switch parts[2] {
		case "ro":
			m.ReadOnly = true
		case "rw":
			// default; accept but no-op
		default:
			return parsedMount{}, fmt.Errorf("--mount %q: mode must be 'ro' or 'rw'", raw)
		}
	}
	if !filepath.IsAbs(m.Src) {
		return parsedMount{}, fmt.Errorf("--mount %q: src must be an absolute path", raw)
	}
	if !filepath.IsAbs(m.Dst) {
		return parsedMount{}, fmt.Errorf("--mount %q: dst must be an absolute path", raw)
	}

	// EvalSymlinks is the defense against laundering a forbidden path
	// via a symlink. We validate the resolved target, not the input.
	resolved, err := filepath.EvalSymlinks(m.Src)
	if err != nil {
		return parsedMount{}, fmt.Errorf("--mount %q: resolving src: %w", raw, err)
	}
	if err := validateHostSrc(resolved, homeDir); err != nil {
		return parsedMount{}, err
	}
	if err := validateContainerDst(m.Dst); err != nil {
		return parsedMount{}, err
	}
	m.Src = resolved
	return m, nil
}

func validateHostSrc(resolved, homeDir string) error {
	if isDockerSocket(resolved) {
		return errors.New("--mount: refusing to bind the docker socket (would undo every sandbox guarantee)")
	}
	if homeDir != "" {
		// Canonicalize homeDir so the prefix comparison is apples-to-apples
		// with the already-EvalSymlinks'd resolved src. On macOS `/var` is a
		// symlink to `/private/var`, and `$TMPDIR` lives under `/var/folders`,
		// so without this the comparison silently misses.
		canonicalHome := homeDir
		if c, err := filepath.EvalSymlinks(homeDir); err == nil {
			canonicalHome = c
		}
		vaultDir := filepath.Join(canonicalHome, ".agent-vault")
		if resolved == vaultDir || strings.HasPrefix(resolved, vaultDir+string(os.PathSeparator)) {
			return fmt.Errorf("--mount: refusing to bind inside %s (contains master-key-encrypted vault data)", filepath.Join(homeDir, ".agent-vault"))
		}
	}
	return nil
}

// isDockerSocket returns true for anything that points at a docker
// control socket, canonicalizing for the macOS /var→/private/var
// indirection and double-checking via file mode for unusual mount
// setups.
func isDockerSocket(resolved string) bool {
	for _, p := range []string{"/var/run/docker.sock", "/private/var/run/docker.sock"} {
		if resolved == p {
			return true
		}
	}
	if filepath.Base(resolved) != "docker.sock" {
		return false
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSocket != 0
}

func validateContainerDst(dst string) error {
	for _, reserved := range reservedContainerDsts {
		if dst == reserved || strings.HasPrefix(dst, reserved+"/") {
			return fmt.Errorf("--mount: refusing to override reserved container path %s", reserved)
		}
	}
	return nil
}
