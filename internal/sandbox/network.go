package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// NetworkLabelKey / NetworkLabelValue are set on every docker network
// agent-vault creates so PruneStaleNetworks can identify ones it owns
// without touching networks from other tools. The same label key is
// applied to per-invocation claude-home volumes for symmetric pruning.
const (
	NetworkLabelKey    = "agent-vault-sandbox"
	NetworkLabelValue  = "1"
	NetworkNamePrefix  = "agent-vault-"
	VolumeNamePrefix   = "agent-vault-claude-home-"
	DefaultPruneGrace  = 60 * time.Second
	sessionIDBytes     = 8 // 16 hex chars
	sessionLabelPrefix = "agent-vault-session="
)

// Network describes a created per-invocation docker bridge network.
type Network struct {
	Name      string
	GatewayIP net.IP
}

// NewSessionID returns 16 lowercase hex chars from crypto/rand. Kept
// separate from the scoped auth-session token so rotating one does not
// invalidate network / volume names mid-run.
func NewSessionID() (string, error) {
	var b [sessionIDBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("session id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func networkName(sessionID string) string { return NetworkNamePrefix + sessionID }

// CreatePerInvocationNetwork creates agent-vault-<sessionID> as a
// labeled bridge network. The gateway IP is where the forwarder binds
// on Linux and what `--add-host=host.docker.internal:host-gateway`
// resolves to inside the container.
func CreatePerInvocationNetwork(ctx context.Context, sessionID string) (*Network, error) {
	name := networkName(sessionID)
	create := exec.CommandContext(ctx, "docker", "network", "create",
		"--driver", "bridge",
		"--label", NetworkLabelKey+"="+NetworkLabelValue,
		"--label", sessionLabelPrefix+sessionID,
		name,
	)
	if out, err := create.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("docker network create %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	gw, err := inspectNetworkGateway(ctx, name)
	if err != nil {
		// Use a detached context for cleanup so a ctx cancellation
		// (SIGINT during startup) doesn't leak a half-created network.
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = exec.CommandContext(cleanup, "docker", "network", "rm", name).Run()
		cancel()
		return nil, err
	}
	return &Network{Name: name, GatewayIP: gw}, nil
}

func inspectNetworkGateway(ctx context.Context, name string) (net.IP, error) {
	cmd := exec.CommandContext(ctx, "docker", "network", "inspect", name,
		"--format", "{{range .IPAM.Config}}{{.Gateway}}{{end}}")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker network inspect %s: %w", name, err)
	}
	gw := net.ParseIP(strings.TrimSpace(string(out)))
	if gw == nil {
		return nil, fmt.Errorf("docker network inspect %s: empty gateway", name)
	}
	return gw, nil
}

// RemoveNetwork is a best-effort teardown.
func RemoveNetwork(ctx context.Context, name string) error {
	return exec.CommandContext(ctx, "docker", "network", "rm", name).Run()
}

// ClaudeHomeVolumeName returns the per-invocation claude-home volume
// name for a session. Keeping the mapping in one place prevents drift
// with PruneStaleVolumes's name-prefix filter.
func ClaudeHomeVolumeName(sessionID string) string {
	return VolumeNamePrefix + sessionID
}

// RemoveVolume is a best-effort `docker volume rm`. Ignores "volume
// still in use" errors (the defer path only runs after the container
// is gone, but a racing run on the same name is theoretically possible
// with the shared volume).
func RemoveVolume(ctx context.Context, name string) error {
	return exec.CommandContext(ctx, "docker", "volume", "rm", name).Run()
}

// PruneStaleVolumes removes agent-vault-claude-home-* named volumes
// that no container is currently mounting. Analogous to
// PruneStaleNetworks — reclaims volumes left behind by crashed runs.
// No grace period is needed because, unlike networks, volumes are only
// "in use" while a container has them attached; docker rejects rm on
// attached volumes, so racing creators are self-protecting.
func PruneStaleVolumes(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "volume", "ls",
		"--filter", "name="+VolumeNamePrefix,
		"--format", "{{.Name}}",
	)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("docker volume ls: %w", err)
	}
	for _, name := range strings.Fields(string(out)) {
		// VolumeNamePrefix has a trailing dash, so it matches only the
		// per-invocation volumes ("agent-vault-claude-home-<sid>"), never
		// the shared volume ("agent-vault-claude-home") whose name lacks
		// the dash. Docker rejects rm on in-use volumes, so racing
		// runs are self-protecting.
		if !strings.HasPrefix(name, VolumeNamePrefix) {
			continue
		}
		_ = exec.CommandContext(ctx, "docker", "volume", "rm", name).Run()
	}
	return nil
}

// PruneStaleNetworks removes agent-vault-* networks with zero attached
// containers whose Created timestamp is older than grace. The grace
// window is load-bearing: invocation B's prune must not delete
// invocation A's freshly-created network before A attaches its
// container. Defaults to DefaultPruneGrace.
func PruneStaleNetworks(ctx context.Context, grace time.Duration) error {
	if grace <= 0 {
		grace = DefaultPruneGrace
	}
	names, err := listLabeledNetworks(ctx)
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-grace)
	for _, n := range names {
		info, err := inspectNetworkInfo(ctx, n)
		if err != nil {
			continue // best-effort
		}
		if !shouldPrune(info, cutoff) {
			continue
		}
		// Ignore errors: another run may be removing it too, or it may
		// have just attached a container between ls and rm.
		_ = exec.CommandContext(ctx, "docker", "network", "rm", n).Run()
	}
	return nil
}

func listLabeledNetworks(ctx context.Context) ([]string, error) {
	cmd := exec.CommandContext(ctx, "docker", "network", "ls",
		"--filter", "label="+NetworkLabelKey+"="+NetworkLabelValue,
		"--filter", "name="+NetworkNamePrefix,
		"--format", "{{.Name}}",
	)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker network ls: %w", err)
	}
	raw := strings.Fields(string(out))
	// Defense in depth: docker's `name=` filter is a substring match.
	// Enforce strict prefix in Go so an unrelated network like
	// "my-agent-vault-thing" never matches.
	filtered := raw[:0]
	for _, n := range raw {
		if strings.HasPrefix(n, NetworkNamePrefix) {
			filtered = append(filtered, n)
		}
	}
	return filtered, nil
}

// networkInfo is the slice of `docker network inspect` output we care
// about for prune decisions.
type networkInfo struct {
	Created    time.Time
	Containers map[string]any
}

func inspectNetworkInfo(ctx context.Context, name string) (networkInfo, error) {
	cmd := exec.CommandContext(ctx, "docker", "network", "inspect", name, "--format", "{{json .}}")
	out, err := cmd.Output()
	if err != nil {
		return networkInfo{}, err
	}
	return parseNetworkInspect(out)
}

func parseNetworkInspect(data []byte) (networkInfo, error) {
	var raw struct {
		Created    time.Time      `json:"Created"`
		Containers map[string]any `json:"Containers"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return networkInfo{}, fmt.Errorf("parse network inspect: %w", err)
	}
	return networkInfo{Created: raw.Created, Containers: raw.Containers}, nil
}

func shouldPrune(info networkInfo, cutoff time.Time) bool {
	if len(info.Containers) > 0 {
		return false
	}
	if info.Created.After(cutoff) {
		return false
	}
	return true
}
