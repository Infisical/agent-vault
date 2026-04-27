package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/Infisical/agent-vault/internal/isolation"
)

// containerOnlyFlags are no-ops in host mode. hostOnlyFlags are
// no-ops in container mode (where MITM is always on, enforced by the
// iptables lockdown). Either direction is a foot-gun if accepted
// silently — reject in both.
var (
	containerOnlyFlags = []string{"image", "mount", "keep", "no-firewall", "home-volume-shared", "share-agent-dir"}
	hostOnlyFlags      = []string{"no-mitm"}
)

// validateContainerFlagCombos enforces mutual-exclusion between container-mode
// flags that would otherwise both try to own /home/claude/.claude. Split from
// validateIsolationFlagConflicts because the "which mode wants which flag"
// axis and the "these two flags can't coexist" axis are independent.
func validateContainerFlagCombos(cmd *cobra.Command) error {
	homeShared, _ := cmd.Flags().GetBool("home-volume-shared")
	shareAgentDir, _ := cmd.Flags().GetBool("share-agent-dir")
	if homeShared && shareAgentDir {
		return errors.New("--home-volume-shared and --share-agent-dir are mutually exclusive")
	}
	return nil
}

func validateIsolationFlagConflicts(cmd *cobra.Command, mode IsolationMode) error {
	var disallowed []string
	var otherMode string
	if mode == IsolationContainer {
		disallowed = hostOnlyFlags
		otherMode = "host"
	} else {
		disallowed = containerOnlyFlags
		otherMode = "container"
	}
	for _, name := range disallowed {
		f := cmd.Flags().Lookup(name)
		if f == nil || !f.Changed {
			continue
		}
		return fmt.Errorf("--%s requires --isolation=%s", name, otherMode)
	}
	return nil
}

// runContainer launches the target agent inside a Docker container with
// egress locked to the agent-vault proxy via iptables.
func runContainer(cmd *cobra.Command, args []string, scopedToken, addr, vault string) error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return fmt.Errorf("--isolation=container: only linux and darwin are supported in v1 (got %s)", runtime.GOOS)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return errors.New("--isolation=container: `docker` not found in PATH")
	}

	// Validate flag combos + set up host-side state for --share-agent-dir
	// before any expensive ops (MITM fetch, network create, image build).
	if err := validateContainerFlagCombos(cmd); err != nil {
		return err
	}
	homeShared, _ := cmd.Flags().GetBool("home-volume-shared")
	shareAgentDir, _ := cmd.Flags().GetBool("share-agent-dir")

	var hostAgentDir string
	var hostUID, hostGID int
	if shareAgentDir {
		// Running as root on Linux would remap the in-container claude
		// user to uid 0, combining with --cap-add NET_ADMIN/NET_RAW/
		// SETUID/SETGID/KILL to give the agent a much larger blast
		// radius than a normal user. --security-opt=no-new-privileges
		// doesn't undo ambient caps on uid 0. Reject.
		if runtime.GOOS == "linux" && os.Getuid() == 0 {
			return errors.New("--share-agent-dir: refusing to map the in-container user to root; re-run agent-vault as a non-root user")
		}
		userHome, herr := os.UserHomeDir()
		if herr != nil {
			return fmt.Errorf("--share-agent-dir: resolve home dir: %w", herr)
		}
		hostAgentDir = filepath.Join(userHome, ".claude")
		if err := os.MkdirAll(hostAgentDir, 0o700); err != nil {
			return fmt.Errorf("--share-agent-dir: create %s: %w", hostAgentDir, err)
		}
		// Touch ~/.claude.json so docker doesn't auto-create a dir
		// where Claude expects a file (O_CREATE without O_TRUNC is a
		// no-op when the file already exists).
		configPath := filepath.Join(userHome, ".claude.json")
		f, err := os.OpenFile(configPath, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("--share-agent-dir: ensure %s: %w", configPath, err)
		}
		_ = f.Close()
		// macOS stores auth in Keychain, not on disk — bridge it into
		// the file Linux Claude reads inside the container.
		populateClaudeCredentialsFromKeychain(hostAgentDir)
		// Docker Desktop on macOS translates UIDs through its hypervisor,
		// so HOST_UID remapping is Linux-only.
		if runtime.GOOS == "linux" {
			hostUID = os.Getuid()
			hostGID = os.Getgid()
		}
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Housekeeping: trim resources leaked by crashed runs before we
	// create new ones. All best-effort.
	isolation.PruneHostCAFiles()
	_ = isolation.PruneStaleNetworks(ctx, isolation.DefaultPruneGrace)
	_ = isolation.PruneStaleVolumes(ctx)

	// Pull the MITM CA from the server. Container mode always routes
	// through MITM — --no-mitm is a host-mode-only escape hatch.
	pem, mitmPort, mitmEnabled, mitmTLS, err := fetchMITMCA(addr)
	if err != nil {
		return fmt.Errorf("fetch MITM CA: %w", err)
	}
	if !mitmEnabled {
		return errors.New("--isolation=container requires the MITM proxy; server has it disabled")
	}
	if mitmPort == 0 {
		mitmPort = DefaultMITMPort
	}

	// Upstream agent-vault HTTP port for the forwarder. Parsed from
	// --address / session address, with DefaultPort as a fallback.
	upstreamHTTPPort := DefaultPort
	if u, perr := url.Parse(addr); perr == nil {
		if p, cerr := strconv.Atoi(u.Port()); cerr == nil && p > 0 {
			upstreamHTTPPort = p
		}
	}

	sessionID, err := isolation.NewSessionID()
	if err != nil {
		return err
	}

	hostCAPath, err := isolation.WriteHostCAFile(pem, sessionID)
	if err != nil {
		return fmt.Errorf("write CA: %w", err)
	}

	network, err := isolation.CreatePerInvocationNetwork(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("create docker network: %w", err)
	}
	defer func() {
		// Detached context so a parent ctx cancel doesn't skip the
		// cleanup exec itself.
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = isolation.RemoveNetwork(cleanup, network.Name)
	}()

	if !homeShared && !shareAgentDir {
		defer func() {
			// Per-invocation volume: remove after the container exits
			// so .claude state (auth tokens, session history) doesn't
			// accumulate one volume per invocation. Shared-mode volume
			// is opt-in persistent; host-bind mode never creates one.
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = isolation.RemoveVolume(cleanup, isolation.ClaudeHomeVolumeName(sessionID))
		}()
	}

	bindIP := isolation.HostBindIP(network)
	if bindIP == nil {
		return errors.New("could not determine host bind IP for forwarder")
	}

	fwd, err := isolation.StartForwarder(ctx, bindIP, upstreamHTTPPort, mitmPort)
	if err != nil {
		return fmt.Errorf("start forwarder: %w", err)
	}
	defer func() { _ = fwd.Close() }()

	image, _ := cmd.Flags().GetString("image")
	imageRef, err := isolation.EnsureImage(ctx, image, os.Stderr)
	if err != nil {
		return err
	}

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getwd: %w", err)
	}

	env := isolation.BuildContainerEnv(scopedToken, vault, fwd.HTTPPort, fwd.MITMPort, mitmTLS)

	mounts, _ := cmd.Flags().GetStringArray("mount")
	keep, _ := cmd.Flags().GetBool("keep")
	noFirewall, _ := cmd.Flags().GetBool("no-firewall")

	dockerArgs, err := isolation.BuildRunArgs(isolation.Config{
		ImageRef:         imageRef,
		SessionID:        sessionID,
		WorkDir:          workDir,
		HostCAPath:       hostCAPath,
		NetworkName:      network.Name,
		AttachTTY:        term.IsTerminal(int(os.Stdin.Fd())),
		Keep:             keep,
		NoFirewall:       noFirewall,
		HomeVolumeShared: homeShared,
		HostAgentDir:     hostAgentDir,
		HostUID:          hostUID,
		HostGID:          hostGID,
		Mounts:           mounts,
		Env:              env,
		CommandArgs:      args,
	})
	if err != nil {
		return err
	}

	dockerBin, err := exec.LookPath("docker")
	if err != nil {
		return err
	}

	if noFirewall {
		fmt.Fprintln(os.Stderr, "agent-vault: WARNING --no-firewall active, container egress is unrestricted")
	}
	fmt.Fprintf(os.Stderr, "%s routing container HTTPS through MITM on %s:%d (container view: host.docker.internal:%d)\n",
		successText("agent-vault:"), bindIP, fwd.MITMPort, fwd.MITMPort)
	fmt.Fprintf(os.Stderr, "%s starting %s with isolation=container (%s)...\n\n",
		successText("agent-vault:"), boldText(args[0]), network.Name)

	// Fork docker (instead of syscall.Exec) so the forwarder stays
	// alive for the container's lifetime. Go listeners are FD_CLOEXEC,
	// so exec'ing would close them before the container could dial
	// host.docker.internal:<fwd-port>, producing ECONNREFUSED on every
	// HTTPS call through the MITM path.
	//
	// Docker is in our process group (default), so the kernel delivers
	// TTY signals (SIGINT, SIGWINCH) to both docker and us. Docker's
	// --init/tini handles them for the container; we ignore them in
	// the parent so we don't exit before the child and leak the
	// forwarder mid-call.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	go func() {
		for range sigs {
		}
	}()

	child := exec.Command(dockerBin, dockerArgs...)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	err = child.Run()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// Return an ExitCodeError so defers (network teardown,
			// signal.Stop, forwarder close) run before Execute() exits
			// with the container's actual status. Silence cobra's own
			// error + usage printing on this path — the container
			// already wrote whatever it had to say to stderr, and a
			// usage block after `pytest` exits 1 is pure noise.
			// SilenceErrors and SilenceUsage are independent gates in
			// cobra, so both must be set.
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			return &ExitCodeError{Code: exitErr.ExitCode()}
		}
		return fmt.Errorf("docker run: %w", err)
	}
	return nil
}
