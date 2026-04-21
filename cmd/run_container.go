package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/Infisical/agent-vault/internal/sandbox"
)

// containerOnlyFlags are no-ops in process mode; we reject them explicitly
// rather than silently ignoring them, which would be a foot-gun.
var containerOnlyFlags = []string{"image", "mount", "keep", "no-firewall", "home-volume-shared"}

func validateSandboxFlagConflicts(cmd *cobra.Command, mode SandboxMode) error {
	if mode == SandboxContainer {
		return nil
	}
	for _, name := range containerOnlyFlags {
		f := cmd.Flags().Lookup(name)
		if f == nil {
			continue
		}
		if f.Changed {
			return fmt.Errorf("--%s requires --sandbox=container", name)
		}
	}
	return nil
}

// runContainer launches the target agent inside a Docker container with
// egress locked to the agent-vault proxy via iptables.
func runContainer(cmd *cobra.Command, args []string, scopedToken, addr, vault string) error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return fmt.Errorf("--sandbox=container: only linux and darwin are supported in v1 (got %s)", runtime.GOOS)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return errors.New("--sandbox=container: `docker` not found in PATH")
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Housekeeping: trim old CA tempfiles and networks from crashed runs
	// before we create new ones. Both are best-effort.
	sandbox.PruneHostCAFiles()
	_ = sandbox.PruneStaleNetworks(ctx, sandbox.DefaultPruneGrace)

	// Pull the MITM CA from the server. Container mode always routes
	// through MITM — --no-mitm is a process-mode-only escape hatch.
	pem, mitmPort, mitmEnabled, mitmTLS, err := fetchMITMCA(addr)
	if err != nil {
		return fmt.Errorf("fetch MITM CA: %w", err)
	}
	if !mitmEnabled {
		return errors.New("--sandbox=container requires the MITM proxy; server has it disabled")
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

	sessionID, err := sandbox.NewSessionID()
	if err != nil {
		return err
	}

	hostCAPath, err := sandbox.WriteHostCAFile(pem, sessionID)
	if err != nil {
		return fmt.Errorf("write CA: %w", err)
	}

	network, err := sandbox.CreatePerInvocationNetwork(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("create docker network: %w", err)
	}
	defer func() {
		// Detached context so a parent ctx cancel doesn't skip the
		// cleanup exec itself.
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = sandbox.RemoveNetwork(cleanup, network.Name)
	}()

	bindIP := sandbox.HostBindIP(network)
	if bindIP == nil {
		return errors.New("could not determine host bind IP for forwarder")
	}

	fwd, err := sandbox.StartForwarder(ctx, bindIP, upstreamHTTPPort, mitmPort)
	if err != nil {
		return fmt.Errorf("start forwarder: %w", err)
	}
	defer func() { _ = fwd.Close() }()

	image, _ := cmd.Flags().GetString("image")
	imageRef, err := sandbox.EnsureImage(ctx, image, os.Stderr)
	if err != nil {
		return err
	}

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getwd: %w", err)
	}

	env := sandbox.BuildContainerEnv(scopedToken, vault, fwd.HTTPPort, fwd.MITMPort, mitmTLS)

	mounts, _ := cmd.Flags().GetStringArray("mount")
	keep, _ := cmd.Flags().GetBool("keep")
	noFirewall, _ := cmd.Flags().GetBool("no-firewall")
	homeShared, _ := cmd.Flags().GetBool("home-volume-shared")

	dockerArgs, err := sandbox.BuildRunArgs(sandbox.Config{
		ImageRef:         imageRef,
		SessionID:        sessionID,
		WorkDir:          workDir,
		HostCAPath:       hostCAPath,
		NetworkName:      network.Name,
		AttachTTY:        term.IsTerminal(int(os.Stdin.Fd())),
		Keep:             keep,
		NoFirewall:       noFirewall,
		HomeVolumeShared: homeShared,
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
	fmt.Fprintf(os.Stderr, "%s starting %s in sandbox (%s)...\n\n",
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
	// Exit-code propagation via fmt.Errorf would collapse everything to
	// Cobra's generic exit 1. Return the ExitError unchanged so a caller
	// wrapping us can inspect it; for now we also lose the exact code to
	// keep defers (network teardown, signal.Stop) intact.
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("sandbox container exited with status %d", exitErr.ExitCode())
		}
		return fmt.Errorf("docker run: %w", err)
	}
	return nil
}
