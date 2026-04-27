package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// keychainItemName is the Keychain generic-password service name that
// Claude Code writes its OAuth credential under on macOS. Linux and
// Windows build the credentials file directly; only macOS needs bridging.
const keychainItemName = "Claude Code-credentials"

// populateClaudeCredentialsFromKeychain extracts the host's Claude Code
// credential from the macOS Keychain and writes it to the host's
// ~/.claude/.credentials.json so the container (Linux, file-based auth)
// picks it up through the --share-agent-dir bind mount.
//
// Only runs on macOS hosts — other OSes already store auth in the file
// the bind mount carries through. If the file already exists it's left
// alone; the container may have refreshed it more recently than the
// Keychain and we don't want to clobber a newer token (users can `rm`
// the file to force re-extraction).
//
// Best-effort: any failure (no keychain entry, user denies the prompt,
// security binary missing) is silently swallowed so the container still
// starts and the user can /login from inside.
func populateClaudeCredentialsFromKeychain(hostAgentDir string) {
	if runtime.GOOS != "darwin" {
		return
	}
	credPath := filepath.Join(hostAgentDir, ".credentials.json")
	if _, err := os.Stat(credPath); err == nil {
		return
	}
	out, err := exec.Command("security", "find-generic-password", "-s", keychainItemName, "-w").Output()
	if err != nil {
		return
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		return
	}
	_ = os.WriteFile(credPath, []byte(token), 0o600)
}
