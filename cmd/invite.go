package cmd

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// formatDuration formats a duration as a human-readable string (e.g. "15m", "2h").
func formatDuration(d time.Duration) string {
	if d >= time.Hour {
		return fmt.Sprintf("%.0fh", d.Hours())
	}
	return fmt.Sprintf("%.0fm", d.Minutes())
}

// copyToClipboard copies text to the system clipboard.
func copyToClipboard(text string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "linux":
		if _, err := exec.LookPath("xclip"); err == nil {
			cmd = exec.Command("xclip", "-selection", "clipboard")
		} else if _, err := exec.LookPath("xsel"); err == nil {
			cmd = exec.Command("xsel", "--clipboard", "--input")
		} else {
			return fmt.Errorf("no clipboard tool found (install xclip or xsel)")
		}
	default:
		return fmt.Errorf("clipboard not supported on %s", runtime.GOOS)
	}
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

// buildAgentInvitePrompt builds the prompt text that an operator pastes into an agent's chat.
func buildAgentInvitePrompt(inviteURL string, ttl time.Duration) string {
	return fmt.Sprintf(`You are being invited to register as a persistent agent with Agent Vault, a local HTTP proxy that lets you call external APIs without seeing credentials.

To accept this invite, make the following HTTP request:

POST %s
Content-Type: application/json

{}

The response contains your session token and usage instructions.

This invite expires in %s and can only be used once.
`, inviteURL, formatDuration(ttl))
}
