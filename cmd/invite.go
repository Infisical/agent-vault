package cmd

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

var inviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Manage invite links for agent onboarding",
}

var inviteCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an invite link and print the onboarding prompt",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		ttl, _ := cmd.Flags().GetDuration("ttl")
		persistent, _ := cmd.Flags().GetBool("persistent")
		direct, _ := cmd.Flags().GetBool("direct")
		agentName, _ := cmd.Flags().GetString("name")
		vaultRole, _ := cmd.Flags().GetString("role")
		label, _ := cmd.Flags().GetString("label")
		sessionTTL, _ := cmd.Flags().GetDuration("session-ttl")

		if agentName != "" && !persistent {
			return fmt.Errorf("--name requires --persistent")
		}
		if direct && persistent {
			return fmt.Errorf("--direct and --persistent are mutually exclusive")
		}
		if direct && agentName != "" {
			return fmt.Errorf("--direct and --name are mutually exclusive")
		}
		if label != "" && persistent {
			return fmt.Errorf("--label cannot be used with --persistent")
		}
		if vaultRole != "" && vaultRole != "consumer" && vaultRole != "member" && vaultRole != "admin" {
			return fmt.Errorf("--role must be one of: consumer, member, admin")
		}
		if sessionTTL > 0 && persistent {
			return fmt.Errorf("--session-ttl cannot be used with --persistent")
		}
		if sessionTTL > 7*24*time.Hour {
			return fmt.Errorf("--session-ttl cannot exceed 7 days")
		}
		if sessionTTL > 0 && sessionTTL < 5*time.Minute {
			return fmt.Errorf("--session-ttl must be at least 5 minutes")
		}

		sess, err := loadSession()
		if err != nil {
			return err
		}

		addr := sess.Address
		if flagAddr, _ := cmd.Flags().GetString("address"); flagAddr != "" {
			addr = flagAddr
		}

		// Direct connect: mint credentials immediately.
		if direct {
			directTTL := 0 // let server apply its default (24h)
			if sessionTTL > 0 {
				directTTL = int(sessionTTL.Seconds())
			} else if cmd.Flags().Changed("ttl") {
				directTTL = int(ttl.Seconds())
			}
			reqBody := map[string]interface{}{
				"vault":       vault,
				"ttl_seconds": directTTL,
			}
			if vaultRole != "" {
				reqBody["vault_role"] = vaultRole
			}
			if label != "" {
				reqBody["label"] = label
			}
			body, err := json.Marshal(reqBody)
			if err != nil {
				return err
			}

			url := fmt.Sprintf("%s/v1/sessions/direct", addr)
			respBody, err := doAdminRequestWithBody("POST", url, sess.Token, body)
			if err != nil {
				return err
			}

			var resp struct {
				AVAddr         string `json:"av_addr"`
				AVSessionToken string `json:"av_session_token"`
				AVVault        string `json:"av_vault"`
				VaultRole      string `json:"vault_role"`
				ExpiresAt      string `json:"expires_at"`
			}
			if err := json.Unmarshal(respBody, &resp); err != nil {
				return fmt.Errorf("parsing response: %w", err)
			}

			envBlock := fmt.Sprintf("export AGENT_VAULT_ADDR=%q\nexport AGENT_VAULT_SESSION_TOKEN=%q\nexport AGENT_VAULT_VAULT=%q",
				resp.AVAddr, resp.AVSessionToken, resp.AVVault)

			displayTTL := 24 * time.Hour
			if directTTL > 0 {
				displayTTL = time.Duration(directTTL) * time.Second
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Direct connect session created (role: %s, expires in %s).\n\n", resp.VaultRole, formatDuration(displayTTL))
			fmt.Fprintf(cmd.OutOrStdout(), "---\n\n%s\n\n---\n", envBlock)
			if err := copyToClipboard(envBlock); err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "\n(Copied to clipboard)\n")
			}
			return nil
		}

		reqBody := map[string]interface{}{
			"vault":       vault,
			"persistent":  persistent,
			"ttl_seconds": int(ttl.Seconds()),
			"agent_name":  agentName,
		}
		if vaultRole != "" {
			reqBody["vault_role"] = vaultRole
		}
		if !persistent {
			if sessionTTL > 0 {
				reqBody["session_ttl_seconds"] = int(sessionTTL.Seconds())
			}
			if label != "" {
				reqBody["session_label"] = label
			}
		}
		body, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/invites", sess.Address)
		respBody, err := doAdminRequestWithBody("POST", url, sess.Token, body)
		if err != nil {
			return err
		}

		var resp struct {
			Token      string `json:"token"`
			Persistent bool   `json:"persistent"`
			ExpiresAt  string `json:"expires_at"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		inviteURL := addr + "/invite/" + resp.Token

		if persistent {
			prompt := buildPersistentInvitePrompt(inviteURL, ttl, agentName)
			fmt.Fprintf(cmd.OutOrStdout(), "Persistent agent invite created (expires in %s).\n", formatDuration(ttl))
			fmt.Fprintf(cmd.OutOrStdout(), "Paste the following into your agent:\n\n")
			fmt.Fprintf(cmd.OutOrStdout(), "---\n\n%s\n---\n", prompt)
			if err := copyToClipboard(prompt); err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "\n(Copied to clipboard)\n")
			}
			return nil
		}

		prompt := buildInvitePrompt(inviteURL, ttl)
		fmt.Fprintf(cmd.OutOrStdout(), "Invite created (expires in %s).\n", formatDuration(ttl))
		fmt.Fprintf(cmd.OutOrStdout(), "Paste the following into your agent:\n\n")
		fmt.Fprintf(cmd.OutOrStdout(), "---\n\n%s\n---\n", prompt)
		if err := copyToClipboard(prompt); err == nil {
			fmt.Fprintf(cmd.OutOrStdout(), "\n(Copied to clipboard)\n")
		}
		return nil
	},
}

var inviteListCmd = &cobra.Command{
	Use:   "list",
	Short: "List invites for a vault",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		status, _ := cmd.Flags().GetString("status")

		sess, err := loadSession()
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/invites?vault=%s", sess.Address, vault)
		if status != "" {
			url += "&status=" + status
		}
		respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
		if err != nil {
			return err
		}

		var invites []struct {
			Token     string `json:"token"`
			Status    string `json:"status"`
			CreatedAt string `json:"created_at"`
			ExpiresAt string `json:"expires_at"`
		}
		if err := json.Unmarshal(respBody, &invites); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if len(invites) == 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "No invites found in vault %q.\n", vault)
			return nil
		}

		t := newTable(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"TOKEN", "STATUS", "CREATED", "EXPIRES"})
		for _, inv := range invites {
			// Show last 8 chars for display.
			suffix := inv.Token
			if len(suffix) > 8 {
				suffix = inv.Token[len(inv.Token)-8:]
			}
			created := inv.CreatedAt
			if parsed, err := time.Parse(time.RFC3339, inv.CreatedAt); err == nil {
				created = parsed.Format("2006-01-02 15:04")
			}
			expires := inv.ExpiresAt
			if parsed, err := time.Parse(time.RFC3339, inv.ExpiresAt); err == nil {
				expires = parsed.Format("2006-01-02 15:04")
			}
			t.AppendRow(table.Row{
				"..." + suffix,
				statusBadge(inv.Status),
				created,
				expires,
			})
		}
		t.Render()
		return nil
	},
}

var inviteRevokeCmd = &cobra.Command{
	Use:   "revoke <token_suffix>",
	Short: "Revoke a pending invite",
	Long:  "Revoke a pending invite by the last 8 (or more) characters of its token.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		suffix := args[0]

		sess, err := loadSession()
		if err != nil {
			return err
		}

		// Fetch pending invites (admin session gets full tokens).
		url := fmt.Sprintf("%s/v1/invites?vault=%s&status=pending", sess.Address, vault)
		respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
		if err != nil {
			return err
		}

		var invites []struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(respBody, &invites); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		// Suffix match.
		var matches []string
		for _, inv := range invites {
			if strings.HasSuffix(inv.Token, suffix) {
				matches = append(matches, inv.Token)
			}
		}

		switch len(matches) {
		case 0:
			return fmt.Errorf("no pending invite found matching suffix %q", suffix)
		case 1:
			// Unique match — proceed.
		default:
			return fmt.Errorf("ambiguous suffix %q matches %d invites — provide more characters", suffix, len(matches))
		}

		revokeURL := fmt.Sprintf("%s/v1/invites/%s", sess.Address, matches[0])
		if err := doAdminRequest("DELETE", revokeURL, sess.Token, nil); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Invite ...%s revoked.\n", suffix)
		return nil
	},
}

func buildPersistentInvitePrompt(inviteURL string, ttl time.Duration, agentName string) string {
	bodyExample := "{}"
	if agentName == "" {
		bodyExample = `{"name": "your-agent-name"}`
	}

	nameNote := ""
	if agentName == "" {
		nameNote = "\nYou must provide a name for yourself in the request body. Choose a short, descriptive name (lowercase, hyphens allowed, 3-64 chars).\n"
	}

	return fmt.Sprintf(`You are being invited to register as a persistent agent with Agent Vault, a local HTTP proxy that lets you call external APIs without seeing credentials.
%s
To accept this invite, make the following HTTP request:

POST %s
Content-Type: application/json

%s

The response contains your service token and usage instructions. Store the service token securely — it cannot be retrieved again.

This invite expires in %s and can only be used once.
`, nameNote, inviteURL, bodyExample, formatDuration(ttl))
}

func buildInvitePrompt(inviteURL string, ttl time.Duration) string {
	return fmt.Sprintf(`You are being invited to use Agent Vault, a local HTTP proxy that lets you call external APIs (Stripe, GitHub, etc.) without seeing the underlying credentials.

To accept this invite, make the following HTTP request:

GET %s

The response contains your session token and usage instructions. Do this before making any external API calls.

This invite expires in %s and can only be used once.
`, inviteURL, formatDuration(ttl))
}

func formatDuration(d time.Duration) string {
	if d >= time.Hour {
		return fmt.Sprintf("%.0fh", d.Hours())
	}
	return fmt.Sprintf("%.0fm", d.Minutes())
}

func copyToClipboard(text string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "linux":
		// Try xclip first, fall back to xsel.
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

func init() {
	inviteCreateCmd.Flags().Duration("ttl", 15*time.Minute, "invite expiration time")
	inviteCreateCmd.Flags().String("address", "", "Agent Vault server address (default: from session)")
	inviteCreateCmd.Flags().Bool("persistent", false, "create a persistent agent invite")
	inviteCreateCmd.Flags().String("name", "", "pre-set the agent name (requires --persistent)")
	inviteCreateCmd.Flags().String("role", "", "vault role for the invited agent (consumer, member, admin; default: consumer)")
	inviteCreateCmd.Flags().Bool("direct", false, "mint credentials immediately (skip invite ceremony)")
	inviteCreateCmd.Flags().String("label", "", "optional label for the session (direct connect and temporary invites)")
	inviteCreateCmd.Flags().Duration("session-ttl", 0, "session lifetime when invite is redeemed (default: 24h; temporary invites only)")
	inviteListCmd.Flags().String("status", "", "filter by status (pending, redeemed, expired, revoked)")

	inviteCmd.AddCommand(inviteCreateCmd)
	inviteCmd.AddCommand(inviteListCmd)
	inviteCmd.AddCommand(inviteRevokeCmd)
	agentCmd.AddCommand(inviteCmd)
}
