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
		inviteTTL, _ := cmd.Flags().GetDuration("invite-ttl")
		direct, _ := cmd.Flags().GetBool("direct")
		agentName, _ := cmd.Flags().GetString("name")
		vaultRole, _ := cmd.Flags().GetString("role")
		ttl, _ := cmd.Flags().GetDuration("ttl")
		hasTTL := cmd.Flags().Changed("ttl")

		if direct && agentName != "" {
			return fmt.Errorf("--direct and --name are mutually exclusive")
		}
		if vaultRole != "" && vaultRole != "proxy" && vaultRole != "member" && vaultRole != "admin" {
			return fmt.Errorf("--role must be one of: proxy, member, admin")
		}
		if hasTTL && ttl > 7*24*time.Hour {
			return fmt.Errorf("--ttl cannot exceed 7 days")
		}
		if hasTTL && ttl < 5*time.Minute {
			return fmt.Errorf("--ttl must be at least 5 minutes")
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		addr := sess.Address
		if flagAddr, _ := cmd.Flags().GetString("address"); flagAddr != "" {
			addr = flagAddr
		}

		// Direct connect: mint credentials immediately.
		if direct {
			reqBody := map[string]interface{}{
				"vault": vault,
			}
			if hasTTL {
				reqBody["ttl_seconds"] = int(ttl.Seconds())
			}
			if vaultRole != "" {
				reqBody["vault_role"] = vaultRole
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

			if hasTTL {
				fmt.Fprintf(cmd.OutOrStdout(), "Direct connect session created (role: %s, expires in %s).\n\n", resp.VaultRole, formatDuration(ttl))
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Direct connect session created (role: %s, no expiry).\n\n", resp.VaultRole)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "---\n\n%s\n\n---\n", envBlock)
			if err := copyToClipboard(envBlock); err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "\n(Copied to clipboard)\n")
			}
			return nil
		}

		// Invite flow: create an invite link for the agent to redeem.
		isPersistent := agentName != ""
		reqBody := map[string]interface{}{
			"vault":       vault,
			"persistent":  isPersistent,
			"ttl_seconds": int(inviteTTL.Seconds()),
			"agent_name":  agentName,
		}
		if vaultRole != "" {
			reqBody["vault_role"] = vaultRole
		}
		if hasTTL {
			reqBody["session_ttl_seconds"] = int(ttl.Seconds())
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

		if isPersistent {
			prompt := buildPersistentInvitePrompt(inviteURL, inviteTTL, agentName)
			fmt.Fprintf(cmd.OutOrStdout(), "Agent invite created (expires in %s).\n", formatDuration(inviteTTL))
			fmt.Fprintf(cmd.OutOrStdout(), "Paste the following into your agent:\n\n")
			fmt.Fprintf(cmd.OutOrStdout(), "---\n\n%s\n---\n", prompt)
			if err := copyToClipboard(prompt); err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "\n(Copied to clipboard)\n")
			}
			return nil
		}

		prompt := buildInvitePrompt(inviteURL, inviteTTL)
		expiryNote := "no expiry"
		if hasTTL {
			expiryNote = "session expires in " + formatDuration(ttl)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Invite created (%s).\n", expiryNote)
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

		sess, err := ensureSession()
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

		sess, err := ensureSession()
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

The response contains your session token and usage instructions.

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
	inviteCreateCmd.Flags().Duration("invite-ttl", 15*time.Minute, "invite link expiration time")
	inviteCreateCmd.Flags().Duration("ttl", 0, "session expiry duration (omit for no expiry)")
	inviteCreateCmd.Flags().String("address", "", "Agent Vault server address (default: from session)")
	inviteCreateCmd.Flags().String("name", "", "pre-set the agent name (creates a named/persistent agent)")
	inviteCreateCmd.Flags().String("role", "", "vault role for the invited agent (proxy, member, admin; default: proxy)")
	inviteCreateCmd.Flags().Bool("direct", false, "mint credentials immediately (skip invite ceremony)")
	inviteListCmd.Flags().String("status", "", "filter by status (pending, redeemed, expired, revoked)")

	inviteCmd.AddCommand(inviteCreateCmd)
	inviteCmd.AddCommand(inviteListCmd)
	inviteCmd.AddCommand(inviteRevokeCmd)
	agentCmd.AddCommand(inviteCmd)
}
