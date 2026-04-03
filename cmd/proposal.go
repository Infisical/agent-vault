package cmd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/Infisical/agent-vault/internal/proposal"
	"github.com/Infisical/agent-vault/internal/session"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// displayProposal prints the full details of a proposal (metadata, rules, credentials).
func displayProposal(w io.Writer, cs *store.Proposal) {
	fmt.Fprintf(w, "%s\n", boldText(fmt.Sprintf("Proposal #%d", cs.ID)))
	fmt.Fprintf(w, "%s %s\n", fieldLabel("Status:"), statusBadge(cs.Status))
	fmt.Fprintf(w, "%s %s\n", fieldLabel("Created:"), cs.CreatedAt.Format(time.RFC3339))
	if cs.ReviewedAt != nil {
		fmt.Fprintf(w, "%s %s\n", fieldLabel("Reviewed:"), *cs.ReviewedAt)
	}
	if cs.Message != "" {
		fmt.Fprintf(w, "%s %s\n", fieldLabel("Message:"), cs.Message)
	}
	if cs.ReviewNote != "" {
		fmt.Fprintf(w, "%s %s\n", fieldLabel("Note:"), cs.ReviewNote)
	}

	printRules(w, cs.RulesJSON)
	printCredentialSlots(w, cs.CredentialsJSON)
}

// printRules prints proposed rules with colored action markers.
func printRules(w io.Writer, rulesJSON string) {
	var rules []proposal.Rule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err == nil && len(rules) > 0 {
		fmt.Fprintf(w, "\n%s\n", sectionHeader("Proposed rules:"))
		for _, r := range rules {
			fmt.Fprintf(w, "  %s %s", actionMarker(string(r.Action)), r.Host)
			if r.Description != "" {
				fmt.Fprintf(w, "  %s", mutedText(fmt.Sprintf("(%s)", r.Description)))
			}
			_, _ = fmt.Fprintln(w)
			if r.Action == proposal.ActionSet && r.Auth != nil {
				fmt.Fprintf(w, "      %s: %s\n", mutedText("auth"), r.Auth.Type)
			}
		}
	}
}

// printCredentialSlots prints credential slots with colored action markers and tags.
func printCredentialSlots(w io.Writer, credentialsJSON string) {
	var credentials []proposal.CredentialSlot
	if err := json.Unmarshal([]byte(credentialsJSON), &credentials); err == nil && len(credentials) > 0 {
		fmt.Fprintf(w, "\n%s\n", sectionHeader("Credentials:"))
		for _, s := range credentials {
			provided := ""
			if s.HasValue {
				provided = " " + tagText("[agent-provided]")
			}
			fmt.Fprintf(w, "  %s %s%s", actionMarker(string(s.Action)), s.Key, provided)
			if s.Description != "" {
				fmt.Fprintf(w, "  %s", mutedText(fmt.Sprintf("(%s)", s.Description)))
			}
			if s.Obtain != "" {
				fmt.Fprintf(w, "\n    %s", mutedText("obtain: "+s.Obtain))
			}
			_, _ = fmt.Fprintln(w)
		}
	}
}

// collectCredentialValues prompts for credential values that need human input.
// It skips agent-provided and delete-action slots, only prompting for
// slots that have no value and aren't covered by credentialOverrides.
func collectCredentialValues(cmd *cobra.Command, cs *store.Proposal, credentialOverrides map[string]string) (map[string]string, error) {
	var credentialSlots []proposal.CredentialSlot
	if err := json.Unmarshal([]byte(cs.CredentialsJSON), &credentialSlots); err != nil {
		return nil, fmt.Errorf("parsing proposal credentials: %w", err)
	}

	credentials := make(map[string]string)

	// Copy overrides.
	for k, v := range credentialOverrides {
		credentials[k] = v
	}

	for _, slot := range credentialSlots {
		if slot.Action == proposal.ActionDelete {
			continue
		}
		// Already covered by override.
		if _, ok := credentials[slot.Key]; ok {
			continue
		}
		// Agent-provided — the server will handle decryption; skip prompting.
		if slot.HasValue {
			fmt.Fprintf(cmd.OutOrStderr(), "%s: [agent-provided] ****\n", slot.Key)
			_, _ = fmt.Fprint(cmd.OutOrStderr(), "Accept agent value? [Y/n] ")
			reader := bufio.NewReader(os.Stdin)
			answer, _ := reader.ReadString('\n')
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer != "n" && answer != "no" {
				continue // let server use the agent-provided value
			}
			// Human wants to override the agent value.
			fmt.Fprintf(cmd.OutOrStderr(), "Enter value for %s: ", slot.Key)
			valBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			_, _ = fmt.Fprintln(cmd.OutOrStderr())
			if err != nil {
				return nil, fmt.Errorf("reading credential: %w", err)
			}
			credentials[slot.Key] = string(valBytes)
			continue
		}

		// No value provided — must prompt.
		fmt.Fprintf(cmd.OutOrStderr(), "Enter value for %s", slot.Key)
		if slot.Description != "" {
			fmt.Fprintf(cmd.OutOrStderr(), " (%s)", slot.Description)
		}
		_, _ = fmt.Fprint(cmd.OutOrStderr(), ": ")
		valBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		_, _ = fmt.Fprintln(cmd.OutOrStderr())
		if err != nil {
			return nil, fmt.Errorf("reading credential: %w", err)
		}
		credentials[slot.Key] = string(valBytes)
	}

	return credentials, nil
}

// sendApproveRequest sends a proposal approval to the running server via HTTP.
func sendApproveRequest(sess *session.ClientSession, vault string, id int, credentials map[string]string) error {
	body, err := json.Marshal(map[string]interface{}{
		"vault":       vault,
		"credentials": credentials,
	})
	if err != nil {
		return fmt.Errorf("marshalling request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/admin/proposals/%d/approve", sess.Address, id)
	return doAdminRequest("POST", url, sess.Token, body)
}

// sendRejectRequest sends a proposal rejection to the running server via HTTP.
func sendRejectRequest(sess *session.ClientSession, vault string, id int, reason string) error {
	body, err := json.Marshal(map[string]interface{}{
		"vault": vault,
		"reason":    reason,
	})
	if err != nil {
		return fmt.Errorf("marshalling request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/admin/proposals/%d/reject", sess.Address, id)
	return doAdminRequest("POST", url, sess.Token, body)
}

// formatIDs formats a slice of proposal IDs for display, e.g. "(#1, #4, #7)".
func formatIDs(ids []int) string {
	if len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("#%d", id)
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// fetchProposal fetches a proposal from the admin API and returns it as a store.Proposal.
func fetchProposal(sess *session.ClientSession, vault string, id int) (*store.Proposal, error) {
	url := fmt.Sprintf("%s/v1/admin/proposals/%d?vault=%s", sess.Address, id, vault)
	respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
	if err != nil {
		return nil, err
	}
	return parseProposalJSON(respBody)
}

// parseProposalJSON parses the admin proposal API response into a store.Proposal.
func parseProposalJSON(data []byte) (*store.Proposal, error) {
	var resp struct {
		ID          int     `json:"id"`
		Status      string  `json:"status"`
		Message     string  `json:"message"`
		UserMessage string  `json:"user_message"`
		RulesJSON   string  `json:"rules_json"`
		CredentialsJSON string  `json:"credentials_json"`
		ReviewNote  string  `json:"review_note"`
		ReviewedAt  *string `json:"reviewed_at"`
		CreatedAt   string  `json:"created_at"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parsing proposal: %w", err)
	}

	createdAt, _ := time.Parse(time.RFC3339, resp.CreatedAt)

	return &store.Proposal{
		ID:          resp.ID,
		Status:      resp.Status,
		Message:     resp.Message,
		UserMessage: resp.UserMessage,
		RulesJSON:   resp.RulesJSON,
		CredentialsJSON: resp.CredentialsJSON,
		ReviewNote:  resp.ReviewNote,
		ReviewedAt:  resp.ReviewedAt,
		CreatedAt:   createdAt,
	}, nil
}


// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

var proposalCmd = &cobra.Command{
	Use:   "proposal",
	Short: "Manage proposals (proposed policy and credential changes)",
}

var proposalListCmd = &cobra.Command{
	Use:   "list",
	Short: "List proposals for a vault",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		status, _ := cmd.Flags().GetString("status")

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/admin/proposals?vault=%s", sess.Address, vault)
		if status != "" {
			url += "&status=" + status
		}
		respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
		if err != nil {
			return err
		}

		var resp struct {
			Proposals []struct {
				ID        int    `json:"id"`
				Status    string `json:"status"`
				Message   string `json:"message"`
				CreatedAt string `json:"created_at"`
			} `json:"proposals"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if len(resp.Proposals) == 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "No proposals found in vault %q.\n", vault)
			return nil
		}

		t := newTable(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"#", "STATUS", "CREATED", "MESSAGE"})
		for _, cs := range resp.Proposals {
			created := cs.CreatedAt
			if parsed, err := time.Parse(time.RFC3339, cs.CreatedAt); err == nil {
				created = parsed.Format("2006-01-02 15:04")
			}
			msg := truncateText(cs.Message, 60)
			t.AppendRow(table.Row{cs.ID, statusBadge(cs.Status), created, msg})
		}
		t.Render()
		return nil
	},
}

var proposalShowCmd = &cobra.Command{
	Use:   "show <number>",
	Short: "Show details of a proposal",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)

		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid proposal number: %s", args[0])
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		cs, err := fetchProposal(sess, vault, id)
		if err != nil {
			return err
		}

		displayProposal(cmd.OutOrStdout(), cs)
		return nil
	},
}

var proposalApproveCmd = &cobra.Command{
	Use:   "approve <number> [KEY=VALUE ...]",
	Short: "Approve and apply a pending proposal",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		yes, _ := cmd.Flags().GetBool("yes")

		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid proposal number: %s", args[0])
		}

		// Parse KEY=VALUE args for credential overrides.
		credentialOverrides := make(map[string]string)
		for _, arg := range args[1:] {
			idx := strings.IndexByte(arg, '=')
			if idx < 1 {
				return fmt.Errorf("invalid format %q, expected KEY=VALUE", arg)
			}
			credentialOverrides[arg[:idx]] = arg[idx+1:]
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		cs, err := fetchProposal(sess, vault, id)
		if err != nil {
			return err
		}
		if cs.Status != "pending" {
			return fmt.Errorf("proposal #%d is already %s", id, cs.Status)
		}

		// Show summary.
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n", boldText(fmt.Sprintf("Proposal #%d: %s", id, cs.Message)))
		printRules(cmd.OutOrStdout(), cs.RulesJSON)
		printCredentialSlots(cmd.OutOrStdout(), cs.CredentialsJSON)
		_, _ = fmt.Fprintln(cmd.OutOrStdout())

		if !yes {
			fmt.Fprintf(cmd.OutOrStderr(), "Approve this proposal? [y/N] ")
			reader := bufio.NewReader(os.Stdin)
			answer, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("reading input: %w", err)
			}
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer != "y" && answer != "yes" {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Aborted.")
				return nil
			}
		}

		// Collect credential values for slots that need human input.
		credentials, err := collectCredentialValues(cmd, cs, credentialOverrides)
		if err != nil {
			return err
		}

		// Send approval to the running server.
		if err := sendApproveRequest(sess, vault, id, credentials); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Proposal #%d approved and applied.\n", successText("✓"), id)
		return nil
	},
}

var proposalRejectCmd = &cobra.Command{
	Use:   "reject <number>",
	Short: "Reject a pending proposal",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		reason, _ := cmd.Flags().GetString("reason")

		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid proposal number: %s", args[0])
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		if err := sendRejectRequest(sess, vault, id, reason); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Proposal #%d rejected.\n", successText("✓"), id)
		return nil
	},
}

var proposalReviewCmd = &cobra.Command{
	Use:   "review",
	Short: "Interactively review all pending proposals",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireTTY(); err != nil {
			return err
		}

		vault := resolveVault(cmd)

		sess, err := ensureSession()
		if err != nil {
			return err
		}
		// Fetch pending proposals via API.
		url := fmt.Sprintf("%s/v1/admin/proposals?vault=%s&status=pending", sess.Address, vault)
		respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
		if err != nil {
			return err
		}

		var resp struct {
			Proposals []struct {
				ID int `json:"id"`
			} `json:"proposals"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if len(resp.Proposals) == 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "No pending proposals in vault %q.\n", vault)
			return nil
		}

		w := cmd.OutOrStdout()
		total := len(resp.Proposals)
		fmt.Fprintf(w, "Found %d pending proposal(s) in vault %q.\n", total, vault)

		// Track results for summary.
		var approved, rejected, skipped []int

		for i, csRef := range resp.Proposals {
			fmt.Fprintf(w, "\n%s\n\n", boldText(fmt.Sprintf("══ Proposal %d of %d ══", i+1, total)))

			// Re-fetch to check for concurrent status changes.
			fresh, err := fetchProposal(sess, vault, csRef.ID)
			if err != nil {
				fmt.Fprintf(cmd.OutOrStderr(), "Error loading proposal #%d: %v\n", csRef.ID, err)
				skipped = append(skipped, csRef.ID)
				continue
			}
			if fresh.Status != "pending" {
				fmt.Fprintf(w, "Proposal #%d is no longer pending (now: %s), skipping.\n", fresh.ID, fresh.Status)
				skipped = append(skipped, csRef.ID)
				continue
			}

			displayProposal(w, fresh)
			_, _ = fmt.Fprintln(w)

			var action string
			err = huh.NewSelect[string]().
				Title("Action").
				Options(
					huh.NewOption("Approve", "approve"),
					huh.NewOption("Reject", "reject"),
					huh.NewOption("Skip", "skip"),
					huh.NewOption("Quit", "quit"),
				).
				Value(&action).
				Run()
			if err != nil {
				if errors.Is(err, huh.ErrUserAborted) {
					_, _ = fmt.Fprintln(w, "Aborted.")
					break
				}
				return err
			}

			switch action {
			case "approve":
				credentials, err := collectCredentialValues(cmd, fresh, nil)
				if err != nil {
					fmt.Fprintf(cmd.OutOrStderr(), "Error collecting credentials for #%d: %v\n", fresh.ID, err)
					skipped = append(skipped, fresh.ID)
					continue
				}

				if err := sendApproveRequest(sess, vault, fresh.ID, credentials); err != nil {
					fmt.Fprintf(cmd.OutOrStderr(), "Error approving proposal #%d: %v\n", fresh.ID, err)
					skipped = append(skipped, fresh.ID)
				} else {
					fmt.Fprintf(w, "%s Proposal #%d approved and applied.\n", successText("✓"), fresh.ID)
					approved = append(approved, fresh.ID)
				}

			case "reject":
				var reason string
				err = huh.NewInput().
					Title("Reason (optional)").
					Value(&reason).
					Run()
				if err != nil && !errors.Is(err, huh.ErrUserAborted) {
					return err
				}

				if err := sendRejectRequest(sess, vault, fresh.ID, reason); err != nil {
					fmt.Fprintf(cmd.OutOrStderr(), "Error rejecting proposal #%d: %v\n", fresh.ID, err)
					skipped = append(skipped, fresh.ID)
				} else {
					fmt.Fprintf(w, "%s Proposal #%d rejected.\n", successText("✓"), fresh.ID)
					rejected = append(rejected, fresh.ID)
				}

			case "skip":
				skipped = append(skipped, fresh.ID)
			}

			if action == "quit" {
				break
			}
		}

		// Print summary.
		_, _ = fmt.Fprintln(w)
		fmt.Fprintf(w, "%s\n", boldText("Review complete:"))
		fmt.Fprintf(w, "  %s %d %s\n", successText("Approved:"), len(approved), formatIDs(approved))
		fmt.Fprintf(w, "  %s %d %s\n", errorText("Rejected:"), len(rejected), formatIDs(rejected))
		fmt.Fprintf(w, "  %s  %d %s\n", mutedText("Skipped:"), len(skipped), formatIDs(skipped))

		return nil
	},
}

func init() {
	proposalListCmd.Flags().String("status", "", "filter by status (pending, applied, rejected, expired)")
	proposalApproveCmd.Flags().Bool("yes", false, "skip confirmation prompt")
	proposalRejectCmd.Flags().String("reason", "", "reason for rejection")

	proposalCmd.AddCommand(proposalListCmd)
	proposalCmd.AddCommand(proposalShowCmd)
	proposalCmd.AddCommand(proposalApproveCmd)
	proposalCmd.AddCommand(proposalRejectCmd)
	proposalCmd.AddCommand(proposalReviewCmd)
	vaultCmd.AddCommand(proposalCmd)
}
