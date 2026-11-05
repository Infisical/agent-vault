package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Infisical/agent-vault/internal/session"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

type proposalAcquisitionRecord struct {
	ID                    string  `json:"id"`
	ProposalID            int     `json:"proposal_id"`
	CredentialKey         string  `json:"key"`
	Attempt               int     `json:"attempt"`
	HandlerID             string  `json:"handler_id"`
	Profile               string  `json:"profile"`
	Mode                  string  `json:"mode"`
	State                 string  `json:"state"`
	Source                string  `json:"source,omitempty"`
	ErrorCode             string  `json:"error_code,omitempty"`
	CredentialExpiresAt   *string `json:"credential_expires_at,omitempty"`
	ContinuationExpiresAt *string `json:"continuation_expires_at,omitempty"`
	StartedAt             *string `json:"started_at,omitempty"`
	CompletedAt           *string `json:"completed_at,omitempty"`
	CreatedAt             string  `json:"created_at"`
	UpdatedAt             string  `json:"updated_at"`
}

func parseProposalNumber(value string) (int, error) {
	id, err := strconv.Atoi(value)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid proposal number: %s", value)
	}
	return id, nil
}

func proposalAcquisitionSession(cmd *cobra.Command) (*session.ClientSession, string, error) {
	sess, tokenSource, err := resolveSession()
	if err != nil {
		return nil, "", err
	}
	vault, err := resolveVaultForCommand(cmd, tokenSource)
	if err != nil {
		return nil, "", err
	}
	return sess, vault, nil
}

func printProposalAcquisition(cmd *cobra.Command, record proposalAcquisitionRecord) {
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s Acquisition %s for proposal #%d credential %q: %s\n",
		successText("✓"), record.ID, record.ProposalID, record.CredentialKey, record.State)
}

var proposalAcquireCmd = &cobra.Command{
	Use:   "acquire ID KEY",
	Short: "Start an approved credential-acquisition handler",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := parseProposalNumber(args[0])
		if err != nil {
			return err
		}
		handler, _ := cmd.Flags().GetString("handler")
		profile, _ := cmd.Flags().GetString("profile")
		sess, vault, err := proposalAcquisitionSession(cmd)
		if err != nil {
			return err
		}
		body, err := json.Marshal(map[string]string{"vault": vault, "handler": handler, "profile": profile})
		if err != nil {
			return err
		}
		path := fmt.Sprintf("/v1/admin/proposals/%d/acquisitions/%s/start", id, url.PathEscape(args[1]))
		response, err := doAdminRequestWithBody(http.MethodPost, sess.Address+path, sess.Token, body)
		if err != nil {
			return err
		}
		var record proposalAcquisitionRecord
		if err := json.Unmarshal(response, &record); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}
		printProposalAcquisition(cmd, record)
		return nil
	},
}

var proposalAcquisitionStatusCmd = &cobra.Command{
	Use:   "acquisition-status ID [KEY]",
	Short: "Show credential-acquisition status for a proposal",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := parseProposalNumber(args[0])
		if err != nil {
			return err
		}
		sess, vault, err := proposalAcquisitionSession(cmd)
		if err != nil {
			return err
		}
		query := url.Values{"vault": []string{vault}}
		if len(args) == 2 {
			query.Set("key", args[1])
		}
		path := fmt.Sprintf("/v1/admin/proposals/%d/acquisitions?%s", id, query.Encode())
		response, err := doAdminRequestWithBody(http.MethodGet, sess.Address+path, sess.Token, nil)
		if err != nil {
			return err
		}
		if len(args) == 2 {
			var record proposalAcquisitionRecord
			if err := json.Unmarshal(response, &record); err != nil {
				return fmt.Errorf("parsing response: %w", err)
			}
			printProposalAcquisition(cmd, record)
			return nil
		}
		var result struct {
			Acquisitions []proposalAcquisitionRecord `json:"acquisitions"`
		}
		if err := json.Unmarshal(response, &result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}
		if len(result.Acquisitions) == 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No acquisitions found for proposal #%d.\n", id)
			return nil
		}
		t := newTable(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"KEY", "ATTEMPT", "HANDLER", "MODE", "STATE", "ERROR"})
		for _, record := range result.Acquisitions {
			t.AppendRow(table.Row{record.CredentialKey, record.Attempt, record.HandlerID, record.Mode, record.State, record.ErrorCode})
		}
		t.Render()
		return nil
	},
}

var proposalAcquisitionCancelCmd = &cobra.Command{
	Use:   "acquisition-cancel ID KEY",
	Short: "Cancel an active credential acquisition",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := parseProposalNumber(args[0])
		if err != nil {
			return err
		}
		sess, vault, err := proposalAcquisitionSession(cmd)
		if err != nil {
			return err
		}
		body, err := json.Marshal(map[string]string{"vault": vault})
		if err != nil {
			return err
		}
		path := fmt.Sprintf("/v1/admin/proposals/%d/acquisitions/%s/cancel", id, url.PathEscape(args[1]))
		response, err := doAdminRequestWithBody(http.MethodPost, sess.Address+path, sess.Token, body)
		if err != nil {
			return err
		}
		var record proposalAcquisitionRecord
		if err := json.Unmarshal(response, &record); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}
		printProposalAcquisition(cmd, record)
		return nil
	},
}

func init() {
	proposalAcquireCmd.Flags().String("handler", "", "registered acquisition handler ID")
	proposalAcquireCmd.Flags().String("profile", "", "registered acquisition profile ID")
	_ = proposalAcquireCmd.MarkFlagRequired("handler")
	_ = proposalAcquireCmd.MarkFlagRequired("profile")
	proposalCmd.AddCommand(proposalAcquireCmd, proposalAcquisitionStatusCmd, proposalAcquisitionCancelCmd)
}
