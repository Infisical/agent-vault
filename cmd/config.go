package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage instance settings (owner only)",
}

var configGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show instance settings",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		url := sess.Address + "/v1/admin/settings"
		respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
		if err != nil {
			return err
		}

		var result struct {
			AllowedEmailDomains []string `json:"allowed_email_domains"`
			InviteOnly          bool     `json:"invite_only"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if result.InviteOnly {
			fmt.Fprintln(cmd.OutOrStdout(), "invite_only: enabled")
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "invite_only: disabled")
		}

		if len(result.AllowedEmailDomains) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "allowed_email_domains: (unrestricted)")
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "allowed_email_domains: %s\n", strings.Join(result.AllowedEmailDomains, ", "))
		}

		return nil
	},
}

var configSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Update instance settings",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		domainsFlag, _ := cmd.Flags().GetString("allowed-domains")
		inviteOnlyFlag, _ := cmd.Flags().GetBool("invite-only")

		payload := make(map[string]interface{})

		if cmd.Flags().Changed("invite-only") {
			payload["invite_only"] = inviteOnlyFlag
		}

		if cmd.Flags().Changed("allowed-domains") {
			var domains []string
			if domainsFlag != "" {
				for _, d := range strings.Split(domainsFlag, ",") {
					d = strings.TrimSpace(d)
					if d != "" {
						domains = append(domains, d)
					}
				}
			}
			if domains == nil {
				domains = []string{}
			}
			payload["allowed_email_domains"] = domains
		}

		if len(payload) == 0 {
			return fmt.Errorf("no settings to update. Use --invite-only or --allowed-domains")
		}

		body, _ := json.Marshal(payload)
		url := sess.Address + "/v1/admin/settings"
		respBody, err := doAdminRequestWithBody("PUT", url, sess.Token, body)
		if err != nil {
			return err
		}

		var result struct {
			AllowedEmailDomains []string `json:"allowed_email_domains"`
			InviteOnly          bool     `json:"invite_only"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if cmd.Flags().Changed("invite-only") {
			if result.InviteOnly {
				fmt.Fprintf(cmd.OutOrStdout(), "%s Invite-only mode enabled. Only vault invites can create new accounts.\n", successText("✓"))
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "%s Invite-only mode disabled. Open registration is allowed.\n", successText("✓"))
			}
		}
		if cmd.Flags().Changed("allowed-domains") {
			if len(result.AllowedEmailDomains) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "%s Signup domain restriction removed (all domains allowed).\n", successText("✓"))
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "%s Signups restricted to: %s\n", successText("✓"), strings.Join(result.AllowedEmailDomains, ", "))
			}
		}

		return nil
	},
}

func init() {
	configSetCmd.Flags().Bool("invite-only", false, "enable invite-only mode (only vault invites can create accounts)")
	configSetCmd.Flags().String("allowed-domains", "", "comma-separated list of allowed email domains (empty to clear)")
	configCmd.AddCommand(configGetCmd)
	configCmd.AddCommand(configSetCmd)
	ownerCmd.AddCommand(configCmd)
}
