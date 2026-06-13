package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/session"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Interact with vaults",
}

var vaultCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		credStore, _ := cmd.Flags().GetString("credential-store")

		payload := map[string]interface{}{"name": name}

		switch credStore {
		case "", store.CredentialStoreBuiltin:
			// no extra payload
		case store.CredentialStoreInfisical:
			cs, err := infisicalStorePayloadFromFlags(cmd)
			if err != nil {
				return err
			}
			payload["credential_store"] = cs
		default:
			return fmt.Errorf("unsupported --credential-store %q (use %s or %s)", credStore, store.CredentialStoreBuiltin, store.CredentialStoreInfisical)
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/vaults", sess.Address)
		respBody, err := doAdminRequestWithBody("POST", url, sess.Token, body)
		if err != nil {
			return err
		}

		var resp struct {
			ID              string                 `json:"id"`
			Name            string                 `json:"name"`
			CredentialStore map[string]interface{} `json:"credential_store,omitempty"`
		}
		_ = json.Unmarshal(respBody, &resp)

		fmt.Fprintf(cmd.OutOrStdout(), "%s Created vault %q (id: %s)\n", successText("✓"), resp.Name, mutedText(resp.ID))
		if kind, ok := resp.CredentialStore["kind"].(string); ok && kind != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "  Credential store: %s\n", kind)
		}
		return nil
	},
}

var vaultCredentialStoreCmd = &cobra.Command{
	Use:   "credential-store",
	Short: "Inspect the credential store backing a vault",
}

// infisicalStorePayloadFromFlags validates the shared Infisical flags and
// returns the {kind, config, poll_interval_seconds} block used by both
// `vault create` and `vault credential-store set`.
func infisicalStorePayloadFromFlags(cmd *cobra.Command) (map[string]interface{}, error) {
	projectID, _ := cmd.Flags().GetString("infisical-project-id")
	environment, _ := cmd.Flags().GetString("infisical-environment")
	secretPath, _ := cmd.Flags().GetString("infisical-path")
	pollSecs, _ := cmd.Flags().GetInt("poll-interval-seconds")

	if projectID == "" || environment == "" {
		return nil, fmt.Errorf("--infisical-project-id and --infisical-environment are required for the %s credential store", store.CredentialStoreInfisical)
	}
	if pollSecs < 10 {
		return nil, fmt.Errorf("--poll-interval-seconds must be at least 10")
	}
	if secretPath == "" {
		secretPath = "/"
	}
	return map[string]interface{}{
		"kind": store.CredentialStoreInfisical,
		"config": map[string]interface{}{
			"project_id":  projectID,
			"environment": environment,
			"secret_path": secretPath,
		},
		"poll_interval_seconds": pollSecs,
	}, nil
}

var vaultCredentialStoreShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show the credential store kind, config, and sync health for a vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		sess, err := ensureSession()
		if err != nil {
			return err
		}
		url := fmt.Sprintf("%s/v1/vaults/%s/context", sess.Address, name)
		respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
		if err != nil {
			return err
		}
		var resp struct {
			VaultName       string                 `json:"vault_name"`
			VaultRole       string                 `json:"vault_role"`
			CredentialStore map[string]interface{} `json:"credential_store,omitempty"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "Vault: %s\n", resp.VaultName)
		printCredentialStore(out, resp.CredentialStore)
		return nil
	},
}

var vaultCredentialStoreSyncCmd = &cobra.Command{
	Use:   "sync <name>",
	Short: "Force an immediate refresh of an external-store vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		sess, err := ensureSession()
		if err != nil {
			return err
		}
		url := fmt.Sprintf("%s/v1/vaults/%s/sync", sess.Address, name)
		respBody, err := doAdminRequestWithBody("POST", url, sess.Token, nil)
		if err != nil {
			return err
		}
		var resp struct {
			CredentialStore map[string]interface{} `json:"credential_store,omitempty"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "%s Synced vault %q\n", successText("✓"), name)
		printCredentialStore(out, resp.CredentialStore)
		return nil
	},
}

var vaultCredentialStoreSetCmd = &cobra.Command{
	Use:   "set <name>",
	Short: "Switch the credential store backing a vault",
	Long: "Switch a vault's credential store after creation.\n\n" +
		"Switching to infisical OVERWRITES the vault's built-in credentials with the\n" +
		"secrets fetched from the connected source and starts polling. It requires\n" +
		"instance-owner role, since the broker's machine identity authorizes the\n" +
		"upstream fetch. Switching to builtin disconnects the external source\n" +
		"(polling stops) but KEEPS the last synced secrets in place as editable\n" +
		"built-in credentials, and is allowed for vault admins too.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		kind, _ := cmd.Flags().GetString("kind")

		var payload map[string]interface{}
		switch kind {
		case store.CredentialStoreBuiltin:
			payload = map[string]interface{}{"kind": store.CredentialStoreBuiltin}
		case store.CredentialStoreInfisical:
			cs, err := infisicalStorePayloadFromFlags(cmd)
			if err != nil {
				return err
			}
			payload = cs
		case "":
			return fmt.Errorf("--kind is required (%s or %s)", store.CredentialStoreBuiltin, store.CredentialStoreInfisical)
		default:
			return fmt.Errorf("unsupported --kind %q (use %s or %s)", kind, store.CredentialStoreBuiltin, store.CredentialStoreInfisical)
		}

		yes, _ := cmd.Flags().GetBool("yes")
		if !yes {
			var warning string
			if kind == store.CredentialStoreInfisical {
				warning = fmt.Sprintf("%s Switching vault %q to Infisical will OVERWRITE its built-in credentials with the secrets from the connected source.", warningText("WARNING"), name)
			} else {
				warning = fmt.Sprintf("%s Switching vault %q to built-in disconnects Infisical; the synced secrets are kept as built-in credentials and stop updating.", warningText("WARNING"), name)
			}
			ok, err := confirmByName(cmd, warning, name)
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}

		reqURL := fmt.Sprintf("%s/v1/vaults/%s/credential-store", sess.Address, url.PathEscape(name))
		respBody, err := doAdminRequestWithBody("PATCH", reqURL, sess.Token, body)
		if err != nil {
			return err
		}

		var resp struct {
			CredentialStore map[string]interface{} `json:"credential_store,omitempty"`
		}
		_ = json.Unmarshal(respBody, &resp)

		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "%s Switched credential store for vault %q\n", successText("✓"), name)
		printCredentialStore(out, resp.CredentialStore)
		return nil
	},
}

func printCredentialStore(out io.Writer, cs map[string]interface{}) {
	if cs == nil {
		fmt.Fprintf(out, "Credential store: %s\n", store.CredentialStoreBuiltin)
		return
	}
	fmt.Fprintf(out, "Credential store: %v\n", cs["kind"])
	if cfg, ok := cs["config"].(map[string]interface{}); ok {
		fmt.Fprintf(out, "  Project:     %v\n", cfg["project_id"])
		fmt.Fprintf(out, "  Environment: %v\n", cfg["environment"])
		fmt.Fprintf(out, "  Path:        %v\n", cfg["secret_path"])
	}
	if v, ok := cs["poll_interval_seconds"]; ok {
		fmt.Fprintf(out, "  Poll:        %vs\n", v)
	}
	status, _ := cs["last_sync_status"].(string)
	if status != "" {
		fmt.Fprintf(out, "  Last sync:   %v\n", status)
	}
	if v, ok := cs["last_synced_at"]; ok {
		label := "Synced at"
		if status == store.SyncStatusError {
			label = "Last attempt"
		}
		fmt.Fprintf(out, "  %s:   %v\n", label, v)
	}
	if v, ok := cs["last_sync_error"]; ok {
		fmt.Fprintf(out, "  Error:       %v\n", v)
	}
}

var vaultListCmd = &cobra.Command{
	Use:   "list",
	Short: "List vaults",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/vaults", sess.Address)
		respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
		if err != nil {
			return err
		}

		var resp struct {
			Vaults []struct {
				ID              string `json:"id"`
				Name            string `json:"name"`
				Role            string `json:"role"`
				CreatedAt       string `json:"created_at"`
				CredentialStore *struct {
					Kind string `json:"kind"`
				} `json:"credential_store,omitempty"`
			} `json:"vaults"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if len(resp.Vaults) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "No vaults found.")
			return nil
		}

		t := newTable(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"ID", "NAME", "ROLE", "STORE", "CREATED"})
		for _, ns := range resp.Vaults {
			created := ns.CreatedAt
			if parsed, err := time.Parse(time.RFC3339, ns.CreatedAt); err == nil {
				created = parsed.Format("2006-01-02 15:04:05")
			}
			role := ns.Role
			if role == "" {
				role = "-"
			}
			kind := store.CredentialStoreBuiltin
			if ns.CredentialStore != nil && ns.CredentialStore.Kind != "" {
				kind = ns.CredentialStore.Kind
			}
			t.AppendRow(table.Row{ns.ID, ns.Name, role, kind, created})
		}
		t.Render()
		return nil
	},
}

// --- Vault context commands ---

var vaultUseCmd = &cobra.Command{
	Use:   "use <name>",
	Short: "Set the active vault for subsequent commands",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := session.SaveVaultContext(name); err != nil {
			return fmt.Errorf("saving vault context: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s Now using vault %q\n", successText("✓"), name)
		return nil
	},
}

var vaultCurrentCmd = &cobra.Command{
	Use:   "current",
	Short: "Show the active vault",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		fmt.Fprintln(cmd.OutOrStdout(), vault)
		return nil
	},
}

// --- Vault user subcommands ---

var vaultUserCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage vault users",
}

var vaultUserAddCmd = &cobra.Command{
	Use:   "add <email>",
	Short: "Add an existing instance user to this vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		vaultName := resolveVault(cmd)
		role, _ := cmd.Flags().GetString("role")

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		body, err := json.Marshal(map[string]string{
			"email": email,
			"role":  role,
		})
		if err != nil {
			return err
		}

		reqURL := fmt.Sprintf("%s/v1/vaults/%s/users", sess.Address, vaultName)
		if _, err := doAdminRequestWithBody("POST", reqURL, sess.Token, body); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Added %s to vault %s (role: %s)\n", successText("✓"), email, vaultName, role)
		return nil
	},
}

var vaultUserListCmd = &cobra.Command{
	Use:   "list",
	Short: "List vault users",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultName := resolveVault(cmd)

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/vaults/%s/users", sess.Address, vaultName)
		respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
		if err != nil {
			return err
		}

		var resp struct {
			Users []struct {
				Email  string `json:"email"`
				Role   string `json:"role"`
				Status string `json:"status"`
			} `json:"users"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if len(resp.Users) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "No users found.")
			return nil
		}

		t := newTable(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"EMAIL", "STATUS", "ROLE"})
		for _, m := range resp.Users {
			t.AppendRow(table.Row{m.Email, m.Status, m.Role})
		}
		t.Render()
		return nil
	},
}

var vaultUserRemoveCmd = &cobra.Command{
	Use:   "remove <email>",
	Short: "Remove a user from the vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		vaultName := resolveVault(cmd)

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		reqURL := fmt.Sprintf("%s/v1/vaults/%s/users/%s", sess.Address, vaultName, url.PathEscape(email))
		if err := doAdminRequest("DELETE", reqURL, sess.Token, nil); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Removed %s from vault %s\n", successText("✓"), email, vaultName)
		return nil
	},
}

var vaultUserSetRoleCmd = &cobra.Command{
	Use:   "set-role <email>",
	Short: "Set a user's vault role",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		vaultName := resolveVault(cmd)
		role, _ := cmd.Flags().GetString("role")
		if role == "" {
			return fmt.Errorf("--role is required (admin or member)")
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		body, _ := json.Marshal(map[string]string{"role": role})
		reqURL := fmt.Sprintf("%s/v1/vaults/%s/users/%s/role", sess.Address, vaultName, url.PathEscape(email))
		if err := doAdminRequest("POST", reqURL, sess.Token, body); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s Set role %s for %s in vault %s\n", successText("✓"), role, email, vaultName)
		return nil
	},
}

var vaultRenameCmd = &cobra.Command{
	Use:   "rename <old-name> <new-name>",
	Short: "Rename a vault",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		oldName := args[0]
		newName := args[1]

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		body, err := json.Marshal(map[string]string{"name": newName})
		if err != nil {
			return err
		}

		reqURL := fmt.Sprintf("%s/v1/vaults/%s/rename", sess.Address, url.PathEscape(oldName))
		if err := doAdminRequest("POST", reqURL, sess.Token, body); err != nil {
			return err
		}

		// Update vault context if the renamed vault was the active one.
		if ctx := session.LoadVaultContext(); ctx == oldName {
			_ = session.SaveVaultContext(newName)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Vault renamed from %q to %q.\n", successText("✓"), oldName, newName)
		return nil
	},
}

// confirmByName prints warning then requires the user to type name to proceed.
// Returns false (after printing "Aborted.") if the typed value doesn't match.
func confirmByName(cmd *cobra.Command, warning, name string) (bool, error) {
	fmt.Fprintln(cmd.OutOrStderr(), warning)
	fmt.Fprintf(cmd.OutOrStderr(), "Type %q to confirm: ", name)
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("reading input: %w", err)
	}
	if strings.TrimSpace(answer) != name {
		fmt.Fprintln(cmd.OutOrStdout(), mutedText("Aborted."))
		return false, nil
	}
	return true, nil
}

var vaultDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a vault (vault admin or instance owner)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		yes, _ := cmd.Flags().GetBool("yes")
		if !yes {
			warning := fmt.Sprintf("%s This will permanently delete vault %q and all its credentials, services, and proposals.", warningText("WARNING"), name)
			ok, err := confirmByName(cmd, warning, name)
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		reqURL := fmt.Sprintf("%s/v1/vaults/%s", sess.Address, url.PathEscape(name))
		if err := doAdminRequest("DELETE", reqURL, sess.Token, nil); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Deleted vault %q\n", successText("✓"), name)
		return nil
	},
}

func init() {
	vaultCmd.PersistentFlags().String("vault", "", "target vault (overrides active context)")

	vaultDeleteCmd.Flags().Bool("yes", false, "Skip confirmation prompt")

	vaultCreateCmd.Flags().String("credential-store", "", "credential store kind: builtin (default) or infisical (owner only)")
	vaultCreateCmd.Flags().String("infisical-project-id", "", "Infisical project ID (required when --credential-store=infisical)")
	vaultCreateCmd.Flags().String("infisical-environment", "", "Infisical environment slug, e.g. dev/prod")
	vaultCreateCmd.Flags().String("infisical-path", "/", "Infisical secret path (default /)")
	vaultCreateCmd.Flags().Int("poll-interval-seconds", 60, "Sync cadence floor for the external store (min 10; server wakes every 10s and refreshes vaults past their interval)")

	vaultCmd.AddCommand(vaultCreateCmd)
	vaultCmd.AddCommand(vaultListCmd)
	vaultCmd.AddCommand(vaultDeleteCmd)
	vaultCmd.AddCommand(vaultRenameCmd)
	vaultCmd.AddCommand(vaultUseCmd)
	vaultCmd.AddCommand(vaultCurrentCmd)

	vaultCredentialStoreSetCmd.Flags().String("kind", "", "target credential store kind: builtin or infisical")
	vaultCredentialStoreSetCmd.Flags().String("infisical-project-id", "", "Infisical project ID (required when --kind=infisical)")
	vaultCredentialStoreSetCmd.Flags().String("infisical-environment", "", "Infisical environment slug, e.g. dev/prod")
	vaultCredentialStoreSetCmd.Flags().String("infisical-path", "/", "Infisical secret path (default /)")
	vaultCredentialStoreSetCmd.Flags().Int("poll-interval-seconds", 60, "Sync cadence floor for the external store (min 10)")
	vaultCredentialStoreSetCmd.Flags().Bool("yes", false, "Skip confirmation prompt")

	vaultCredentialStoreCmd.AddCommand(vaultCredentialStoreShowCmd)
	vaultCredentialStoreCmd.AddCommand(vaultCredentialStoreSyncCmd)
	vaultCredentialStoreCmd.AddCommand(vaultCredentialStoreSetCmd)
	vaultCmd.AddCommand(vaultCredentialStoreCmd)

	vaultUserAddCmd.Flags().String("role", "member", "role to grant (admin or member)")
	vaultUserSetRoleCmd.Flags().String("role", "", "role to set (admin or member)")

	vaultUserCmd.AddCommand(vaultUserAddCmd, vaultUserListCmd, vaultUserRemoveCmd, vaultUserSetRoleCmd)
	vaultCmd.AddCommand(vaultUserCmd)

	rootCmd.AddCommand(vaultCmd)
}
