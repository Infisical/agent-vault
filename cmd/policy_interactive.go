package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/session"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

type mergeStrategy int

const (
	mergeReplace mergeStrategy = iota
	mergeAppend
)


// runInteractivePolicySet is the entry point for the interactive policy builder.
// It is called from policySetCmd when no -f flag is provided.
func runInteractivePolicySet(cmd *cobra.Command) error {
	if err := requireTTY(); err != nil {
		return err
	}

	sess, err := ensureSession()
	if err != nil {
		return err
	}
	client := sess

	// Step 1: Vault selection
	nsName, err := selectVault(client)
	if err != nil {
		return handleAbort(cmd, err)
	}

	// Step 2: Check existing policy
	existingRules, err := fetchPolicyRules(client, nsName)
	if err != nil {
		return err
	}

	strategy, err := chooseMergeStrategy(cmd, existingRules)
	if err != nil {
		return handleAbort(cmd, err)
	}

	// Step 3: Rule builder loop
	newRules, err := ruleBuilderLoop(client, nsName, cmd)
	if err != nil {
		return handleAbort(cmd, err)
	}

	// Merge
	finalRules := mergeRules(existingRules, newRules, strategy)

	// Validate
	cfg := broker.Config{
		Vault: nsName,
		Rules:     finalRules,
	}
	if err := broker.Validate(&cfg); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}

	// Emit non-blocking warnings
	credentialKeys := listCredentialKeys(client, nsName)
	for _, w := range findUnresolvedCredentials(finalRules, credentialKeys) {
		fmt.Fprintf(cmd.ErrOrStderr(), "%s credential %q is referenced but not found in vault\n", warningText("Warning:"), w)
	}

	// Step 5: Preview
	preview := renderPreview(nsName, finalRules)
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), preview)

	// Step 6: Confirm
	ok, err := confirmApply()
	if err != nil {
		return handleAbort(cmd, err)
	}
	if !ok {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), mutedText("Aborted."))
		return nil
	}

	// Apply via API
	rulesJSON, err := json.Marshal(finalRules)
	if err != nil {
		return fmt.Errorf("marshalling rules: %w", err)
	}

	body, err := json.Marshal(map[string]json.RawMessage{"rules": rulesJSON})
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/vaults/%s/policy", client.Address, nsName)
	if err := doAdminRequest("PUT", url, client.Token, body); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "%s Policy applied to vault %q (%d rule(s)).\n", successText("✓"), nsName, len(finalRules))
	return nil
}

// handleAbort checks for user abort (Ctrl+C) and returns nil with a message.
func handleAbort(cmd *cobra.Command, err error) error {
	if err != nil && errors.Is(err, huh.ErrUserAborted) {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), mutedText("Aborted."))
		return nil
	}
	return err
}

// requireTTY checks that stdin is a terminal.
func requireTTY() error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("interactive mode requires a terminal. Use -f to apply a policy from a file")
	}
	return nil
}

// fetchPolicyRules fetches the current policy rules for a vault via the API.
func fetchPolicyRules(client *session.ClientSession, nsName string) ([]broker.Rule, error) {
	url := fmt.Sprintf("%s/v1/vaults/%s/policy", client.Address, nsName)
	respBody, err := doAdminRequestWithBody("GET", url, client.Token, nil)
	if err != nil {
		return nil, nil // No policy or vault not found — treat as empty.
	}

	var resp struct {
		Rules json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, nil
	}

	var rules []broker.Rule
	if err := json.Unmarshal(resp.Rules, &rules); err != nil {
		return nil, nil
	}
	return rules, nil
}

// selectVault prompts the user to pick a vault.
// If only one exists, it is auto-selected.
func selectVault(client *session.ClientSession) (string, error) {
	url := fmt.Sprintf("%s/v1/admin/vaults", client.Address)
	respBody, err := doAdminRequestWithBody("GET", url, client.Token, nil)
	if err != nil {
		return "", fmt.Errorf("fetching vaults: %w", err)
	}

	var resp struct {
		Vaults []struct {
			Name string `json:"name"`
		} `json:"vaults"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("parsing vaults: %w", err)
	}

	if len(resp.Vaults) == 0 {
		return "", fmt.Errorf("no vaults found")
	}
	if len(resp.Vaults) == 1 {
		return resp.Vaults[0].Name, nil
	}

	opts := make([]huh.Option[string], len(resp.Vaults))
	for i, ns := range resp.Vaults {
		opts[i] = huh.NewOption[string](ns.Name, ns.Name)
	}

	var choice string
	err = huh.NewSelect[string]().
		Title("Which vault?").
		Options(opts...).
		Value(&choice).
		Run()
	if err != nil {
		return "", err
	}

	return choice, nil
}

// chooseMergeStrategy asks the user what to do when existing rules are present.
func chooseMergeStrategy(cmd *cobra.Command, existingRules []broker.Rule) (mergeStrategy, error) {
	if len(existingRules) == 0 {
		return mergeReplace, nil
	}

	var choice string
	err := huh.NewSelect[string]().
		Title(fmt.Sprintf("Vault already has %d rule(s). What would you like to do?", len(existingRules))).
		Options(
			huh.NewOption[string]("Add new rules (keep existing)", "append"),
			huh.NewOption[string]("Replace all rules", "replace"),
		).
		Value(&choice).
		Run()
	if err != nil {
		return mergeReplace, err
	}

	if choice == "append" {
		return mergeAppend, nil
	}
	return mergeReplace, nil
}

// ruleBuilderLoop collects rules until the user declines to add more.
func ruleBuilderLoop(client *session.ClientSession, nsName string, cmd *cobra.Command) ([]broker.Rule, error) {
	var rules []broker.Rule

	for {
		rule, err := buildRule(client, nsName, cmd)
		if err != nil {
			return nil, err
		}
		rules = append(rules, *rule)

		// Warn on duplicate hosts
		for _, dup := range findDuplicateHosts(rules) {
			fmt.Fprintf(cmd.ErrOrStderr(), "%s multiple rules for host %q — the last rule wins\n", warningText("Warning:"), dup)
		}

		if len(rules) > 0 {
			var addMore bool
			err = huh.NewConfirm().
				Title("Add another rule?").
				Affirmative("Yes").
				Negative("No").
				Value(&addMore).
				Run()
			if err != nil {
				return nil, err
			}
			if !addMore {
				break
			}
		}
	}

	return rules, nil
}

// buildRule guides the user through creating a single rule.
func buildRule(client *session.ClientSession, nsName string, cmd *cobra.Command) (*broker.Rule, error) {
	host, err := promptHost(cmd)
	if err != nil {
		return nil, err
	}

	desc, err := promptDescription()
	if err != nil {
		return nil, err
	}

	auth, err := promptAuth(client, nsName)
	if err != nil {
		return nil, err
	}

	return &broker.Rule{
		Host:        host,
		Description: desc,
		Auth:        auth,
	}, nil
}

// promptAuth asks the user to select an auth method and configure it.
func promptAuth(client *session.ClientSession, nsName string) (broker.Auth, error) {
	const (
		optBearer = "bearer"
		optBasic  = "basic"
		optApiKey = "api-key"
		optCustom = "custom"
	)

	var choice string
	err := huh.NewSelect[string]().
		Title("Authentication method:").
		Options(
			huh.NewOption[string]("Bearer token", optBearer),
			huh.NewOption[string]("HTTP Basic Auth (username:password)", optBasic),
			huh.NewOption[string]("API key in header", optApiKey),
			huh.NewOption[string]("Custom headers", optCustom),
		).
		Value(&choice).
		Run()
	if err != nil {
		return broker.Auth{}, err
	}

	switch choice {
	case optBearer:
		var token string
		err := huh.NewInput().
			Title("Token credential key name:").
			Placeholder("e.g. STRIPE_KEY").
			Value(&token).
			Validate(validateCredentialKeyInput).
			Run()
		if err != nil {
			return broker.Auth{}, err
		}
		return broker.Auth{Type: "bearer", Token: strings.TrimSpace(token)}, nil

	case optBasic:
		var username string
		err := huh.NewInput().
			Title("Username credential key name:").
			Placeholder("e.g. ASHBY_API_KEY").
			Value(&username).
			Validate(validateCredentialKeyInput).
			Run()
		if err != nil {
			return broker.Auth{}, err
		}

		var password string
		err = huh.NewInput().
			Title("Password credential key name (leave empty if not needed):").
			Value(&password).
			Run()
		if err != nil {
			return broker.Auth{}, err
		}

		auth := broker.Auth{Type: "basic", Username: strings.TrimSpace(username)}
		password = strings.TrimSpace(password)
		if password != "" {
			if !broker.CredentialKeyPattern.MatchString(password) {
				return broker.Auth{}, fmt.Errorf("password credential key %q must be UPPER_SNAKE_CASE", password)
			}
			auth.Password = password
		}
		return auth, nil

	case optApiKey:
		var key string
		err := huh.NewInput().
			Title("API key credential name:").
			Placeholder("e.g. OPENAI_API_KEY").
			Value(&key).
			Validate(validateCredentialKeyInput).
			Run()
		if err != nil {
			return broker.Auth{}, err
		}

		var header string
		err = huh.NewInput().
			Title("Header name (default: Authorization):").
			Value(&header).
			Run()
		if err != nil {
			return broker.Auth{}, err
		}

		var prefix string
		err = huh.NewInput().
			Title("Prefix before key value (optional, e.g. \"Bearer \"):").
			Value(&prefix).
			Run()
		if err != nil {
			return broker.Auth{}, err
		}

		auth := broker.Auth{Type: "api-key", Key: strings.TrimSpace(key)}
		header = strings.TrimSpace(header)
		if header != "" {
			auth.Header = header
		}
		if prefix != "" {
			auth.Prefix = prefix
		}
		return auth, nil

	default: // custom
		headers, err := headerBuilderLoop(client, nsName)
		if err != nil {
			return broker.Auth{}, err
		}
		return broker.Auth{Type: "custom", Headers: headers}, nil
	}
}

// validateCredentialKeyInput validates that a credential key name is non-empty and UPPER_SNAKE_CASE.
func validateCredentialKeyInput(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("credential key name cannot be empty")
	}
	if !broker.CredentialKeyPattern.MatchString(s) {
		return fmt.Errorf("must be UPPER_SNAKE_CASE (e.g. STRIPE_KEY)")
	}
	return nil
}

// promptHost asks for a host pattern and warns about suspicious patterns.
func promptHost(cmd *cobra.Command) (string, error) {
	var host string
	err := huh.NewInput().
		Title("Host pattern (e.g. api.stripe.com, *.github.com):").
		Value(&host).
		Validate(func(s string) error {
			if strings.TrimSpace(s) == "" {
				return fmt.Errorf("host pattern cannot be empty")
			}
			return nil
		}).
		Run()
	if err != nil {
		return "", err
	}

	host = strings.TrimSpace(host)

	// Non-blocking warnings
	for _, w := range hostWarnings(host) {
		fmt.Fprintf(cmd.ErrOrStderr(), "%s %s\n", warningText("Warning:"), w)
	}

	return host, nil
}

// promptDescription asks for an optional description.
func promptDescription() (*string, error) {
	var desc string
	err := huh.NewInput().
		Title("Description (optional):").
		Value(&desc).
		Run()
	if err != nil {
		return nil, err
	}

	desc = strings.TrimSpace(desc)
	if desc == "" {
		return nil, nil
	}
	return &desc, nil
}

// headerBuilderLoop collects at least one header per rule.
func headerBuilderLoop(client *session.ClientSession, nsName string) (map[string]string, error) {
	headers := make(map[string]string)

	for {
		name, err := promptHeaderName()
		if err != nil {
			return nil, err
		}

		value, err := promptHeaderValue(client, nsName, name)
		if err != nil {
			return nil, err
		}

		headers[name] = value

		var addMore bool
		err = huh.NewConfirm().
			Title("Add another header?").
			Affirmative("Yes").
			Negative("No").
			Value(&addMore).
			Run()
		if err != nil {
			return nil, err
		}
		if !addMore {
			break
		}
	}

	return headers, nil
}

// promptHeaderName asks for the header name with common options.
func promptHeaderName() (string, error) {
	const otherOption = "__other__"

	var choice string
	err := huh.NewSelect[string]().
		Title("Header name:").
		Options(
			huh.NewOption[string]("Authorization", "Authorization"),
			huh.NewOption[string]("X-API-Key", "X-API-Key"),
			huh.NewOption[string]("Other (type custom)", otherOption),
		).
		Value(&choice).
		Run()
	if err != nil {
		return "", err
	}

	if choice != otherOption {
		return choice, nil
	}

	var custom string
	err = huh.NewInput().
		Title("Custom header name:").
		Value(&custom).
		Validate(func(s string) error {
			s = strings.TrimSpace(s)
			if s == "" {
				return fmt.Errorf("header name cannot be empty")
			}
			if strings.ContainsAny(s, " \t") {
				return fmt.Errorf("header name cannot contain spaces")
			}
			return nil
		}).
		Run()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(custom), nil
}

// promptHeaderValue builds the header value, optionally using available credentials.
func promptHeaderValue(client *session.ClientSession, nsName string, headerName string) (string, error) {
	credentialKeys := listCredentialKeys(client, nsName)

	// If credentials exist, offer to pick from them
	if len(credentialKeys) > 0 {
		var usePicker bool
		err := huh.NewConfirm().
			Title(fmt.Sprintf("Pick from existing credentials? (%d available)", len(credentialKeys))).
			Affirmative("Yes").
			Negative("No").
			Value(&usePicker).
			Run()
		if err != nil {
			return "", err
		}

		if usePicker {
			return pickCredentialValue(credentialKeys, headerName)
		}
	}

	// Manual entry
	var value string
	err := huh.NewInput().
		Title("Header value (use {{ SECRET_NAME }} for credential references):").
		Value(&value).
		Validate(func(s string) error {
			if strings.TrimSpace(s) == "" {
				return fmt.Errorf("header value cannot be empty")
			}
			return nil
		}).
		Run()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(value), nil
}

// pickCredentialValue lets the user select a credential and optionally format it.
func pickCredentialValue(credentialKeys []string, headerName string) (string, error) {
	opts := make([]huh.Option[string], len(credentialKeys))
	for i, key := range credentialKeys {
		opts[i] = huh.NewOption[string](key, key)
	}

	var chosen string
	err := huh.NewSelect[string]().
		Title("Select credential:").
		Options(opts...).
		Value(&chosen).
		Run()
	if err != nil {
		return "", err
	}

	// For Authorization headers, offer format patterns
	if headerName == "Authorization" {
		return pickAuthFormat(chosen)
	}

	// For other headers, default to {{ CREDENTIAL }}
	return fmt.Sprintf("{{ %s }}", chosen), nil
}

// pickAuthFormat offers common Authorization header formats.
func pickAuthFormat(credentialKey string) (string, error) {
	const customOption = "__custom__"

	bearer := fmt.Sprintf("Bearer {{ %s }}", credentialKey)
	token := fmt.Sprintf("token {{ %s }}", credentialKey)
	basic := fmt.Sprintf("Basic {{ %s }}", credentialKey)

	var choice string
	err := huh.NewSelect[string]().
		Title("Authorization format:").
		Options(
			huh.NewOption[string](bearer, bearer),
			huh.NewOption[string](token, token),
			huh.NewOption[string](basic, basic),
			huh.NewOption[string]("Custom format", customOption),
		).
		Value(&choice).
		Run()
	if err != nil {
		return "", err
	}

	if choice != customOption {
		return choice, nil
	}

	var custom string
	err = huh.NewInput().
		Title("Header value (use {{ SECRET_NAME }} for credential references):").
		Placeholder(fmt.Sprintf("{{ %s }}", credentialKey)).
		Value(&custom).
		Validate(func(s string) error {
			if strings.TrimSpace(s) == "" {
				return fmt.Errorf("header value cannot be empty")
			}
			return nil
		}).
		Run()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(custom), nil
}

// renderPreview returns the full policy as a formatted YAML preview.
func renderPreview(vault string, rules []broker.Rule) string {
	cfg := broker.Config{
		Vault: vault,
		Rules:     rules,
	}

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Sprintf("(error rendering preview: %v)", err)
	}

	var sb strings.Builder
	sb.WriteString(sectionHeader("--- Policy Preview ---") + "\n")
	sb.Write(out)
	sb.WriteString(mutedText("----------------------"))
	return sb.String()
}

// confirmApply asks the user to confirm applying the policy.
func confirmApply() (bool, error) {
	var ok bool
	err := huh.NewConfirm().
		Title("Apply this policy?").
		Affirmative("Yes").
		Negative("No").
		Value(&ok).
		Run()
	return ok, err
}

// listCredentialKeys returns the credential key names for a vault via the API.
func listCredentialKeys(client *session.ClientSession, nsName string) []string {
	url := fmt.Sprintf("%s/v1/credentials?vault=%s", client.Address, nsName)
	respBody, err := doAdminRequestWithBody("GET", url, client.Token, nil)
	if err != nil {
		return nil
	}
	var resp struct {
		Keys []string `json:"keys"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil
	}
	return resp.Keys
}

// --- Pure helper functions (testable) ---

// hostWarnings returns warning messages for suspicious host patterns.
func hostWarnings(host string) []string {
	var warnings []string
	if !strings.Contains(host, ".") && !strings.HasPrefix(host, "*") {
		warnings = append(warnings, fmt.Sprintf("host %q has no dots — did you mean a full hostname?", host))
	}
	if strings.ContainsAny(host, " \t") {
		warnings = append(warnings, fmt.Sprintf("host %q contains whitespace", host))
	}
	return warnings
}

// findDuplicateHosts returns host patterns that appear more than once in the rule list.
func findDuplicateHosts(rules []broker.Rule) []string {
	seen := make(map[string]int)
	for _, r := range rules {
		seen[r.Host]++
	}
	var dups []string
	for host, count := range seen {
		if count > 1 {
			dups = append(dups, host)
		}
	}
	return dups
}

// findUnresolvedCredentials returns credential names referenced in rules that are not in knownKeys.
func findUnresolvedCredentials(rules []broker.Rule, knownKeys []string) []string {
	known := make(map[string]bool, len(knownKeys))
	for _, k := range knownKeys {
		known[k] = true
	}

	seen := make(map[string]bool)
	var unresolved []string
	for _, r := range rules {
		for _, key := range r.Auth.CredentialKeys() {
			if !known[key] && !seen[key] {
				unresolved = append(unresolved, key)
				seen[key] = true
			}
		}
	}
	return unresolved
}

// mergeRules combines existing and new rules based on the chosen strategy.
func mergeRules(existing, newRules []broker.Rule, strategy mergeStrategy) []broker.Rule {
	if strategy == mergeAppend {
		return append(existing, newRules...)
	}
	return newRules
}
