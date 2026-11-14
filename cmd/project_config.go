package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Infisical/agent-vault/internal/isolation"
	"github.com/spf13/cobra"
)

// ProjectConfigFile is the name of the project-level Agent Vault config.
const ProjectConfigFile = "agent-vault.json"

// ProjectConfigVersion is the current version of the profiles schema. Legacy
// files containing only {"vault":"..."} intentionally omit it.
const ProjectConfigVersion = 1

type projectConfig struct {
	Version  int                       `json:"version,omitempty"`
	Address  string                    `json:"address,omitempty"`
	Vault    string                    `json:"vault,omitempty"`
	Profiles map[string]projectProfile `json:"profiles,omitempty"`
}

type projectProfile struct {
	Vault string            `json:"vault"`
	Env   map[string]string `json:"env,omitempty"`
}

type resolvedRunProfile struct {
	Address string
	Vault   string
	Env     map[string]string
}

const resolvedRunProfileVaultAnnotation = "agent-vault.dev/run-profile-vault"

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// findProjectConfig walks from the working directory toward its repository
// root. The nearest file wins. A .git file counts as a repository root too,
// which is important for Git worktrees.
func findProjectConfig() (string, bool, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", false, fmt.Errorf("resolve working directory: %w", err)
	}

	for {
		path := filepath.Join(dir, ProjectConfigFile)
		if _, err := os.Stat(path); err == nil {
			return path, true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", false, fmt.Errorf("inspect %s: %w", path, err)
		}

		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return "", false, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", false, fmt.Errorf("inspect repository boundary in %s: %w", dir, err)
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false, nil
		}
		dir = parent
	}
}

func loadProjectConfig() (*projectConfig, string, bool, error) {
	path, found, err := findProjectConfig()
	if err != nil || !found {
		return nil, path, found, err
	}

	data, err := os.ReadFile(path) //nolint:gosec // path is discovered from the user's working tree.
	if err != nil {
		return nil, path, true, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg projectConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, path, true, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := validateProjectConfig(&cfg); err != nil {
		return nil, path, true, fmt.Errorf("validate %s: %w", path, err)
	}
	return &cfg, path, true, nil
}

func validateProjectConfig(cfg *projectConfig) error {
	if cfg.Version != 0 && cfg.Version != ProjectConfigVersion {
		return fmt.Errorf("unsupported version %d (supported: %d)", cfg.Version, ProjectConfigVersion)
	}
	if (cfg.Address != "" || len(cfg.Profiles) > 0) && cfg.Version != ProjectConfigVersion {
		return fmt.Errorf("profiles and address require version %d", ProjectConfigVersion)
	}
	if cfg.Address != "" {
		address, err := normalizeProjectAddress(cfg.Address)
		if err != nil {
			return err
		}
		cfg.Address = address
	}

	profileNames := make([]string, 0, len(cfg.Profiles))
	for name := range cfg.Profiles {
		profileNames = append(profileNames, name)
	}
	sort.Strings(profileNames)
	for _, name := range profileNames {
		profile := cfg.Profiles[name]
		if !isSlug(name) {
			return fmt.Errorf("profile name %q must use lowercase letters, numbers, and hyphens", name)
		}
		if profile.Vault == "" {
			return fmt.Errorf("profile %q must set vault", name)
		}
		if !isSlug(profile.Vault) {
			return fmt.Errorf("vault %q in profile %q must use lowercase letters, numbers, and hyphens", profile.Vault, name)
		}
		envKeys := make([]string, 0, len(profile.Env))
		for key := range profile.Env {
			envKeys = append(envKeys, key)
		}
		sort.Strings(envKeys)
		for _, key := range envKeys {
			value := profile.Env[key]
			if err := validateProfileEnvKey(key); err != nil {
				return fmt.Errorf("profile %q env key %q: %w", name, key, err)
			}
			if strings.ContainsRune(value, '\x00') {
				return fmt.Errorf("profile %q env key %q: value must not contain a NUL byte", name, key)
			}
		}
	}
	return nil
}

func normalizeProjectAddress(address string) (string, error) {
	u, err := url.Parse(address)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("address must be an absolute http or https URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("address must not contain user info, a query, or a fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("address must not contain a path")
	}
	u.Path = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func isSlug(value string) bool {
	if value == "" || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func validateProfileEnvKey(key string) error {
	if !envNamePattern.MatchString(key) {
		return errors.New("must be a valid environment variable name")
	}
	upper := strings.ToUpper(key)
	if upper == "PATH" || upper == "HOME" || strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "DYLD_") {
		return errors.New("is reserved and cannot be set by a profile")
	}
	if strings.HasPrefix(upper, "AGENT_VAULT_") {
		return errors.New("is managed by Agent Vault")
	}
	if upper == "ALL_PROXY" {
		return errors.New("is managed by Agent Vault")
	}
	for _, managed := range isolation.ProxyEnvKeys {
		if upper == managed {
			return errors.New("is managed by Agent Vault")
		}
	}
	return nil
}

func resolveRunProfile(cmd *cobra.Command) (*resolvedRunProfile, error) {
	name, _ := cmd.Flags().GetString("profile")
	if name == "" {
		return nil, nil
	}
	if flag := cmd.Flag("vault"); flag != nil && flag.Changed {
		return nil, errors.New("--profile and --vault are mutually exclusive")
	}

	cfg, path, found, err := loadProjectConfig()
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("--profile %q requires %s in the project root", name, ProjectConfigFile)
	}
	profile, ok := cfg.Profiles[name]
	if !ok {
		names := make([]string, 0, len(cfg.Profiles))
		for available := range cfg.Profiles {
			names = append(names, available)
		}
		sort.Strings(names)
		if len(names) == 0 {
			return nil, fmt.Errorf("profile %q not found in %s (no profiles are configured)", name, path)
		}
		return nil, fmt.Errorf("profile %q not found in %s (available: %s)", name, path, strings.Join(names, ", "))
	}

	return &resolvedRunProfile{
		Address: cfg.Address,
		Vault:   profile.Vault,
		Env:     profile.Env,
	}, nil
}

func setResolvedRunProfileVault(cmd *cobra.Command, vault string) {
	if cmd.Annotations == nil {
		cmd.Annotations = make(map[string]string)
	}
	cmd.Annotations[resolvedRunProfileVaultAnnotation] = vault
}

func clearResolvedRunProfileVault(cmd *cobra.Command) {
	delete(cmd.Annotations, resolvedRunProfileVaultAnnotation)
}

func getResolvedRunProfileVault(cmd *cobra.Command) string {
	if cmd.Annotations == nil {
		return ""
	}
	return cmd.Annotations[resolvedRunProfileVaultAnnotation]
}

// applyProfileEnv replaces inherited values with the profile's child-only
// values. Sorting keeps the resulting env deterministic for tests and logs
// produced by process supervisors without ever exposing values ourselves.
func applyProfileEnv(env []string, values map[string]string) []string {
	if len(values) == 0 {
		return env
	}
	keys := make(map[string]struct{}, len(values))
	ordered := make([]string, 0, len(values))
	for key := range values {
		keys[key] = struct{}{}
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	env = stripEnvKeys(env, keys)
	for _, key := range ordered {
		env = append(env, key+"="+values[key])
	}
	return env
}
