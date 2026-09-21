package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const defaultRunProfilesFile = "profiles.yaml"

type runProfilesConfig struct {
	Profiles map[string]runProfile `yaml:"profiles"`
}

type runProfile struct {
	Vault            string   `yaml:"vault"`
	TTL              int      `yaml:"ttl"`
	Isolation        string   `yaml:"isolation"`
	Image            string   `yaml:"image"`
	Mounts           []string `yaml:"mounts"`
	Keep             bool     `yaml:"keep"`
	HomeVolumeShared bool     `yaml:"home_volume_shared"`
	ShareAgentDir    bool     `yaml:"share_agent_dir"`
}

func applyRunProfile(cmd *cobra.Command) error {
	profileName, _ := cmd.Flags().GetString("profile")
	profilesFile, _ := cmd.Flags().GetString("profiles-file")
	if profileName == "" {
		if cmd.Flags().Changed("profiles-file") {
			return errors.New("--profiles-file requires --profile")
		}
		return nil
	}
	if strings.TrimSpace(profileName) != profileName {
		return errors.New("--profile may not have leading or trailing whitespace")
	}

	path, err := resolveRunProfilesPath(profilesFile)
	if err != nil {
		return err
	}
	profiles, err := loadRunProfiles(path)
	if err != nil {
		return err
	}
	profile, ok := profiles[profileName]
	if !ok {
		return fmt.Errorf("run profile %q not found in %s", profileName, path)
	}
	if err := validateRunProfile(profileName, profile); err != nil {
		return err
	}
	return applyRunProfileFlags(cmd, profile)
}

func resolveRunProfilesPath(explicit string) (string, error) {
	if explicit != "" {
		return filepath.Clean(explicit), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory for run profiles: %w", err)
	}
	return filepath.Join(home, ".agent-vault", defaultRunProfilesFile), nil
}

func loadRunProfiles(path string) (map[string]runProfile, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open run profiles %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var config runProfilesConfig
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("parse run profiles %s: %w", path, err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("parse run profiles %s: multiple YAML documents are not supported", path)
		}
		return nil, fmt.Errorf("parse run profiles %s: %w", path, err)
	}
	if len(config.Profiles) == 0 {
		return nil, fmt.Errorf("run profiles %s contains no profiles", path)
	}
	return config.Profiles, nil
}

func validateRunProfile(name string, profile runProfile) error {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(name) != name {
		return fmt.Errorf("run profile name %q is invalid", name)
	}
	if profile.TTL != 0 && (profile.TTL < 300 || profile.TTL > 604800) {
		return fmt.Errorf("run profile %q: ttl must be between 300 and 604800 seconds", name)
	}
	if profile.Isolation != "" && profile.Isolation != string(IsolationHost) && profile.Isolation != string(IsolationContainer) {
		return fmt.Errorf("run profile %q: isolation must be host or container", name)
	}
	return nil
}

func applyRunProfileFlags(cmd *cobra.Command, profile runProfile) error {
	values := []struct {
		name  string
		value string
	}{
		{"vault", profile.Vault},
		{"isolation", profile.Isolation},
		{"image", profile.Image},
	}
	if profile.TTL > 0 {
		values = append(values, struct {
			name  string
			value string
		}{"ttl", fmt.Sprintf("%d", profile.TTL)})
	}
	for _, value := range values {
		if value.value == "" || cmd.Flags().Changed(value.name) {
			continue
		}
		if err := cmd.Flags().Set(value.name, value.value); err != nil {
			return fmt.Errorf("apply run profile flag --%s: %w", value.name, err)
		}
	}
	if !cmd.Flags().Changed("mount") {
		for _, mount := range profile.Mounts {
			if err := cmd.Flags().Set("mount", mount); err != nil {
				return fmt.Errorf("apply run profile flag --mount: %w", err)
			}
		}
	}
	bools := []struct {
		name  string
		value bool
	}{
		{"keep", profile.Keep},
		{"home-volume-shared", profile.HomeVolumeShared},
		{"share-agent-dir", profile.ShareAgentDir},
	}
	for _, value := range bools {
		if !value.value || cmd.Flags().Changed(value.name) {
			continue
		}
		if err := cmd.Flags().Set(value.name, "true"); err != nil {
			return fmt.Errorf("apply run profile flag --%s: %w", value.name, err)
		}
	}
	return nil
}
