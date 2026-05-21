package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type cliProfileProjection struct {
	Profile       string
	Env           string
	CredentialKey string
}

var builtInCLIProfiles = map[string][]cliProfileProjection{
	"azure-devops": {
		{Profile: "azure-devops", Env: "AZURE_DEVOPS_EXT_PAT", CredentialKey: "AZURE_DEVOPS_PASSWORD"},
	},
}

func resolveCLIProfileProjections(profiles []string) ([]cliProfileProjection, error) {
	var projections []cliProfileProjection
	for _, profile := range profiles {
		profile = strings.TrimSpace(strings.ToLower(profile))
		if profile == "" {
			continue
		}
		items, ok := builtInCLIProfiles[profile]
		if !ok {
			return nil, fmt.Errorf("unknown CLI profile %q", profile)
		}
		projections = append(projections, items...)
	}
	return projections, nil
}

func applyCLIProfileProjections(env []string, projections []cliProfileProjection, fetch func(key string) (string, error)) ([]string, []string, error) {
	if len(projections) == 0 {
		return env, nil, nil
	}
	keys := make(map[string]struct{}, len(projections))
	for _, projection := range projections {
		keys[projection.Env] = struct{}{}
	}
	env = stripEnvKeys(env, keys)

	summaries := make([]string, 0, len(projections))
	for _, projection := range projections {
		value, err := fetch(projection.CredentialKey)
		if err != nil {
			return env, summaries, fmt.Errorf("CLI profile %q credential %q: %w", projection.Profile, projection.CredentialKey, err)
		}
		env = append(env, projection.Env+"="+value)
		summaries = append(summaries, fmt.Sprintf("%s: %s -> %s", projection.Profile, projection.CredentialKey, projection.Env))
	}
	return env, summaries, nil
}

func fetchRevealedCredentialValue(addr, token, vault, key string) (string, error) {
	endpoint, err := url.Parse(strings.TrimRight(addr, "/") + "/v1/credentials")
	if err != nil {
		return "", err
	}
	q := endpoint.Query()
	q.Set("vault", vault)
	q.Set("reveal", "true")
	q.Set("key", key)
	endpoint.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		msg := errResp.Error
		if msg == "" {
			msg = fmt.Sprintf("status %d", resp.StatusCode)
		}
		return "", fmt.Errorf("credential reveal failed: %s", msg)
	}
	var payload struct {
		Credentials []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"credentials"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	for _, credential := range payload.Credentials {
		if credential.Key == key {
			return credential.Value, nil
		}
	}
	return "", fmt.Errorf("credential %q not found in response", key)
}
