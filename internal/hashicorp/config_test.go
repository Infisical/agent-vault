package hashicorp

import "testing"

// TestParseConfigJSON_TrimsAndDefaults locks the trim + default contract: a
// padded mount/path is cleaned, a leading slash on the path is dropped, and an
// omitted kv_version defaults to 2.
func TestParseConfigJSON_TrimsAndDefaults(t *testing.T) {
	raw := `{"mount":"  secret  ","secret_path":" /agent-vault/demo "}`
	cfg, err := ParseConfigJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Mount != "secret" {
		t.Errorf("mount: want %q, got %q", "secret", cfg.Mount)
	}
	if cfg.SecretPath != "agent-vault/demo" {
		t.Errorf("secret_path: want %q, got %q", "agent-vault/demo", cfg.SecretPath)
	}
	if cfg.KVVersion != DefaultKVVersion {
		t.Errorf("kv_version: want %d, got %d", DefaultKVVersion, cfg.KVVersion)
	}
}

func TestVaultConfig_Validate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     VaultConfig
		wantErr bool
	}{
		{"ok v2", VaultConfig{Mount: "secret", SecretPath: "demo", KVVersion: 2}, false},
		{"ok v1", VaultConfig{Mount: "kv", SecretPath: "demo", KVVersion: 1}, false},
		{"missing mount", VaultConfig{SecretPath: "demo", KVVersion: 2}, true},
		{"missing path", VaultConfig{Mount: "secret", KVVersion: 2}, true},
		{"bad version", VaultConfig{Mount: "secret", SecretPath: "demo", KVVersion: 3}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestStringValue(t *testing.T) {
	cases := []struct {
		in   interface{}
		want string
	}{
		{"sk-abc", "sk-abc"},
		{true, "true"},
		{nil, ""},
		{map[string]interface{}{"a": "b"}, `{"a":"b"}`},
		{float64(5), "5"},                         // no ".0"
		{float64(1e21), "1000000000000000000000"}, // no exponent notation
		{3.5, "3.5"},
	}
	for _, tc := range cases {
		if got := stringValue(tc.in); got != tc.want {
			t.Errorf("stringValue(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
