package infisical

import "testing"

// TestParseConfigJSON_TrimsStringFields locks the contract that surrounding
// whitespace on project_id / environment / secret_path is stripped at parse
// time. The Web UI .trim()s before POSTing, but the CLI and direct-HTTP
// clients pass cobra flag values through verbatim — without this trim, a
// copy-pasted " abc-123 " passes Validate (which uses TrimSpace as a check
// but discards the result), then reaches ListSecrets with the padding,
// 404s upstream, and the scrubbed error message gives the operator no
// hint about whitespace as the cause.
func TestParseConfigJSON_TrimsStringFields(t *testing.T) {
	raw := `{"project_id":"  abc-123  ","environment":"\tprod\n","secret_path":" / ","recursive":true}`
	cfg, err := ParseConfigJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ProjectID != "abc-123" {
		t.Errorf("project_id: want %q, got %q", "abc-123", cfg.ProjectID)
	}
	if cfg.Environment != "prod" {
		t.Errorf("environment: want %q, got %q", "prod", cfg.Environment)
	}
	if cfg.SecretPath != "/" {
		t.Errorf("secret_path: want %q, got %q", "/", cfg.SecretPath)
	}
	if !cfg.Recursive {
		t.Errorf("recursive: want true, got false")
	}
}
