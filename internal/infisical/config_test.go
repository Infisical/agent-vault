package infisical

import "testing"

// TestParseConfigJSON_TrimsStringFields locks the trim contract so a
// padded value never reaches ListSecrets verbatim.
func TestParseConfigJSON_TrimsStringFields(t *testing.T) {
	raw := `{"project_id":"  abc-123  ","environment":"\tprod\n","secret_path":" / "}`
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
}
