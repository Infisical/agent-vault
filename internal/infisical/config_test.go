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

// TestParseConfigJSON_RecursiveDefaultsFalse locks backward compatibility:
// config_json rows written before the recursive option existed must keep
// syncing non-recursively.
func TestParseConfigJSON_RecursiveDefaultsFalse(t *testing.T) {
	raw := `{"project_id":"p","environment":"dev","secret_path":"/"}`
	cfg, err := ParseConfigJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Recursive {
		t.Errorf("recursive: want false for legacy config, got true")
	}
}

func TestParseConfigJSON_RecursiveRoundTrip(t *testing.T) {
	cfg, err := ParseConfigJSON(`{"project_id":"p","environment":"dev","secret_path":"/","recursive":true}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Recursive {
		t.Fatalf("recursive: want true, got false")
	}
	out, err := MarshalConfigJSON(cfg)
	if err != nil {
		t.Fatalf("MarshalConfigJSON: %v", err)
	}
	back, err := ParseConfigJSON(out)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if !back.Recursive {
		t.Fatalf("recursive lost in round-trip: %s", out)
	}
}
