package broker

import (
	"strings"
	"testing"
)

func methodsCfg(methods []string) *Config {
	return &Config{
		Vault: "v1",
		Services: []Service{{
			Name:    "api",
			Host:    "api.example.com",
			Methods: methods,
			Auth:    Auth{Type: "bearer", Token: "TOKEN"},
		}},
	}
}

func TestValidate_MethodsNormalized(t *testing.T) {
	cfg := methodsCfg([]string{"get", "Post"})
	if err := Validate(cfg); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	got := cfg.Services[0].Methods
	if len(got) != 2 || got[0] != "GET" || got[1] != "POST" {
		t.Fatalf("methods not normalized in place: %v", got)
	}
}

func TestValidate_MethodsRejectsUnsupported(t *testing.T) {
	err := Validate(methodsCfg([]string{"GET", "FETCH"}))
	if err == nil || !strings.Contains(err.Error(), "unsupported method") {
		t.Fatalf("want unsupported-method error, got %v", err)
	}
}

func TestValidate_MethodsRejectsDuplicates(t *testing.T) {
	err := Validate(methodsCfg([]string{"GET", "get"}))
	if err == nil || !strings.Contains(err.Error(), "duplicate method") {
		t.Fatalf("want duplicate-method error, got %v", err)
	}
}

func TestValidate_MethodsRejectsExplicitEmptyList(t *testing.T) {
	err := Validate(methodsCfg([]string{}))
	if err == nil || !strings.Contains(err.Error(), "empty list") {
		t.Fatalf("want empty-list error, got %v", err)
	}
}

func TestValidate_MethodsNilAllowed(t *testing.T) {
	if err := Validate(methodsCfg(nil)); err != nil {
		t.Fatalf("nil methods must validate: %v", err)
	}
}

func TestAllowsMethod(t *testing.T) {
	cases := []struct {
		name    string
		methods []string
		method  string
		want    bool
	}{
		{"nil list allows all", nil, "DELETE", true},
		{"listed method allowed", []string{"GET", "HEAD"}, "GET", true},
		{"unlisted method denied", []string{"GET", "HEAD"}, "POST", false},
		{"non-canonical case fails closed", []string{"GET"}, "get", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := Service{Methods: tc.methods}
			if got := s.AllowsMethod(tc.method); got != tc.want {
				t.Fatalf("AllowsMethod(%q) with %v = %v, want %v", tc.method, tc.methods, got, tc.want)
			}
		})
	}
}
