package oauth

import (
	"regexp"
	"strings"
	"testing"
)

func TestGenerateCodeVerifier_Format(t *testing.T) {
	v, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier returned error: %v", err)
	}
	if len(v) != 43 {
		t.Errorf("verifier length = %d, want 43", len(v))
	}
	// base64url alphabet: [A-Za-z0-9_-], no padding '='
	re := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	if !re.MatchString(v) {
		t.Errorf("verifier %q contains invalid base64url characters", v)
	}
}

func TestCodeChallengeS256_KnownVector(t *testing.T) {
	// RFC 7636 Appendix B test vector
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	got := CodeChallengeS256(verifier)
	if got != want {
		t.Errorf("CodeChallengeS256(%q) = %q, want %q", verifier, got, want)
	}
}

func TestBuildAuthorizationURL_WithPKCE(t *testing.T) {
	u := BuildAuthorizationURL(
		"https://auth.example.com/authorize",
		"client123",
		"http://localhost/callback",
		"state-abc",
		"challenge-xyz",
		"",
		"",
		false, // PKCE enabled
	)

	if !strings.Contains(u, "code_challenge=challenge-xyz") {
		t.Errorf("URL missing code_challenge: %s", u)
	}
	if !strings.Contains(u, "code_challenge_method=S256") {
		t.Errorf("URL missing code_challenge_method: %s", u)
	}
	if !strings.Contains(u, "response_type=code") {
		t.Errorf("URL missing response_type=code: %s", u)
	}
	if !strings.Contains(u, "client_id=client123") {
		t.Errorf("URL missing client_id: %s", u)
	}
	if !strings.Contains(u, "state=state-abc") {
		t.Errorf("URL missing state: %s", u)
	}
}

func TestBuildAuthorizationURL_WithoutPKCE(t *testing.T) {
	u := BuildAuthorizationURL(
		"https://auth.example.com/authorize",
		"client123",
		"http://localhost/callback",
		"state-abc",
		"challenge-xyz",
		"",
		"",
		true, // PKCE disabled
	)

	if strings.Contains(u, "code_challenge") {
		t.Errorf("URL should NOT contain code_challenge when disablePKCE=true: %s", u)
	}
	if strings.Contains(u, "code_challenge_method") {
		t.Errorf("URL should NOT contain code_challenge_method when disablePKCE=true: %s", u)
	}
}

func TestBuildAuthorizationURL_WithScopes(t *testing.T) {
	u := BuildAuthorizationURL(
		"https://auth.example.com/authorize",
		"client123",
		"http://localhost/callback",
		"state-abc",
		"challenge-xyz",
		"read write",
		" ",
		false,
	)

	// url.Values.Encode encodes spaces as +
	if !strings.Contains(u, "scope=read+write") && !strings.Contains(u, "scope=read%20write") {
		t.Errorf("URL missing or incorrect scope param: %s", u)
	}
}
