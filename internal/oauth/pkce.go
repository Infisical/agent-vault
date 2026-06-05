package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
)

// GenerateCodeVerifier returns a cryptographically random code verifier
// per RFC 7636 §4.1: 32 random bytes, base64url-encoded without padding,
// yielding a 43-character string.
func GenerateCodeVerifier() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("oauth: generating code verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// CodeChallengeS256 computes the S256 code challenge for a given verifier
// per RFC 7636 §4.2: BASE64URL(SHA256(verifier)).
func CodeChallengeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// BuildAuthorizationURL constructs a full authorization endpoint URL with the
// required OAuth 2.0 query parameters.
//
// If disablePKCE is false, code_challenge and code_challenge_method=S256 are
// included. The scopes string, if non-empty, is sent as-is in the "scope" param.
func BuildAuthorizationURL(baseURL, clientID, redirectURI, state, codeChallenge, scopes, scopeSeparator string, disablePKCE bool) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		// Fallback: return the base URL unchanged — callers will get an error
		// when the browser tries to load it.
		return baseURL
	}

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)

	if !disablePKCE {
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", "S256")
	}

	if scopes != "" {
		q.Set("scope", scopes)
	}

	u.RawQuery = q.Encode()
	return u.String()
}
