package oauth

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	googleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"
	jwksCacheTTL  = 1 * time.Hour
	maxIatAge     = 5 * time.Minute // reject ID tokens issued more than 5 minutes ago
)

// GoogleConfig holds the configuration for the Google OAuth provider.
type GoogleConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string // e.g. "http://localhost:14321/v1/auth/oauth/google/callback"
}

// GoogleProvider implements the Provider interface for Google OIDC.
type GoogleProvider struct {
	config  *oauth2.Config
	jwks    *JWKS
	enabled bool
}

// NewGoogleProvider creates a Google OAuth provider. Returns a disabled
// provider if clientID or clientSecret is empty.
func NewGoogleProvider(cfg GoogleConfig) *GoogleProvider {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return &GoogleProvider{enabled: false}
	}

	return &GoogleProvider{
		config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint:     google.Endpoint,
		},
		jwks:    NewJWKS(googleJWKSURL, nil, jwksCacheTTL),
		enabled: true,
	}
}

func (g *GoogleProvider) Name() string        { return "google" }
func (g *GoogleProvider) DisplayName() string  { return "Google" }
func (g *GoogleProvider) Enabled() bool        { return g.enabled }
func (g *GoogleProvider) CallbackPath() string { return "/v1/auth/oauth/google/callback" }

// AuthCodeURL builds the Google authorization URL with PKCE (S256) and an OIDC nonce.
func (g *GoogleProvider) AuthCodeURL(state, codeVerifier, nonce string) string {
	challenge := pkceS256(codeVerifier)
	return g.config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("nonce", nonce),
	)
}

// Exchange trades an authorization code for validated user information.
func (g *GoogleProvider) Exchange(ctx context.Context, code, codeVerifier, nonce string) (*UserInfo, error) {
	tok, err := g.config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return nil, fmt.Errorf("exchanging code: %w", err)
	}

	// Google returns the ID token in the token response.
	idTokenRaw, ok := tok.Extra("id_token").(string)
	if !ok || idTokenRaw == "" {
		return nil, errors.New("no id_token in token response")
	}

	claims, err := g.validateIDToken(idTokenRaw, nonce)
	if err != nil {
		return nil, fmt.Errorf("validating id_token: %w", err)
	}

	return &UserInfo{
		ProviderUserID: claims.Sub,
		Email:          claims.Email,
		Name:           claims.Name,
		AvatarURL:      claims.Picture,
		EmailVerified:  claims.EmailVerified,
	}, nil
}

// googleIDTokenClaims are the claims we validate from a Google ID token.
type googleIDTokenClaims struct {
	Iss           string `json:"iss"`
	Azp           string `json:"azp"`
	Aud           string `json:"aud"`
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Exp           int64  `json:"exp"`
	Iat           int64  `json:"iat"`
	Nonce         string `json:"nonce"`
}

func (g *GoogleProvider) validateIDToken(idToken, expectedNonce string) (*googleIDTokenClaims, error) {
	// 1. Parse header to get key ID.
	hdr, err := ParseJWTHeader(idToken)
	if err != nil {
		return nil, err
	}
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported algorithm: %s", hdr.Alg)
	}

	// 2. Get the signing key from Google's JWKS.
	key, err := g.jwks.GetKey(hdr.Kid)
	if err != nil {
		return nil, err
	}

	// 3. Verify RS256 signature.
	if err := VerifyRS256(idToken, key); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// 4. Parse and validate claims.
	payload, err := ParseJWTPayload(idToken)
	if err != nil {
		return nil, err
	}

	var claims googleIDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}

	// Validate issuer.
	if claims.Iss != "accounts.google.com" && claims.Iss != "https://accounts.google.com" {
		return nil, fmt.Errorf("invalid issuer: %s", claims.Iss)
	}

	// Validate audience matches our client ID.
	if claims.Aud != g.config.ClientID {
		return nil, fmt.Errorf("invalid audience: %s", claims.Aud)
	}

	// Validate expiry.
	now := time.Now().Unix()
	if now > claims.Exp {
		return nil, errors.New("id_token has expired")
	}

	// Validate issued-at to tighten the replay window.
	if claims.Iat == 0 {
		return nil, errors.New("id_token iat is missing")
	}
	iatDelta := now - claims.Iat
	if iatDelta < -60 || iatDelta > int64(maxIatAge.Seconds()) {
		return nil, errors.New("id_token iat is out of acceptable range")
	}

	// Validate nonce to prevent token injection attacks.
	if expectedNonce != "" {
		if claims.Nonce != expectedNonce {
			return nil, errors.New("id_token nonce mismatch")
		}
	}

	// Require sub.
	if claims.Sub == "" {
		return nil, errors.New("missing sub claim")
	}

	return &claims, nil
}

// pkceS256 computes the S256 PKCE code_challenge from a code_verifier.
func pkceS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// GenerateCodeVerifier generates a PKCE code_verifier (43 chars of
// URL-safe base64 from 32 random bytes).
func GenerateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(crand.Reader, b); err != nil {
		return "", fmt.Errorf("generating code verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
