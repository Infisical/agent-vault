// Package oauth implements pure OAuth 2.0 protocol mechanics: token exchange,
// refresh, PKCE, and singleflight-based refresh deduplication. No database or
// HTTP handler code — just protocol logic, testable with httptest.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenResponse holds the parsed token endpoint response.
type TokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	Scope        string    `json:"scope"`
	ExpiresIn    int       `json:"expires_in"`
	ExpiresAt    time.Time `json:"-"`
}

// ExchangeConfig configures an authorization-code token exchange.
type ExchangeConfig struct {
	TokenURL        string
	ClientID        string
	ClientSecret    string
	Code            string
	RedirectURI     string
	CodeVerifier    string
	TokenAuthMethod string // "client_secret_post" (default) or "client_secret_basic"
}

// RefreshConfig configures a refresh-token grant.
type RefreshConfig struct {
	TokenURL        string
	ClientID        string
	ClientSecret    string
	RefreshToken    string
	Scopes          string
	ScopeSeparator  string // defaults to " " (space)
	TokenAuthMethod string // "client_secret_post" (default) or "client_secret_basic"
}

// TokenError is returned when the token endpoint responds with a non-2xx status.
type TokenError struct {
	StatusCode int
	Body       string
	Permanent  bool
}

func (e *TokenError) Error() string {
	return fmt.Sprintf("oauth: token endpoint returned %d: %s", e.StatusCode, e.Body)
}

// IsPermanentError returns true for 4xx status codes that are not transient.
// 408 (Request Timeout) and 429 (Too Many Requests) are considered transient.
func IsPermanentError(statusCode int) bool {
	if statusCode < 400 || statusCode >= 500 {
		return false
	}
	return statusCode != 408 && statusCode != 429
}

// Exchange performs an authorization_code token exchange per RFC 6749 §4.1.3.
func Exchange(ctx context.Context, cfg ExchangeConfig) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {cfg.Code},
		"redirect_uri": {cfg.RedirectURI},
	}
	if cfg.CodeVerifier != "" {
		form.Set("code_verifier", cfg.CodeVerifier)
	}

	authMethod := cfg.TokenAuthMethod
	if authMethod == "" {
		authMethod = "client_secret_post"
	}

	applyClientAuth(form, cfg.ClientID, cfg.ClientSecret, authMethod)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oauth: building exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	if authMethod == "client_secret_basic" && cfg.ClientSecret != "" {
		req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	}

	return doTokenRequest(req)
}

// Refresh performs a refresh_token grant per RFC 6749 §6.
func Refresh(ctx context.Context, cfg RefreshConfig) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {cfg.RefreshToken},
	}

	if cfg.Scopes != "" {
		sep := cfg.ScopeSeparator
		if sep == "" {
			sep = " "
		}
		// Scopes is stored with the provider's separator; normalise to space
		// for the wire format (RFC 6749 §3.3).
		form.Set("scope", strings.ReplaceAll(cfg.Scopes, sep, " "))
	}

	authMethod := cfg.TokenAuthMethod
	if authMethod == "" {
		authMethod = "client_secret_post"
	}

	applyClientAuth(form, cfg.ClientID, cfg.ClientSecret, authMethod)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oauth: building refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	if authMethod == "client_secret_basic" && cfg.ClientSecret != "" {
		req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	}

	return doTokenRequest(req)
}

// applyClientAuth adds client credentials to the form body when using
// client_secret_post. For client_secret_basic the caller sets the header.
func applyClientAuth(form url.Values, clientID, clientSecret, method string) {
	switch method {
	case "client_secret_basic":
		// client_id is still sent in the body per some providers' expectations,
		// but credentials go in the Authorization header (set by caller).
		form.Set("client_id", clientID)
	default: // "client_secret_post"
		form.Set("client_id", clientID)
		if clientSecret != "" {
			form.Set("client_secret", clientSecret)
		}
	}
}

var defaultTokenClient = func() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	return &http.Client{Timeout: 30 * time.Second, Transport: t}
}()

// TokenClient is the HTTP client used for token endpoint requests.
// Override this at init time to inject network guards (e.g., SSRF protection).
var TokenClient = defaultTokenClient

func doTokenRequest(req *http.Request) (*TokenResponse, error) {
	resp, err := TokenClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: sending token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("oauth: reading token response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &TokenError{
			StatusCode: resp.StatusCode,
			Body:       string(body),
			Permanent:  IsPermanentError(resp.StatusCode),
		}
	}

	var tok TokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("oauth: parsing token response: %w", err)
	}
	if tok.ExpiresIn > 0 {
		tok.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	return &tok, nil
}
