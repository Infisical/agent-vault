package brokercore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrOAuthRefreshFailed means the upstream OAuth token endpoint refused the
// refresh-token grant. Callers must not log token request values.
var ErrOAuthRefreshFailed = errors.New("brokercore: oauth refresh failed")

// accessTokenCacheEntry holds a process-local OAuth access token cache entry.
type accessTokenCacheEntry struct {
	AccessToken string
	ExpiresAt   time.Time
}

// OAuthAccessTokenSource exchanges refresh tokens for short-lived access tokens.
type OAuthAccessTokenSource interface {
	Get(ctx context.Context, clientID, clientSecret, refreshToken, tokenEndpoint string, scopes []string) (string, error)
}

// OAuthTokenSource handles the OAuth2 refresh-token grant for services with
// auth.type == "oauth". The refresh token is stored in the vault as an ordinary
// credential; this source exchanges it for a short-lived access token at request
// time, caches the result in memory until just before expiry, and returns only
// the access token to the injection path. The token cache is process-local and
// does not persist across restarts.
type OAuthTokenSource struct {
	mu     sync.Mutex
	cache  map[string]accessTokenCacheEntry
	client *http.Client
	now    func() time.Time
}

// NewOAuthTokenSource constructs an OAuth token source with a 10s HTTP timeout.
func NewOAuthTokenSource() *OAuthTokenSource {
	return &OAuthTokenSource{
		cache:  make(map[string]accessTokenCacheEntry),
		client: &http.Client{Timeout: 10 * time.Second},
		now:    time.Now,
	}
}

// Get returns a fresh access token for the OAuth2 refresh-token grant. It POSTs
// grant_type=refresh_token when no fresh cache entry exists. The cache key is
// sha256(clientID|clientSecret|refreshToken|tokenEndpoint), and the cache TTL is
// expires_in - 60s.
func (s *OAuthTokenSource) Get(ctx context.Context, clientID, clientSecret, refreshToken, tokenEndpoint string, scopes []string) (string, error) {
	if s == nil {
		s = NewOAuthTokenSource()
	}
	if s.client == nil {
		s.client = &http.Client{Timeout: 10 * time.Second}
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.cache == nil {
		s.cache = make(map[string]accessTokenCacheEntry)
	}

	key := oauthCacheKey(clientID, clientSecret, refreshToken, tokenEndpoint)
	now := s.now()

	s.mu.Lock()
	if entry, ok := s.cache[key]; ok && now.Before(entry.ExpiresAt) {
		token := entry.AccessToken
		s.mu.Unlock()
		return token, nil
	}
	s.mu.Unlock()

	token, expiresIn, err := s.refresh(ctx, clientID, clientSecret, refreshToken, tokenEndpoint, scopes)
	if err != nil {
		return "", err
	}
	if expiresIn == 0 {
		expiresIn = 3600
	}
	ttl := time.Duration(expiresIn)*time.Second - 60*time.Second
	if ttl < 0 {
		ttl = 0
	}

	s.mu.Lock()
	s.cache[key] = accessTokenCacheEntry{
		AccessToken: token,
		ExpiresAt:   s.now().Add(ttl),
	}
	s.mu.Unlock()

	return token, nil
}

func (s *OAuthTokenSource) refresh(ctx context.Context, clientID, clientSecret, refreshToken, tokenEndpoint string, scopes []string) (string, int64, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("oauth refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("oauth refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 201))
		truncated := string(body)
		if len(body) > 200 {
			truncated = string(body[:200])
		}
		err := fmt.Errorf("oauth token endpoint returned status %d: %s", resp.StatusCode, truncated)
		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return "", 0, fmt.Errorf("%w: %v", ErrOAuthRefreshFailed, err)
		}
		return "", 0, err
	}

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, fmt.Errorf("oauth token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", 0, fmt.Errorf("oauth token response missing access_token")
	}
	return out.AccessToken, out.ExpiresIn, nil
}

func oauthCacheKey(clientID, clientSecret, refreshToken, tokenEndpoint string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{clientID, clientSecret, refreshToken, tokenEndpoint}, "|")))
	return hex.EncodeToString(sum[:])
}
