package oauth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JWKS fetches and caches a JSON Web Key Set from a remote endpoint.
type JWKS struct {
	url     string
	client  *http.Client
	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
	ttl     time.Duration
}

// NewJWKS creates a JWKS fetcher for the given URL.
func NewJWKS(url string, client *http.Client, ttl time.Duration) *JWKS {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &JWKS{
		url:    url,
		client: client,
		keys:   make(map[string]*rsa.PublicKey),
		ttl:    ttl,
	}
}

// GetKey returns the RSA public key for the given key ID. It fetches or
// refreshes the JWKS if the cache is empty or stale.
func (j *JWKS) GetKey(kid string) (*rsa.PublicKey, error) {
	j.mu.RLock()
	if key, ok := j.keys[kid]; ok && time.Since(j.fetched) < j.ttl {
		j.mu.RUnlock()
		return key, nil
	}
	j.mu.RUnlock()

	if err := j.refresh(); err != nil {
		return nil, err
	}

	j.mu.RLock()
	defer j.mu.RUnlock()
	key, ok := j.keys[kid]
	if !ok {
		return nil, fmt.Errorf("key %q not found in JWKS", kid)
	}
	return key, nil
}

func (j *JWKS) refresh() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	// Double-check after acquiring write lock.
	if len(j.keys) > 0 && time.Since(j.fetched) < j.ttl {
		return nil
	}

	resp, err := j.client.Get(j.url)
	if err != nil {
		return fmt.Errorf("fetching JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}

	// Limit response body to 128 KB to prevent memory exhaustion from a
	// compromised or malicious JWKS endpoint.
	limited := http.MaxBytesReader(nil, resp.Body, 128*1024)
	defer func() { _ = limited.Close() }()

	var jwks struct {
		Keys []jwkEntry `json:"keys"`
	}
	if err := json.NewDecoder(limited).Decode(&jwks); err != nil {
		return fmt.Errorf("decoding JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, entry := range jwks.Keys {
		if entry.Kty != "RSA" || entry.Use != "sig" {
			continue
		}
		pub, err := entry.rsaPublicKey()
		if err != nil {
			continue
		}
		keys[entry.Kid] = pub
	}

	j.keys = keys
	j.fetched = time.Now()
	return nil
}

type jwkEntry struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (e *jwkEntry) rsaPublicKey() (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(e.N)
	if err != nil {
		return nil, fmt.Errorf("decoding modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(e.E)
	if err != nil {
		return nil, fmt.Errorf("decoding exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	exp := new(big.Int).SetBytes(eBytes)
	if !exp.IsInt64() {
		return nil, errors.New("exponent too large")
	}

	return &rsa.PublicKey{N: n, E: int(exp.Int64())}, nil
}

// jwtHeader is the decoded header portion of a JWT.
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// ParseJWTHeader extracts the header from a JWT without verifying it.
func ParseJWTHeader(token string) (*jwtHeader, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT header: %w", err)
	}

	var hdr jwtHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return nil, fmt.Errorf("parsing JWT header: %w", err)
	}
	return &hdr, nil
}

// ParseJWTPayload extracts the payload from a JWT without verifying it.
// Callers must verify the signature separately before trusting the claims.
func ParseJWTPayload(token string) (json.RawMessage, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT payload: %w", err)
	}
	return json.RawMessage(payload), nil
}

// VerifyRS256 verifies the RS256 signature of a JWT using the given public key.
func VerifyRS256(token string, key *rsa.PublicKey) error {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return errors.New("invalid JWT format")
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decoding JWT signature: %w", err)
	}

	signedContent := []byte(parts[0] + "." + parts[1])
	h := sha256.Sum256(signedContent)
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, h[:], sigBytes)
}
