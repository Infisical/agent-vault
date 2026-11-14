package broker

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

// FilterOp records how a service write treated the filter block.
type FilterOp string

const (
	FilterOpOmit  FilterOp = ""
	FilterOpSet   FilterOp = "set"
	FilterOpClear FilterOp = "clear"
)

// Filter is the sidecar hop for one service. url is the address Agent Vault
// dials. The sidecar does not reuse it as a base for its own outbound calls.
type Filter struct {
	URL                      string `json:"url" yaml:"url"`
	PolicyVault              string `json:"policy_vault,omitempty" yaml:"policy_vault,omitempty"`
	AllowInsecurePrivateHTTP bool   `json:"allow_insecure_private_http,omitempty" yaml:"allow_insecure_private_http,omitempty"`
	CA                       string `json:"ca,omitempty" yaml:"ca,omitempty"`
}

// Validate checks a filter block. A nil filter is valid (no hop).
func (f *Filter) Validate() error {
	if f == nil {
		return nil
	}
	if strings.TrimSpace(f.URL) == "" {
		return fmt.Errorf("filter: url is required")
	}
	u, err := url.Parse(f.URL)
	if err != nil {
		return fmt.Errorf("filter: url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("filter: url scheme must be http or https")
	}
	if u.Host == "" {
		return fmt.Errorf("filter: url host is required")
	}
	if u.User != nil {
		return fmt.Errorf("filter: url must not include userinfo")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("filter: url must not include a query or fragment")
	}
	if f.CA != "" {
		if u.Scheme != "https" {
			return fmt.Errorf("filter: ca is only valid on https urls")
		}
		if err := validateFilterCAPEM(f.CA); err != nil {
			return err
		}
	}
	if u.Scheme == "http" && !httpHostIsLiteralLoopback(u.Hostname()) && !f.AllowInsecurePrivateHTTP {
		return fmt.Errorf("filter: cleartext http to %q requires allow_insecure_private_http or a literal loopback address", u.Hostname())
	}
	return nil
}

func validateFilterCAPEM(raw string) error {
	rest := []byte(raw)
	var blocks int
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("filter: ca contains a PEM block that is not a certificate")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("filter: ca: %w", err)
		}
		blocks++
	}
	if blocks == 0 {
		return fmt.Errorf("filter: ca must be a PEM certificate")
	}
	return nil
}

func httpHostIsLiteralLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// UnmarshalJSON distinguishes an omitted filter, an explicit null or empty
// object (clear), and a filter object (set).
func (s *Service) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	type serviceBody struct {
		Name          string         `json:"name"`
		Host          string         `json:"host"`
		Path          string         `json:"path"`
		Enabled       *bool          `json:"enabled"`
		Auth          Auth           `json:"auth"`
		Substitutions []Substitution `json:"substitutions"`
	}
	var body serviceBody
	if err := json.Unmarshal(data, &body); err != nil {
		return err
	}
	s.Name = body.Name
	s.Host = body.Host
	s.Path = body.Path
	s.Enabled = body.Enabled
	s.Auth = body.Auth
	s.Substitutions = body.Substitutions
	s.Filter = nil
	s.FilterOp = FilterOpOmit
	filt, ok := raw["filter"]
	if !ok {
		return nil
	}
	trimmed := strings.TrimSpace(string(filt))
	if trimmed == "null" || emptyJSONObject(trimmed) {
		s.FilterOp = FilterOpClear
		return nil
	}
	var f Filter
	if err := json.Unmarshal(filt, &f); err != nil {
		return fmt.Errorf("filter: %w", err)
	}
	s.Filter = &f
	s.FilterOp = FilterOpSet
	return nil
}

func emptyJSONObject(s string) bool {
	if s == "{}" {
		return true
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return false
	}
	return len(m) == 0
}

// UnmarshalYAML is the YAML counterpart of UnmarshalJSON. An absent filter
// preserves on upsert. An explicit null or empty mapping clears.
func (s *Service) UnmarshalYAML(node *yaml.Node) error {
	type serviceBody struct {
		Name          string         `yaml:"name"`
		Host          string         `yaml:"host"`
		Path          string         `yaml:"path"`
		Port          *int           `yaml:"port"`
		Enabled       *bool          `yaml:"enabled"`
		Auth          Auth           `yaml:"auth"`
		Substitutions []Substitution `yaml:"substitutions"`
		Filter        *Filter        `yaml:"filter"`
	}
	var body serviceBody
	if err := node.Decode(&body); err != nil {
		return err
	}
	s.Name = body.Name
	s.Host = body.Host
	s.Path = body.Path
	s.Port = body.Port
	s.Enabled = body.Enabled
	s.Auth = body.Auth
	s.Substitutions = body.Substitutions
	s.Filter = nil
	s.FilterOp = FilterOpOmit
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value != "filter" {
			continue
		}
		val := node.Content[i+1]
		if val.Tag == "!!null" || (val.Kind == yaml.MappingNode && len(val.Content) == 0) {
			s.FilterOp = FilterOpClear
			return nil
		}
		s.Filter = body.Filter
		s.FilterOp = FilterOpSet
		return nil
	}
	return nil
}

// CredentialHeaderNames returns the header names a client could use to
// place a secret in the slot this service's credential will occupy.
// Passthrough has no such slot.
func CredentialHeaderNames(auth Auth) []string {
	switch auth.Type {
	case "bearer", "basic":
		return []string{"Authorization"}
	case "api-key":
		if auth.Header == "" {
			return []string{"Authorization"}
		}
		return []string{auth.Header}
	case "custom":
		names := make([]string, 0, len(auth.Headers))
		for name := range auth.Headers {
			names = append(names, name)
		}
		return names
	default:
		return nil
	}
}

// ShadowsFiltered reports whether an unfiltered service can win or tie
// filtered for some request. Host, port, and path are the matcher language
// MatchService uses. Declaration order is not part of the comparison.
func ShadowsFiltered(unfiltered, filtered Service) bool {
	if unfiltered.Filter != nil || filtered.Filter == nil {
		return false
	}
	host, ok := overlapHost(unfiltered.Host, filtered.Host)
	if !ok {
		return false
	}
	if !portsOverlap(unfiltered.Port, filtered.Port) {
		return false
	}
	if !globsOverlap(unfiltered.Path, filtered.Path) {
		return false
	}
	pTier, pOK := matchHostPattern(unfiltered.Host, host)
	fTier, fOK := matchHostPattern(filtered.Host, host)
	if !pOK || !fOK {
		return false
	}
	proposed := MatchScore{
		HostTier:       pTier,
		PortSpecific:   unfiltered.Port != nil,
		PathLiteralLen: pathLiteralLen(unfiltered.Path),
	}
	incumbent := MatchScore{
		HostTier:       fTier,
		PortSpecific:   filtered.Port != nil,
		PathLiteralLen: pathLiteralLen(filtered.Path),
	}
	return !incumbent.Better(proposed)
}

func pathLiteralLen(pattern string) int {
	if pattern == "" {
		return 0
	}
	return len(strings.Split(pattern, "*")[0])
}

func portsOverlap(a, b *int) bool {
	if a == nil || b == nil {
		return true
	}
	return *a == *b
}

func overlapHost(a, b string) (string, bool) {
	aExact := !strings.HasPrefix(a, "*.")
	bExact := !strings.HasPrefix(b, "*.")
	switch {
	case aExact && bExact:
		if a == b {
			return a, true
		}
		return "", false
	case aExact && !bExact:
		if _, ok := matchHostPattern(b, a); ok {
			return a, true
		}
		return "", false
	case !aExact && bExact:
		if _, ok := matchHostPattern(a, b); ok {
			return b, true
		}
		return "", false
	default:
		if a != b {
			return "", false
		}
		return "a" + a[1:], true
	}
}

func globsOverlap(a, b string) bool {
	if a == "" || b == "" {
		return true
	}
	// Exact intersection. A depth cap that returns "no overlap" would let a
	// long star absorb enough of the other pattern to skip the check.
	n, m := len(a), len(b)
	dp := make([][]bool, n+1)
	for i := range dp {
		dp[i] = make([]bool, m+1)
	}
	dp[n][m] = true
	for i := n; i >= 0; i-- {
		for j := m; j >= 0; j-- {
			if i == n && j == m {
				continue
			}
			if i == n {
				dp[i][j] = onlyStars(b[j:])
				continue
			}
			if j == m {
				dp[i][j] = onlyStars(a[i:])
				continue
			}
			switch {
			case a[i] != '*' && b[j] != '*':
				if a[i] == b[j] {
					dp[i][j] = dp[i+1][j+1]
				}
			case a[i] == '*' && b[j] == '*':
				dp[i][j] = dp[i+1][j] || dp[i][j+1] || dp[i+1][j+1]
			case a[i] == '*':
				dp[i][j] = dp[i+1][j] || dp[i][j+1]
			default:
				dp[i][j] = dp[i][j+1] || dp[i+1][j]
			}
		}
	}
	return dp[0][0]
}

func onlyStars(s string) bool {
	return strings.Trim(s, "*") == ""
}
