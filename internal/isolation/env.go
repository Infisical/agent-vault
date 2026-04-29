// Package isolation builds the non-cooperative container that
// `vault run --isolation=container` launches the child agent inside.
package isolation

import (
	"fmt"
	"net/url"
	"strings"
)

const (
	ContainerCAPath       = "/etc/agent-vault/ca.pem"
	ContainerProxyHost    = "host.docker.internal"
	ContainerClaudeHome   = "/home/claude/.claude"
	ContainerClaudeConfig = "/home/claude/.claude.json"
)

// ProxyEnvParams feeds BuildProxyEnv. Process mode and container mode
// differ only in Host (loopback vs host.docker.internal) and CAPath
// (host-local vs container-local bind mount).
type ProxyEnvParams struct {
	Host    string // MITM listener host from the child's point of view
	Port    int
	Token   string
	Vault   string
	CAPath  string // path the child reads the CA PEM from
	MITMTLS bool   // true → HTTPS_PROXY uses https://, false → http://

	ExtraNoProxy []string // appended to NO_PROXY defaults; see buildNoProxy
}

// buildNoProxy merges the default bypass list (loopback) with the
// caller's extras, trimming whitespace and dropping empties + dupes
// while preserving order. The defaults always come first so the
// localhost protections cannot be reordered or overridden.
func buildNoProxy(extras []string) string {
	hosts := []string{"localhost", "127.0.0.1"}
	seen := map[string]struct{}{"localhost": {}, "127.0.0.1": {}}
	for _, h := range extras {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		hosts = append(hosts, h)
	}
	return strings.Join(hosts, ",")
}

// BuildProxyEnv returns the nine env vars that point an HTTPS client at
// agent-vault's MITM proxy with the right credentials and CA trust.
// Canonical source for both the process path (augmentEnvWithMITM) and
// the container path (BuildContainerEnv) so the list can't drift.
//
// NB: keep in sync with buildProxyEnv() in
// sdks/sdk-typescript/src/resources/sessions.ts.
func BuildProxyEnv(p ProxyEnvParams) []string {
	scheme := "http"
	if p.MITMTLS {
		scheme = "https"
	}
	proxyURL := (&url.URL{
		Scheme: scheme,
		User:   url.UserPassword(p.Token, p.Vault),
		Host:   fmt.Sprintf("%s:%d", p.Host, p.Port),
	}).String()
	return []string{
		"HTTPS_PROXY=" + proxyURL,
		"NO_PROXY=" + buildNoProxy(p.ExtraNoProxy),
		"NODE_USE_ENV_PROXY=1",
		"SSL_CERT_FILE=" + p.CAPath,
		"NODE_EXTRA_CA_CERTS=" + p.CAPath,
		"REQUESTS_CA_BUNDLE=" + p.CAPath,
		"CURL_CA_BUNDLE=" + p.CAPath,
		"GIT_SSL_CAINFO=" + p.CAPath,
		"DENO_CERT=" + p.CAPath,
	}
}

// ProxyEnvKeys are the keys BuildProxyEnv emits. POSIX getenv returns
// the first match in C code paths, so parent-env occurrences must be
// stripped before appending these.
var ProxyEnvKeys = []string{
	"HTTPS_PROXY",
	"NO_PROXY",
	"NODE_USE_ENV_PROXY",
	"SSL_CERT_FILE",
	"NODE_EXTRA_CA_CERTS",
	"REQUESTS_CA_BUNDLE",
	"CURL_CA_BUNDLE",
	"GIT_SSL_CAINFO",
	"DENO_CERT",
}

// BuildContainerEnv returns the KEY=VALUE entries to pass to `docker
// run` via -e flags. Produces a fresh list rather than augmenting
// os.Environ() — the container should not inherit the host's env.
//
// extraNoProxy is appended to NO_PROXY's default loopback entries; see
// ProxyEnvParams.ExtraNoProxy for semantics.
func BuildContainerEnv(token, vault string, httpPort, mitmPort int, mitmTLS bool, extraNoProxy []string) []string {
	env := BuildProxyEnv(ProxyEnvParams{
		Host:         ContainerProxyHost,
		Port:         mitmPort,
		Token:        token,
		Vault:        vault,
		CAPath:       ContainerCAPath,
		MITMTLS:      mitmTLS,
		ExtraNoProxy: extraNoProxy,
	})
	return append(env,
		"AGENT_VAULT_SESSION_TOKEN="+token,
		"AGENT_VAULT_ADDR="+fmt.Sprintf("http://%s:%d", ContainerProxyHost, httpPort),
		"AGENT_VAULT_VAULT="+vault,
		fmt.Sprintf("VAULT_HTTP_PORT=%d", httpPort),
		fmt.Sprintf("VAULT_MITM_PORT=%d", mitmPort),
	)
}
