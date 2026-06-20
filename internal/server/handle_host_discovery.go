package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
)

const (
	discoveredHostsDefaultLimit = 5
	discoveredHostsMaxLimit     = 100
	settingDismissedHosts       = "dismissed_discovered_hosts"
)

type discoveredHost struct {
	Host         string `json:"host"`
	RequestCount int    `json:"request_count"`
	LastSeen     string `json:"last_seen"`
	AuthScheme   string `json:"auth_scheme,omitempty"`
	AuthHeader   string `json:"auth_header,omitempty"`

	lastSeenTime time.Time
}

func (s *Server) handleDiscoveredHosts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}

	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	// Parse limit: absent/error = default, negative = default, 0 = count-only, >max = clamp.
	limit := discoveredHostsDefaultLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			if v == 0 {
				limit = 0
			} else if v > 0 {
				limit = v
			}
		}
	}
	if limit > discoveredHostsMaxLimit {
		limit = discoveredHostsMaxLimit
	}

	unmatched, err := s.store.ListUnmatchedHosts(ctx, ns.ID)
	if err != nil {
		s.logger.Warn("discovered-hosts: store query failed", "vault", name, "err", err.Error())
		jsonError(w, http.StatusInternalServerError, "Failed to list discovered hosts")
		return
	}

	services, err := s.loadServices(ctx, ns.ID)
	if err != nil {
		s.logger.Warn("discovered-hosts: loadServices failed", "vault", name, "err", err.Error())
		jsonError(w, http.StatusInternalServerError, "Failed to load services")
		return
	}

	// Port-strip and deduplicate: merge entries that differ only by port.
	deduped := make(map[string]*discoveredHost)
	for _, uh := range unmatched {
		h := uh.Host
		if stripped, _, err := net.SplitHostPort(h); err == nil {
			h = stripped
		}
		if existing, ok := deduped[h]; ok {
			existing.RequestCount += uh.RequestCount
			if uh.LastSeen.After(existing.lastSeenTime) {
				existing.lastSeenTime = uh.LastSeen
				existing.LastSeen = uh.LastSeen.Format(time.RFC3339)
				existing.AuthScheme = uh.AuthScheme
				existing.AuthHeader = uh.AuthHeader
			}
		} else {
			deduped[h] = &discoveredHost{
				Host:         h,
				RequestCount: uh.RequestCount,
				LastSeen:     uh.LastSeen.Format(time.RFC3339),
				AuthScheme:   uh.AuthScheme,
				AuthHeader:   uh.AuthHeader,
				lastSeenTime: uh.LastSeen,
			}
		}
	}

	// Load dismissed hosts.
	dismissed := loadDismissedHosts(ctx, s.store, ns.ID)

	// Filter out hosts that match a currently configured service or were dismissed.
	var filtered []*discoveredHost
	for _, dh := range deduped {
		if broker.AnyHostMatches(dh.Host, services) {
			continue
		}
		if dismissed[dh.Host] {
			continue
		}
		filtered = append(filtered, dh)
	}

	// Re-sort by last_seen DESC, hostname ASC as tiebreaker for stable ordering.
	sort.Slice(filtered, func(i, j int) bool {
		if !filtered[i].lastSeenTime.Equal(filtered[j].lastSeenTime) {
			return filtered[i].lastSeenTime.After(filtered[j].lastSeenTime)
		}
		return filtered[i].Host < filtered[j].Host
	})

	total := len(filtered)

	// limit=0: count-only mode for sidebar badge polling.
	if limit == 0 {
		jsonOK(w, map[string]any{
			"hosts": []discoveredHost{},
			"total": total,
		})
		return
	}

	if limit < len(filtered) {
		filtered = filtered[:limit]
	}

	hosts := make([]discoveredHost, len(filtered))
	for i, dh := range filtered {
		hosts[i] = *dh
	}

	jsonOK(w, map[string]any{
		"hosts": hosts,
		"total": total,
	})
}

// handleDismissDiscoveredHost dismisses a single discovered host so it no
// longer appears in the suggestions banner.
func (s *Server) handleDismissDiscoveredHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vaultName := r.PathValue("name")
	host := r.PathValue("host")

	ns, err := s.store.GetVault(ctx, vaultName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", vaultName))
		return
	}

	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	if host == "" {
		jsonError(w, http.StatusBadRequest, "Host is required")
		return
	}

	dismissed := loadDismissedHosts(ctx, s.store, ns.ID)
	dismissed[host] = true
	if err := saveDismissedHosts(ctx, s.store, ns.ID, dismissed); err != nil {
		s.logger.Warn("dismiss-host: save failed", "vault", vaultName, "err", err.Error())
		jsonError(w, http.StatusInternalServerError, "Failed to dismiss host")
		return
	}

	jsonOK(w, map[string]any{"dismissed": host})
}

// handleDismissAllDiscoveredHosts dismisses all currently visible discovered
// hosts for a vault.
func (s *Server) handleDismissAllDiscoveredHosts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vaultName := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, vaultName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", vaultName))
		return
	}

	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	// Collect all currently visible unmatched hosts to dismiss them.
	unmatched, err := s.store.ListUnmatchedHosts(ctx, ns.ID)
	if err != nil {
		s.logger.Warn("dismiss-all: store query failed", "vault", vaultName, "err", err.Error())
		jsonError(w, http.StatusInternalServerError, "Failed to list discovered hosts")
		return
	}

	dismissed := loadDismissedHosts(ctx, s.store, ns.ID)
	for _, uh := range unmatched {
		h := uh.Host
		if stripped, _, err := net.SplitHostPort(h); err == nil {
			h = stripped
		}
		dismissed[h] = true
	}

	if err := saveDismissedHosts(ctx, s.store, ns.ID, dismissed); err != nil {
		s.logger.Warn("dismiss-all: save failed", "vault", vaultName, "err", err.Error())
		jsonError(w, http.StatusInternalServerError, "Failed to dismiss hosts")
		return
	}

	jsonOK(w, map[string]any{"dismissed": len(dismissed)})
}

type vaultSettingStore interface {
	GetVaultSetting(ctx context.Context, vaultID, key string) (string, error)
	SetVaultSetting(ctx context.Context, vaultID, key, value string) error
}

func loadDismissedHosts(ctx context.Context, st vaultSettingStore, vaultID string) map[string]bool {
	raw, err := st.GetVaultSetting(ctx, vaultID, settingDismissedHosts)
	if err != nil || raw == "" {
		return make(map[string]bool)
	}
	var hosts []string
	if err := json.Unmarshal([]byte(raw), &hosts); err != nil {
		return make(map[string]bool)
	}
	m := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		m[h] = true
	}
	return m
}

func saveDismissedHosts(ctx context.Context, st vaultSettingStore, vaultID string, dismissed map[string]bool) error {
	hosts := make([]string, 0, len(dismissed))
	for h := range dismissed {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	data, err := json.Marshal(hosts)
	if err != nil {
		return err
	}
	return st.SetVaultSetting(ctx, vaultID, settingDismissedHosts, string(data))
}

