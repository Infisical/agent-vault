package server

import (
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

	// Filter out hosts that match a currently configured service (host-only matching).
	var filtered []*discoveredHost
	for _, dh := range deduped {
		if broker.AnyHostMatches(dh.Host, services) {
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
