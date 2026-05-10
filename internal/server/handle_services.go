package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/catalog"
	"github.com/Infisical/agent-vault/internal/proposal"
)

// splitInlineFormHost splits a user-friendly inline form like
// `slack.com/api/*` into bare host + path. Returns the inputs unchanged
// when host doesn't contain a `/` or when path is already populated.
// Shared by every server-side ingest path (broker.Service upserts and
// proposal.Service ingest); CLI-side splits are kept in cmd/ since the
// CLI cannot import server packages.
func splitInlineFormHost(host, path string) (string, string) {
	if path != "" {
		return host, path
	}
	if i := strings.IndexByte(host, '/'); i > 0 {
		return host[:i], host[i:]
	}
	return host, path
}

// normalizeIncoming applies splitInlineFormHost to every service then
// backfills missing Names via broker.NormalizeServices. The result is
// ready for broker.Validate.
func normalizeIncoming(in []broker.Service) []broker.Service {
	out := make([]broker.Service, len(in))
	for i, svc := range in {
		svc.Host, svc.Path = splitInlineFormHost(svc.Host, svc.Path)
		out[i] = svc
	}
	return broker.NormalizeServices(out)
}

// hostAmbiguityError signals that an ActionDelete proposal targeted a
// host with multiple registered services and no Name to disambiguate.
// Carries the candidate list for the caller to surface in the 409.
type hostAmbiguityError struct {
	host       string
	candidates []broker.Service
}

func (e *hostAmbiguityError) Error() string {
	return fmt.Sprintf("multiple services match host %q — retry with a service name", e.host)
}

// normalizeProposalServices auto-fills proposal.Service.Name when
// missing and splits inline-form host (slack.com/api/* → host + path)
// for every entry. Mirrors the bulk-upsert ingest semantics so the
// proposal flow accepts the same legacy and inline-form payloads.
//
// For ActionSet entries, Name is auto-slugged via broker.Slugify(host,
// path) when blank. For ActionDelete entries, Name is resolved against
// the vault's existing services: a unique host match fills Name, a
// 2+ match returns *hostAmbiguityError so the caller can surface the
// candidate list as a 409, and a 0-hit leaves Name blank so the merge
// step warns "service not found" downstream.
func normalizeProposalServices(in []proposal.Service, existing []broker.Service) ([]proposal.Service, *hostAmbiguityError, error) {
	out := make([]proposal.Service, len(in))
	autoSlugged := make([]bool, len(in))
	for i, svc := range in {
		svc.Host, svc.Path = splitInlineFormHost(svc.Host, svc.Path)

		switch svc.Action {
		case proposal.ActionDelete:
			if svc.Name == "" {
				var matches []broker.Service
				for _, e := range existing {
					if e.Host == svc.Host {
						matches = append(matches, e)
					}
				}
				switch {
				case len(matches) == 1:
					svc.Name = matches[0].Name
				case len(matches) > 1:
					return nil, &hostAmbiguityError{host: svc.Host, candidates: matches}, nil
				default:
					// 0 hits: still need a Name to satisfy Validate.
					// The merge step will warn "service not found".
					svc.Name = broker.Slugify(svc.Host, svc.Path)
				}
			}
		default: // ActionSet (and any unknown — Validate will reject)
			if svc.Name == "" {
				svc.Name = broker.Slugify(svc.Host, svc.Path)
				autoSlugged[i] = true
			}
		}
		out[i] = svc
	}

	// Resolve auto-slug collisions for set actions. Seed `used` with
	// names already taken — both by existing vault services and by
	// explicit (user-supplied) names elsewhere in this proposal — so
	// that auto-slugs bump (`-2`) rather than silently replacing an
	// unrelated existing service.
	//
	// Explicit-name collisions are left alone: a user resubmitting a
	// proposal with the same Name as an existing service is asking for
	// upsert-by-name (the intended ActionSet semantic), and an
	// intra-proposal duplicate-explicit-Name is caught by
	// proposal.Validate's duplicate-name check.
	used := make(map[string]bool, len(existing)+len(out))
	for _, e := range existing {
		used[e.Name] = true
	}
	for i := range out {
		if out[i].Action != proposal.ActionSet || autoSlugged[i] {
			continue
		}
		used[out[i].Name] = true
	}
	for i := range out {
		if out[i].Action != proposal.ActionSet || !autoSlugged[i] {
			continue
		}
		if !used[out[i].Name] {
			used[out[i].Name] = true
			continue
		}
		out[i].Name = broker.EnsureUniqueName(out[i].Name, used)
		used[out[i].Name] = true
	}
	return out, nil, nil
}

// loadServices reads and parses the broker config, returning a
// name-normalized slice (legacy services missing Name get slugged on
// the fly so callers always see populated names without a write).
// Returns nil, nil when the vault has no broker config.
func (s *Server) loadServices(ctx context.Context, vaultID string) ([]broker.Service, error) {
	bc, err := s.store.GetBrokerConfig(ctx, vaultID)
	if err != nil {
		return nil, err
	}
	if bc == nil {
		return nil, nil
	}
	var services []broker.Service
	if err := json.Unmarshal([]byte(bc.ServicesJSON), &services); err != nil {
		return nil, err
	}
	return broker.NormalizeServices(services), nil
}

// resolveServiceRef looks up a service by the {host} URL slot, which we
// reinterpret as a name-or-host slot. Tries Name match first (1:1, no
// ambiguity); falls back to Host match (1 hit applies, 2+ returns the
// candidate list for the caller to surface as 409). Returns the matched
// index, the candidate list (set only when host-match was ambiguous),
// and ok=false when nothing matched.
func resolveServiceRef(services []broker.Service, ref string) (idx int, candidates []broker.Service, ok bool) {
	for i, svc := range services {
		if svc.Name == ref {
			return i, nil, true
		}
	}
	matches := []int{}
	for i, svc := range services {
		if svc.Host == ref {
			matches = append(matches, i)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil, true
	}
	if len(matches) > 1 {
		cands := make([]broker.Service, 0, len(matches))
		for _, i := range matches {
			cands = append(cands, services[i])
		}
		return -1, cands, false
	}
	return -1, nil, false
}

// candidateRefs is the body shape returned with 409 when a host slot
// matches multiple services. Caller picks one by Name and retries.
type candidateRef struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Path string `json:"path,omitempty"`
}

func toCandidateRefs(svcs []broker.Service) []candidateRef {
	out := make([]candidateRef, len(svcs))
	for i, s := range svcs {
		out[i] = candidateRef{Name: s.Name, Host: s.Host, Path: s.Path}
	}
	return out
}

func (s *Server) handleServicesGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}

	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	services, err := s.loadServices(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to parse services")
		return
	}
	if services == nil {
		services = []broker.Service{}
	}

	jsonOK(w, map[string]interface{}{"vault": name, "services": services})
}

func (s *Server) handleServicesCredentialUsage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}

	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	key := r.URL.Query().Get("key")
	if key == "" {
		jsonError(w, http.StatusBadRequest, "Missing required query parameter: key")
		return
	}

	services, err := s.loadServices(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to parse services")
		return
	}

	type serviceRef struct {
		Name        string `json:"name"`
		Host        string `json:"host"`
		Path        string `json:"path,omitempty"`
		Description string `json:"description,omitempty"`
	}
	var refs []serviceRef
	for _, svc := range services {
		for _, sk := range svc.Auth.CredentialKeys() {
			if sk == key {
				ref := serviceRef{Name: svc.Name, Host: svc.Host, Path: svc.Path}
				if svc.Description != nil {
					ref.Description = *svc.Description
				}
				refs = append(refs, ref)
				break
			}
		}
	}

	if refs == nil {
		refs = []serviceRef{}
	}
	jsonOK(w, map[string]interface{}{"services": refs})
}

func (s *Server) handleServicesUpsert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}

	if _, err := s.requireVaultAdmin(w, r, ns.ID); err != nil {
		return
	}

	var req struct {
		Services []broker.Service `json:"services"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(req.Services) == 0 {
		jsonError(w, http.StatusBadRequest, "At least one service is required")
		return
	}

	// Inline-form split + auto-slug missing names so legacy clients
	// (host-only, no name) keep working.
	incomingSlice := normalizeIncoming(req.Services)

	// Validate incoming services.
	incoming := broker.Config{Vault: name, Services: incomingSlice}
	if err := broker.Validate(&incoming); err != nil {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid services: %v", err))
		return
	}

	// Load existing services (NormalizeServices fills any legacy missing names).
	existing, err := s.loadServices(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to parse services")
		return
	}

	// Index existing by canonical Name for upsert.
	byName := make(map[string]int, len(existing))
	for i, svc := range existing {
		byName[svc.Name] = i
	}

	var upserted []string
	for _, svc := range incomingSlice {
		if idx, ok := byName[svc.Name]; ok {
			existing[idx] = svc
		} else {
			byName[svc.Name] = len(existing)
			existing = append(existing, svc)
		}
		upserted = append(upserted, svc.Name)
	}

	servicesJSON, err := json.Marshal(existing)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to marshal services")
		return
	}

	if _, err := s.store.SetBrokerConfig(ctx, ns.ID, string(servicesJSON)); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to set services")
		return
	}

	jsonOK(w, map[string]interface{}{
		"vault":          name,
		"upserted":       upserted,
		"services_count": len(existing),
	})
}

func (s *Server) handleServiceRemove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}

	if _, err := s.requireVaultAdmin(w, r, ns.ID); err != nil {
		return
	}

	ref := r.PathValue("host")
	if ref == "" {
		jsonError(w, http.StatusBadRequest, "Service name or host is required")
		return
	}

	// Load existing services (auto-normalized: legacy names backfilled).
	services, err := s.loadServices(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to parse services")
		return
	}
	if services == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Service not found for %q", ref))
		return
	}

	idx, candidates, ok := resolveServiceRef(services, ref)
	if !ok {
		if candidates != nil {
			jsonStatus(w, http.StatusConflict, map[string]interface{}{
				"error":      fmt.Sprintf("multiple services match host %q — retry with a service name", ref),
				"candidates": toCandidateRefs(candidates),
			})
			return
		}
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Service not found for %q", ref))
		return
	}

	removed := services[idx]
	filtered := append(services[:idx:idx], services[idx+1:]...)

	servicesJSON, err := json.Marshal(filtered)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to marshal services")
		return
	}

	if _, err := s.store.SetBrokerConfig(ctx, ns.ID, string(servicesJSON)); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to update services")
		return
	}

	jsonOK(w, map[string]interface{}{
		"vault":          name,
		"removed":        removed.Name,
		"removed_host":   removed.Host,
		"services_count": len(filtered),
	})
}

// handleServicePatch applies a partial update to a single service. The
// {host} URL slot is interpreted as a name-or-host reference: name match
// wins (1:1, no ambiguity); host match falls back, with a 409 candidate
// list when more than one service shares that host. Today only the
// `enabled` field is patchable — other fields change through the
// POST/PUT upsert/set flow so auth-config validation has a single code
// path. Admin-only.
func (s *Server) handleServicePatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}

	if _, err := s.requireVaultAdmin(w, r, ns.ID); err != nil {
		return
	}

	ref := r.PathValue("host")
	if ref == "" {
		jsonError(w, http.StatusBadRequest, "Service name or host is required")
		return
	}

	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Enabled == nil {
		jsonError(w, http.StatusBadRequest, "At least one patchable field is required (enabled)")
		return
	}

	services, err := s.loadServices(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to parse services")
		return
	}
	if services == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Service not found for %q", ref))
		return
	}

	idx, candidates, ok := resolveServiceRef(services, ref)
	if !ok {
		if candidates != nil {
			jsonStatus(w, http.StatusConflict, map[string]interface{}{
				"error":      fmt.Sprintf("multiple services match host %q — retry with a service name", ref),
				"candidates": toCandidateRefs(candidates),
			})
			return
		}
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Service not found for %q", ref))
		return
	}

	services[idx].Enabled = req.Enabled

	servicesJSON, err := json.Marshal(services)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to marshal services")
		return
	}

	if _, err := s.store.SetBrokerConfig(ctx, ns.ID, string(servicesJSON)); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to update services")
		return
	}

	jsonOK(w, map[string]interface{}{
		"vault":   name,
		"name":    services[idx].Name,
		"host":    services[idx].Host,
		"enabled": *req.Enabled,
	})
}

func (s *Server) handleServicesSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}

	// Setting services requires admin role.
	if _, err := s.requireVaultAdmin(w, r, ns.ID); err != nil {
		return
	}

	var req struct {
		Services json.RawMessage `json:"services"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate services by unmarshalling into broker.Service slice and running broker.Validate.
	var services []broker.Service
	if err := json.Unmarshal(req.Services, &services); err != nil {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid services: %v", err))
		return
	}
	services = normalizeIncoming(services)
	cfg := broker.Config{Vault: name, Services: services}
	if err := broker.Validate(&cfg); err != nil {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid services: %v", err))
		return
	}

	servicesJSON, err := json.Marshal(services)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to marshal services")
		return
	}

	if _, err := s.store.SetBrokerConfig(ctx, ns.ID, string(servicesJSON)); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to set services")
		return
	}

	jsonOK(w, map[string]interface{}{"vault": name, "services_count": len(services)})
}

func (s *Server) handleServicesClear(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}

	// Clearing services requires admin role.
	if _, err := s.requireVaultAdmin(w, r, ns.ID); err != nil {
		return
	}

	if _, err := s.store.SetBrokerConfig(ctx, ns.ID, "[]"); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to clear services")
		return
	}

	jsonOK(w, map[string]interface{}{"vault": name, "cleared": true})
}

func (s *Server) handleServiceCatalog(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]interface{}{"services": catalog.GetAll()})
}

// SetSkills sets the embedded skill content for the CLI and HTTP skills.
func (s *Server) SetSkills(cli, httpSkill string) {
	s.skillCLI = []byte(cli)
	s.skillHTTP = []byte(httpSkill)
}

func (s *Server) handleSkillCLI(w http.ResponseWriter, r *http.Request) {
	s.serveSkill(w, r, s.skillCLI)
}

func (s *Server) handleSkillHTTP(w http.ResponseWriter, r *http.Request) {
	s.serveSkill(w, r, s.skillHTTP)
}

func (s *Server) serveSkill(w http.ResponseWriter, r *http.Request, content []byte) {
	if len(content) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	_, _ = w.Write(content)
}
