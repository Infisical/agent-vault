package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/catalog"
	"github.com/Infisical/agent-vault/internal/proposal"
)

// rejectDeprecatedDescription scans a raw JSON services array for the
// now-removed `description` field. Returns the zero-based index of the
// first offending entry, or -1 if none. Best-effort: malformed JSON
// returns -1 so the typed decoder downstream produces a structured
// error instead of two layered ones.
func rejectDeprecatedDescription(servicesRaw json.RawMessage) int {
	var probes []map[string]json.RawMessage
	if err := json.Unmarshal(servicesRaw, &probes); err != nil {
		return -1
	}
	for i, p := range probes {
		if _, ok := p["description"]; ok {
			return i
		}
	}
	return -1
}

const deprecatedDescriptionMsg = "description is no longer supported; rename via the service name field instead"

// normalizeIncoming applies broker.SplitInlineHost to every service then
// backfills missing Names via broker.NormalizeServices. Suitable for
// replace-all flows (handleServicesSet) where existing state is about
// to be overwritten — for partial upserts use normalizeIncomingAgainstExisting
// so auto-slugged names don't collide with unrelated stored services.
func normalizeIncoming(in []broker.Service) []broker.Service {
	out := make([]broker.Service, len(in))
	for i, svc := range in {
		svc.Host, svc.Path = broker.SplitInlineHost(svc.Host, svc.Path)
		out[i] = svc
	}
	return broker.NormalizeServices(out)
}

// normalizeIncomingAgainstExisting is the upsert-aware counterpart to
// normalizeIncoming. For each incoming service with no Name:
//
//  1. Look up an existing service with the same (Host, Path). If found,
//     adopt its Name. This preserves the legacy "upsert by host" pattern
//     (`agent-vault vault service add --host api.stripe.com …` updates
//     the stored api.stripe.com service even when its Name was assigned
//     explicitly or by an older slug).
//  2. Otherwise, auto-slug from broker.Slugify(Host, Path). If the slug
//     collides with a name already taken — by an existing service or by
//     an explicit name elsewhere in this batch — bump (`-2`) so the
//     downstream byName upsert can't silently overwrite an unrelated
//     stored service. Mirrors normalizeProposalServices's seeding.
//
// Explicit-name collisions are left alone: a caller resubmitting an
// upsert with the same Name as an existing service is asking for
// upsert-by-name (the intended POST semantic). Intra-batch duplicate
// explicit Names fall through to broker.Validate's duplicate-name check.
func normalizeIncomingAgainstExisting(in []broker.Service, existing []broker.Service) []broker.Service {
	out := make([]broker.Service, len(in))
	autoSlugged := make([]bool, len(in))
	for i, svc := range in {
		svc.Host, svc.Path = broker.SplitInlineHost(svc.Host, svc.Path)
		if svc.Name == "" {
			if matched := findByHostPath(existing, svc.Host, svc.Path); matched != nil {
				svc.Name = matched.Name
			} else {
				svc.Name = broker.Slugify(svc.Host, svc.Path)
				autoSlugged[i] = true
			}
		}
		out[i] = svc
	}

	used := make(map[string]bool, len(existing)+len(out))
	for _, e := range existing {
		used[e.Name] = true
	}
	for i := range out {
		if !autoSlugged[i] {
			used[out[i].Name] = true
		}
	}
	for i := range out {
		if !autoSlugged[i] {
			continue
		}
		if !used[out[i].Name] {
			used[out[i].Name] = true
			continue
		}
		out[i].Name = broker.EnsureUniqueName(out[i].Name, used)
		used[out[i].Name] = true
	}
	return out
}

// findByHostPath returns the first existing service whose Host and Path
// equal the given pair, or nil. First-match preserves declaration order
// in the same way broker.MatchService falls back to it on score ties.
func findByHostPath(existing []broker.Service, host, path string) *broker.Service {
	for i := range existing {
		if existing[i].Host == host && existing[i].Path == path {
			return &existing[i]
		}
	}
	return nil
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
// For ActionSet entries with no Name, the (Host, Path) pair is matched
// against existing services first — if found, the existing Name is
// adopted so a legacy "rotate-credentials" proposal (host-only, no
// name) updates the stored service rather than creating a duplicate.
// Only when no host+path match exists does the entry fall through to
// broker.Slugify with collision bumping. For ActionDelete entries, Name
// is resolved against the vault's existing services: a unique host
// match fills Name, a 2+ match returns *hostAmbiguityError so the
// caller can surface the candidate list as a 409, and a 0-hit leaves
// Name blank so proposal.Validate rejects the no-op delete cleanly
// (rather than fabricating a slug that might collide with an unrelated
// service's explicit Name).
func normalizeProposalServices(in []proposal.Service, existing []broker.Service) ([]proposal.Service, *hostAmbiguityError, error) {
	out := make([]proposal.Service, len(in))
	autoSlugged := make([]bool, len(in))
	for i, svc := range in {
		svc.Host, svc.Path = broker.SplitInlineHost(svc.Host, svc.Path)

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
					// 0 hits: leave Name empty — Validate will reject
					// with "name required" rather than letting a
					// fabricated slug collide with an unrelated service.
				}
			}
		default: // ActionSet (and any unknown — Validate will reject)
			if svc.Name == "" {
				if matched := findByHostPath(existing, svc.Host, svc.Path); matched != nil {
					svc.Name = matched.Name
				} else {
					svc.Name = broker.Slugify(svc.Host, svc.Path)
					autoSlugged[i] = true
				}
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
// Splits any inline-form host (`slack.com/api/*`) into bare Host +
// Path so the matcher invariant — stored Host never contains "/" —
// holds even after broker.Service.MarshalJSON persists the joined
// form. Idempotent: a Host with no "/" passes through unchanged.
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
	for i := range services {
		services[i].Host, services[i].Path = broker.SplitInlineHost(services[i].Host, services[i].Path)
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
	var matches []int
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
// Host is the joined inline form (`slack.com/api/*`) so the field
// matches the single-host wire shape used everywhere else.
type candidateRef struct {
	Name string `json:"name"`
	Host string `json:"host"`
}

func toCandidateRefs(svcs []broker.Service) []candidateRef {
	out := make([]candidateRef, len(svcs))
	for i, s := range svcs {
		out[i] = candidateRef{Name: s.Name, Host: s.MatcherPattern()}
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

// handleServicesCredentialUsage returns the {name, host} of every
// service that references the given credential key. Gated at proxy+
// (requireVaultAccess) deliberately: this is a strict subset of what
// /discover already exposes to the same role — /discover lists every
// service in the vault and every available credential key, so an
// agent could filter client-side and arrive at the same answer.
// Tightening to member+ here would create asymmetry without preventing
// access.
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
		Name string `json:"name"`
		Host string `json:"host"`
	}
	var refs []serviceRef
	for _, svc := range services {
		for _, sk := range svc.Auth.CredentialKeys() {
			if sk == key {
				refs = append(refs, serviceRef{Name: svc.Name, Host: svc.MatcherPattern()})
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

	var raw struct {
		Services json.RawMessage `json:"services"`
	}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if i := rejectDeprecatedDescription(raw.Services); i >= 0 {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("services[%d]: %s", i, deprecatedDescriptionMsg))
		return
	}

	var req struct {
		Services []broker.Service
	}
	if len(raw.Services) > 0 {
		if err := json.Unmarshal(raw.Services, &req.Services); err != nil {
			jsonError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
	}

	if len(req.Services) == 0 {
		jsonError(w, http.StatusBadRequest, "At least one service is required")
		return
	}

	// Serialize the load → normalize → save cycle. SQLite serializes
	// individual statements but not the sequence; without this, two
	// concurrent upserts can both pass the auto-slug collision check
	// against the same pre-state and the second writer wins.
	defer s.lockVaultServices(ns.ID)()

	// Load existing first so the incoming-batch normalization can seed
	// its collision map with names already taken in the vault.
	// Otherwise an incoming service with no Name whose Slugify(Host,Path)
	// happens to match an unrelated stored service's Name would silently
	// overwrite that service via the byName upsert below.
	existing, err := s.loadServices(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to parse services")
		return
	}

	// Inline-form split + auto-slug missing names; auto-slugs that
	// collide with `existing` bump (`-2`) rather than overwrite.
	incomingSlice := normalizeIncomingAgainstExisting(req.Services, existing)

	// Validate incoming services.
	incoming := broker.Config{Vault: name, Services: incomingSlice}
	if err := broker.Validate(&incoming); err != nil {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid services: %v", err))
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

	defer s.lockVaultServices(ns.ID)()

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
	filtered := make([]broker.Service, 0, len(services)-1)
	filtered = append(filtered, services[:idx]...)
	filtered = append(filtered, services[idx+1:]...)

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
		"removed_host":   removed.MatcherPattern(),
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

	defer s.lockVaultServices(ns.ID)()

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
		"host":    services[idx].MatcherPattern(),
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
	if i := rejectDeprecatedDescription(req.Services); i >= 0 {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("services[%d]: %s", i, deprecatedDescriptionMsg))
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

	defer s.lockVaultServices(ns.ID)()

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
