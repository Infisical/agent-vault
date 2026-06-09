package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/catalog"
	"github.com/Infisical/agent-vault/internal/proposal"
)

// rejectDeprecatedDescription returns the index of the first services
// entry carrying the now-removed `description` field, or -1. Returns
// -1 on malformed JSON so the typed decoder produces the structured
// error downstream.
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

// splitInlineHosts copies the input slice and applies SplitInlineHost
// to each entry so the matcher invariant (Host has no '/') holds before
// validation. Name is required and validated downstream.
func splitInlineHosts(in []broker.Service) []broker.Service {
	out := make([]broker.Service, len(in))
	for i, svc := range in {
		svc.Host, svc.Path, svc.Port = broker.SplitInlineHost(svc.Host, svc.Path)
		out[i] = svc
	}
	return out
}

// hostAmbiguityError is returned when an unnamed ActionDelete targets a
// host with multiple registered services. Carries the candidate list.
type hostAmbiguityError struct {
	host       string
	candidates []broker.Service
}

func (e *hostAmbiguityError) Error() string {
	return fmt.Sprintf("multiple services match host %q — retry with a service name", e.host)
}

// hostNotFoundError is returned when an unnamed ActionDelete targets a
// host with no matching service.
type hostNotFoundError struct{ host string }

func (e *hostNotFoundError) Error() string {
	return fmt.Sprintf("no service matches host %q — delete target must be addressable by host or service name", e.host)
}

// writeNormalizeError maps a normalizeProposalServices error to an HTTP
// response. Ambiguity → 409 with candidates. Not-found uses
// notFoundStatus (caller picks 404 at create, 409 at apply); notFoundMsg
// optionally overrides the body.
func writeNormalizeError(w http.ResponseWriter, err error, notFoundStatus, defaultStatus int, notFoundMsg func(host string) string) {
	var ambig *hostAmbiguityError
	if errors.As(err, &ambig) {
		jsonStatus(w, http.StatusConflict, map[string]interface{}{
			"error":      ambig.Error(),
			"candidates": toCandidateRefs(ambig.candidates),
		})
		return
	}
	var notFound *hostNotFoundError
	if errors.As(err, &notFound) {
		msg := notFound.Error()
		if notFoundMsg != nil {
			msg = notFoundMsg(notFound.host)
		}
		jsonStatus(w, notFoundStatus, map[string]interface{}{"error": msg})
		return
	}
	jsonError(w, defaultStatus, err.Error())
}

// adoptByHost fills empty Name on `services` by adopting from an
// existing service whose (Host, Path) uniquely matches. When
// `rebindStale` is true, non-empty Names that miss the existing
// nameset are also rebound by (Host, Path) — used by the proposal
// path to close the create→rename→apply race where the existing
// service was renamed after the proposal was persisted. Direct
// admin upserts pass false so a caller-supplied Name is never
// silently rewritten. Empty Names without a unique host match are
// left empty so downstream validation surfaces "name is required".
func adoptByHost(services []broker.Service, existing []broker.Service, rebindStale bool) {
	type hp struct {
		host string
		path string
		port int
	}
	hpCount := make(map[hp]int, len(existing))
	hpName := make(map[hp]string, len(existing))
	var nameSet map[string]bool
	if rebindStale {
		nameSet = make(map[string]bool, len(existing))
	}
	for _, e := range existing {
		if nameSet != nil {
			nameSet[e.Name] = true
		}
		k := hp{e.Host, e.Path, broker.PortVal(e.Port)}
		hpCount[k]++
		if hpCount[k] == 1 {
			hpName[k] = e.Name
		}
	}
	for i := range services {
		svc := &services[i]
		if svc.Name != "" {
			if !rebindStale || nameSet[svc.Name] {
				continue
			}
		}
		k := hp{svc.Host, svc.Path, broker.PortVal(svc.Port)}
		if hpCount[k] == 1 {
			svc.Name = hpName[k]
		}
	}
}

// normalizeProposalServices splits inline-form host on every entry,
// resolves ActionDelete-by-host (unique → fill Name; 2+ → ambiguity
// error; 0 → not-found error), and routes ActionSet entries through
// adoptByHost so empty Names adopt a unique (Host, Path) match and
// stale Names rebind across the create→rename→apply race. Empty-Host
// ActionSet entries are excluded from adoption so an invalid Host
// surfaces at validation rather than resolving from garbage. Empty
// Names without a unique host match fall through to proposal.Validate
// which rejects with "name is required".
func normalizeProposalServices(in []proposal.Service, existing []broker.Service) ([]proposal.Service, error) {
	out := make([]proposal.Service, len(in))

	for i, svc := range in {
		svc.Host, svc.Path, svc.Port = broker.SplitInlineHost(svc.Host, svc.Path)
		if svc.Action == proposal.ActionDelete && svc.Name == "" {
			var matches []broker.Service
			for _, e := range existing {
				if e.Host != svc.Host {
					continue
				}
				// Narrow by Path when the caller scoped via inline form;
				// empty Path stays a host-level delete that intentionally
				// surfaces multi-service ambiguity.
				if svc.Path != "" && e.Path != svc.Path {
					continue
				}
				if svc.Port != nil && (e.Port == nil || *e.Port != *svc.Port) {
					continue
				}
				matches = append(matches, e)
			}
			switch {
			case len(matches) == 1:
				svc.Name = matches[0].Name
			case len(matches) > 1:
				return nil, &hostAmbiguityError{host: svc.Host, candidates: matches}
			default:
				return nil, &hostNotFoundError{host: svc.Host}
			}
		}
		out[i] = svc
	}

	setIdx := make([]int, 0, len(out))
	for i, svc := range out {
		if svc.Action == proposal.ActionSet && svc.Host != "" {
			setIdx = append(setIdx, i)
		}
	}
	if len(setIdx) > 0 {
		view := make([]broker.Service, len(setIdx))
		for j, i := range setIdx {
			view[j] = broker.Service{Name: out[i].Name, Host: out[i].Host, Path: out[i].Path, Port: out[i].Port}
		}
		adoptByHost(view, existing, true)
		for j, i := range setIdx {
			out[i].Name = view[j].Name
		}
	}
	return out, nil
}

// loadServices reads the vault's broker config, splits inline-form
// Host so the matcher invariant holds, and backfills missing Name
// fields via AssignSlugNames (the slug becomes durable on the next
// write). Returns nil, nil when no config exists.
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
		services[i].Host, services[i].Path, services[i].Port = broker.SplitInlineHost(services[i].Host, services[i].Path)
	}
	broker.AssignSlugNames(services)
	return services, nil
}

// resolveServiceRef looks up a service by name first, then by host.
// Returns ambiguous host matches as candidates (ok=false) for the
// caller to surface as 409.
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

// candidateRef is the 409-body entry callers pick from to retry. Host
// is in joined inline form (`slack.com/api/*`).
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

// handleServicesCredentialUsage returns {name, host} for every service
// referencing the given credential key. Gated at proxy+ deliberately:
// /discover already exposes the same data to the same role, so member+
// gating here would only create asymmetry.
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

	// SQLite serializes statements but not the load → validate → save
	// sequence; without this lock concurrent upserts can both pass the
	// duplicate-name check against the same pre-state.
	defer s.lockVaultServices(ns.ID)()

	existing, err := s.loadServices(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to parse services")
		return
	}

	incomingSlice := splitInlineHosts(req.Services)
	// rebindStale=false: direct admin upsert must not silently rewrite a
	// caller-supplied Name onto a different existing entry.
	adoptByHost(incomingSlice, existing, false)

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

// handleServicePatch updates a single service via name-or-host
// reference. Only `enabled` is patchable; all other fields change via
// the POST/PUT upsert/set flow so auth validation has one code path.
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
	services = splitInlineHosts(services)
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

	defer s.lockVaultServices(ns.ID)()

	if _, err := s.store.SetBrokerConfig(ctx, ns.ID, "[]"); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to clear services")
		return
	}

	jsonOK(w, map[string]interface{}{"vault": name, "cleared": true})
}

func (s *Server) handleServiceCatalog(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]interface{}{"services": catalog.GetAll()})
}

// SetSkills sets the embedded skill content.
func (s *Server) SetSkills(cli string) {
	s.skillCLI = []byte(cli)
}

func (s *Server) handleSkillCLI(w http.ResponseWriter, r *http.Request) {
	s.serveSkill(w, r, s.skillCLI)
}

func (s *Server) serveSkill(w http.ResponseWriter, r *http.Request, content []byte) {
	if len(content) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	_, _ = w.Write(content)
}
