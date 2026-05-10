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
		svc.Host, svc.Path = broker.SplitInlineHost(svc.Host, svc.Path)
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

// normalizeProposalServices splits inline-form host on every entry,
// resolves ActionDelete-by-host targets against the current vault
// state, and auto-slugs ActionSet entries that omit Name.
//
// ActionDelete without Name: resolve against existing services by Host
// (and Path when inline-form scoped). Unique match fills Name; 2+ →
// *hostAmbiguityError; 0 → *hostNotFoundError.
//
// ActionSet without Name: filled via broker.Slugify(host, path), with
// disambiguation against other ActionSet entries in the same proposal.
// Names already present in `existing` are deliberately NOT reserved —
// an empty-name set whose slug matches an existing service applies as
// an in-place replace, which is the natural upsert semantics.
func normalizeProposalServices(in []proposal.Service, existing []broker.Service) ([]proposal.Service, error) {
	out := make([]proposal.Service, len(in))

	// Track ActionSet slugs assigned so far so two empty-name sets in
	// the same proposal get distinct names.
	setNames := make(map[string]bool)
	for _, svc := range in {
		if svc.Action == proposal.ActionSet && svc.Name != "" {
			setNames[svc.Name] = true
		}
	}

	for i, svc := range in {
		svc.Host, svc.Path = broker.SplitInlineHost(svc.Host, svc.Path)

		switch {
		case svc.Action == proposal.ActionDelete && svc.Name == "":
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
		case svc.Action == proposal.ActionSet && svc.Name == "" && svc.Host != "":
			base := broker.Slugify(svc.Host, svc.Path)
			name := base
			for n := 2; setNames[name]; n++ {
				suffix := fmt.Sprintf("-%d", n)
				trunc := base
				if len(trunc)+len(suffix) > 64 {
					trunc = trunc[:64-len(suffix)]
					for len(trunc) > 0 && trunc[len(trunc)-1] == '-' {
						trunc = trunc[:len(trunc)-1]
					}
				}
				name = trunc + suffix
			}
			svc.Name = name
			setNames[name] = true
		}
		out[i] = svc
	}
	return out, nil
}

// loadServices reads the vault's broker config and splits inline-form
// Host on every entry so the matcher invariant holds. Missing Name
// fields are filled via broker.AssignSlugNames so legacy services
// persisted before Name became required heal lazily on read — the
// backfilled name becomes durable the next time the caller writes the
// list back. Returns nil, nil when no config exists.
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
	broker.AssignSlugNames(services, nil)
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

	// Auto-slug empty Name entries from host+path. Existing names are
	// NOT reserved so an empty-name upsert whose slug matches an
	// existing service acts as an in-place replace — that's the natural
	// expectation for an upsert keyed by stable identity.
	broker.AssignSlugNames(incomingSlice, nil)

	// Validate incoming services. broker.Validate enforces that Name is
	// non-empty; AssignSlugNames has filled any blanks above.
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
	// Auto-slug empty Name entries from host+path. The PUT replaces the
	// full set, so there's nothing pre-existing to reserve against.
	broker.AssignSlugNames(services, nil)
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
