package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/catalog"
)

// buildServiceList returns the services array for a vault (reused by discover and invite redeem).
func (s *Server) buildServiceList(ctx context.Context, vaultID string) []discoverService {
	brokerCfg, err := s.store.GetBrokerConfig(ctx, vaultID)
	if err != nil || brokerCfg == nil {
		return []discoverService{}
	}

	var svcList []broker.Service
	if err := json.Unmarshal([]byte(brokerCfg.ServicesJSON), &svcList); err != nil {
		return []discoverService{}
	}

	services := make([]discoverService, len(svcList))
	for i, svc := range svcList {
		services[i] = discoverService{
			Host:        svc.Host,
			Description: svc.Description,
		}
	}
	return services
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

	bc, err := s.store.GetBrokerConfig(ctx, ns.ID)
	if err != nil || bc == nil {
		// No services set — return empty services.
		jsonOK(w, map[string]interface{}{"vault": name, "services": []interface{}{}})
		return
	}

	var services json.RawMessage
	if err := json.Unmarshal([]byte(bc.ServicesJSON), &services); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to parse services")
		return
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

	bc, err := s.store.GetBrokerConfig(ctx, ns.ID)
	if err != nil || bc == nil {
		jsonOK(w, map[string]interface{}{"services": []interface{}{}})
		return
	}

	var services []broker.Service
	if err := json.Unmarshal([]byte(bc.ServicesJSON), &services); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to parse services")
		return
	}

	type serviceRef struct {
		Host        string `json:"host"`
		Description string `json:"description,omitempty"`
	}
	var refs []serviceRef
	for _, svc := range services {
		for _, sk := range svc.Auth.CredentialKeys() {
			if sk == key {
				ref := serviceRef{Host: svc.Host}
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
