package server

import (
	"encoding/json"
	"net/http"

	"github.com/Infisical/agent-vault/internal/broker"
)

type discoverService struct {
	Host        string  `json:"host"`
	Description *string `json:"description"`
}

type discoverResponse struct {
	Vault                string            `json:"vault"`
	ProxyURL             string            `json:"proxy_url"`
	Services             []discoverService `json:"services"`
	AvailableCredentials []string          `json:"available_credentials"`
}

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Require scoped session or agent token with X-Vault.
	sess := sessionFromContext(ctx)
	if sess == nil {
		proxyError(w, http.StatusForbidden, "forbidden", "Discovery requires a vault-scoped session")
		return
	}

	ns, _, err := s.resolveVaultForSession(w, r, sess)
	if err != nil {
		return
	}

	credentialKeys := s.listCredentialKeys(ctx, ns.ID)

	// Load broker config for this vault.
	brokerCfg, err := s.store.GetBrokerConfig(ctx, ns.ID)
	if err != nil || brokerCfg == nil {
		// No config means no services — return empty list.
		jsonOK(w, discoverResponse{
			Vault:                ns.Name,
			ProxyURL:             s.baseURL + "/proxy",
			Services:             []discoverService{},
			AvailableCredentials: credentialKeys,
		})
		return
	}

	var svcList []broker.Service
	if err := json.Unmarshal([]byte(brokerCfg.ServicesJSON), &svcList); err != nil {
		proxyError(w, http.StatusInternalServerError, "internal", "Failed to parse broker services")
		return
	}

	services := make([]discoverService, len(svcList))
	for i, svc := range svcList {
		services[i] = discoverService{
			Host:        svc.Host,
			Description: svc.Description,
		}
	}

	jsonOK(w, discoverResponse{
		Vault:                ns.Name,
		ProxyURL:             s.baseURL + "/proxy",
		Services:             services,
		AvailableCredentials: credentialKeys,
	})
}
