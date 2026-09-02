package server

import (
	"fmt"
	"sort"

	"github.com/Infisical/agent-vault/internal/oauth"
)

// SetManagedOAuthProviders configures OAuth applications supplied by the
// instance operator. It must be called before the server starts.
func (s *Server) SetManagedOAuthProviders(providers []oauth.ManagedProvider) {
	s.managedOAuthProviders = make(map[string]oauth.ManagedProvider, len(providers))
	for _, provider := range providers {
		if provider.ID == "" {
			continue
		}
		s.managedOAuthProviders[provider.ID] = provider
	}
}

func (s *Server) managedOAuthProviderIDs() []string {
	ids := make([]string, 0, len(s.managedOAuthProviders))
	for id := range s.managedOAuthProviders {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (s *Server) applyManagedOAuthProvider(req *oauthConnectRequest) error {
	if req.Provider == "" {
		return nil
	}

	provider, ok := s.managedOAuthProviders[req.Provider]
	if !ok {
		return fmt.Errorf("managed OAuth provider %q is not configured", req.Provider)
	}

	req.AuthorizationURL = provider.AuthorizationURL
	req.TokenURL = provider.TokenURL
	req.ClientID = provider.ClientID
	req.ClientSecret = provider.ClientSecret
	req.TokenAuthMethod = provider.TokenAuthMethod
	return nil
}

func (s *Server) managedOAuthProviderForConfig(authorizationURL, tokenURL, clientID string) string {
	for _, id := range s.managedOAuthProviderIDs() {
		provider := s.managedOAuthProviders[id]
		if provider.AuthorizationURL == authorizationURL &&
			provider.TokenURL == tokenURL &&
			provider.ClientID == clientID {
			return id
		}
	}
	return ""
}
