package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/egress"
	"github.com/Infisical/agent-vault/internal/store"
)

// --- Admin API: instance-level upstream (egress) proxy profiles ---
//
// Profiles are referenced by name from service rules and resolved per request
// by upstreamProxyResolver. Credentials are encrypted immediately on write and
// never returned by any read endpoint.

type createUpstreamProxyRequest struct {
	Name       string `json:"name"`
	Scheme     string `json:"scheme"`
	Host       string `json:"host"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	NoProxy    string `json:"no_proxy"`
	ProxyCAPEM string `json:"proxy_ca_pem"`
	OnFailure  string `json:"on_failure"`
	IsDefault  bool   `json:"is_default"`
	Enabled    *bool  `json:"enabled"`
}

type updateUpstreamProxyRequest struct {
	Scheme     *string `json:"scheme"`
	Host       *string `json:"host"`
	Username   *string `json:"username"`
	Password   *string `json:"password"`
	ClearAuth  bool    `json:"clear_auth"`
	NoProxy    *string `json:"no_proxy"`
	ProxyCAPEM *string `json:"proxy_ca_pem"`
	OnFailure  *string `json:"on_failure"`
	IsDefault  *bool   `json:"is_default"`
	Enabled    *bool   `json:"enabled"`
}

// proxyView is the API shape of a profile. It deliberately carries no secret
// material: clients learn whether credentials exist, never what they are.
type proxyView struct {
	Name      string `json:"name"`
	Scheme    string `json:"scheme"`
	Host      string `json:"host"`
	HasAuth   bool   `json:"has_auth"`
	NoProxy   string `json:"no_proxy"`
	HasCA     bool   `json:"has_ca"`
	OnFailure string `json:"on_failure"`
	IsDefault bool   `json:"is_default"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func (s *Server) viewProxy(p *store.UpstreamProxy) proxyView {
	return proxyView{
		Name:      p.Name,
		Scheme:    p.Scheme,
		Host:      p.Host,
		HasAuth:   s.proxyHasAuth(p),
		NoProxy:   p.NoProxy,
		HasCA:     strings.TrimSpace(p.ProxyCAPEM) != "",
		OnFailure: p.OnFailure,
		IsDefault: p.IsDefault,
		Enabled:   p.Enabled,
		CreatedAt: p.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		UpdatedAt: p.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

func (s *Server) proxyHasAuth(p *store.UpstreamProxy) bool {
	if len(p.UsernameCT) > 0 {
		username, err := crypto.Decrypt(p.UsernameCT, p.UsernameNonce, s.encKey)
		if err == nil {
			hasAuth := len(username) > 0
			crypto.WipeBytes(username)
			if hasAuth {
				return true
			}
		}
	}
	if len(p.PasswordCT) > 0 {
		password, err := crypto.Decrypt(p.PasswordCT, p.PasswordNonce, s.encKey)
		if err == nil {
			hasAuth := len(password) > 0
			crypto.WipeBytes(password)
			return hasAuth
		}
	}
	return false
}

func (s *Server) handleListUpstreamProxies(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwnerActor(w, r); err != nil {
		return
	}
	proxies, err := s.store.ListUpstreamProxies(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list upstream proxies")
		return
	}
	views := make([]proxyView, 0, len(proxies))
	for i := range proxies {
		views = append(views, s.viewProxy(&proxies[i]))
	}
	jsonOK(w, map[string]interface{}{"proxies": views})
}

func (s *Server) handleCreateUpstreamProxy(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwnerActor(w, r); err != nil {
		return
	}

	var req createUpstreamProxyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		jsonError(w, http.StatusBadRequest, "name is required")
		return
	}
	if err := broker.ValidateUpstreamProxyName(req.Name); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Scheme = strings.ToLower(strings.TrimSpace(req.Scheme))
	if !brokercore.IsValidUpstreamProxyScheme(req.Scheme) {
		jsonError(w, http.StatusBadRequest, "scheme must be one of: http, https, socks5, socks5h")
		return
	}
	if !brokercore.IsValidUpstreamProxyFailure(req.OnFailure) {
		jsonError(w, http.StatusBadRequest, "on_failure must be one of: fail_closed, fail_open")
		return
	}
	if err := validateProxyEndpoint(req.Host); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := egress.ValidateProxyCAPEM(req.ProxyCAPEM); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	p := &store.UpstreamProxy{
		Name:       req.Name,
		Scheme:     req.Scheme,
		Host:       req.Host,
		NoProxy:    req.NoProxy,
		ProxyCAPEM: req.ProxyCAPEM,
		OnFailure:  req.OnFailure,
		IsDefault:  req.IsDefault,
		Enabled:    true,
	}
	if req.Enabled != nil {
		p.Enabled = *req.Enabled
	}
	if req.Username != "" {
		uct, unonce, err := crypto.Encrypt([]byte(req.Username), s.encKey)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Encryption failed")
			return
		}
		p.UsernameCT, p.UsernameNonce = uct, unonce
	}
	if req.Password != "" {
		ct, nonce, err := crypto.Encrypt([]byte(req.Password), s.encKey)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Encryption failed")
			return
		}
		p.PasswordCT, p.PasswordNonce = ct, nonce
	}

	if err := s.store.CreateUpstreamProxy(r.Context(), p); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			jsonError(w, http.StatusConflict, fmt.Sprintf("Upstream proxy %q already exists", req.Name))
			return
		}
		jsonError(w, http.StatusInternalServerError, "Failed to create upstream proxy")
		return
	}

	created, err := s.store.GetUpstreamProxyByName(r.Context(), req.Name)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to load upstream proxy")
		return
	}
	s.invalidateUpstreamProxyCache()
	jsonCreated(w, map[string]interface{}{"proxy": s.viewProxy(created)})
}

func (s *Server) handleGetUpstreamProxy(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwnerActor(w, r); err != nil {
		return
	}
	p, err := s.store.GetUpstreamProxyByName(r.Context(), r.PathValue("name"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "Upstream proxy not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, "Failed to load upstream proxy")
		return
	}
	jsonOK(w, map[string]interface{}{"proxy": s.viewProxy(p)})
}

func (s *Server) handleUpdateUpstreamProxy(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwnerActor(w, r); err != nil {
		return
	}

	name := r.PathValue("name")
	if _, err := s.store.GetUpstreamProxyByName(r.Context(), name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "Upstream proxy not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, "Failed to load upstream proxy")
		return
	}

	var req updateUpstreamProxyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	params := store.UpdateUpstreamProxyParams{Name: name}
	if req.Scheme != nil {
		scheme := strings.ToLower(strings.TrimSpace(*req.Scheme))
		if !brokercore.IsValidUpstreamProxyScheme(scheme) {
			jsonError(w, http.StatusBadRequest, "scheme must be one of: http, https, socks5, socks5h")
			return
		}
		params.Scheme = &scheme
	}
	if req.Host != nil {
		if err := validateProxyEndpoint(*req.Host); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		params.Host = req.Host
	}
	if req.NoProxy != nil {
		params.NoProxy = req.NoProxy
	}
	if req.ProxyCAPEM != nil {
		if err := egress.ValidateProxyCAPEM(*req.ProxyCAPEM); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		params.ProxyCAPEM = req.ProxyCAPEM
	}
	if req.OnFailure != nil {
		if !brokercore.IsValidUpstreamProxyFailure(*req.OnFailure) {
			jsonError(w, http.StatusBadRequest, "on_failure must be one of: fail_closed, fail_open")
			return
		}
		params.OnFailure = req.OnFailure
	}
	if req.IsDefault != nil {
		params.IsDefault = req.IsDefault
	}
	if req.Enabled != nil {
		params.Enabled = req.Enabled
	}
	if req.ClearAuth {
		var nilBytes []byte
		params.UsernameCT, params.UsernameNonce = &nilBytes, &nilBytes
		params.PasswordCT, params.PasswordNonce = &nilBytes, &nilBytes
	} else {
		if req.Username != nil {
			if *req.Username == "" {
				var nilBytes []byte
				params.UsernameCT, params.UsernameNonce = &nilBytes, &nilBytes
			} else {
				uct, unonce, err := crypto.Encrypt([]byte(*req.Username), s.encKey)
				if err != nil {
					jsonError(w, http.StatusInternalServerError, "Encryption failed")
					return
				}
				params.UsernameCT, params.UsernameNonce = &uct, &unonce
			}
		}
		if req.Password != nil {
			if *req.Password == "" {
				var nilBytes []byte
				params.PasswordCT, params.PasswordNonce = &nilBytes, &nilBytes
			} else {
				ct, nonce, err := crypto.Encrypt([]byte(*req.Password), s.encKey)
				if err != nil {
					jsonError(w, http.StatusInternalServerError, "Encryption failed")
					return
				}
				params.PasswordCT, params.PasswordNonce = &ct, &nonce
			}
		}
	}
	updated, err := s.store.UpdateUpstreamProxy(r.Context(), params)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "Upstream proxy not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, "Failed to update upstream proxy")
		return
	}
	s.invalidateUpstreamProxyCache()
	jsonOK(w, map[string]interface{}{"proxy": s.viewProxy(updated)})
}

func validateProxyEndpoint(host string) error {
	if err := egress.ValidateHost(host); err != nil {
		return err
	}
	_, port, _ := net.SplitHostPort(host)
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("egress: upstream proxy port must be between 1 and 65535")
	}
	return nil
}

func (s *Server) handleDeleteUpstreamProxy(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwnerActor(w, r); err != nil {
		return
	}

	name := r.PathValue("name")
	ctx := r.Context()

	if err := s.store.DeleteUpstreamProxy(ctx, name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "Upstream proxy not found")
			return
		}
		var referenced *store.UpstreamProxyReferencedError
		if errors.As(err, &referenced) {
			jsonError(w, http.StatusConflict,
				fmt.Sprintf("Upstream proxy %q is referenced by %d service(s): %s", referenced.Name, len(referenced.References), strings.Join(referenced.References, ", ")))
			return
		}
		jsonError(w, http.StatusInternalServerError, "Failed to delete upstream proxy")
		return
	}
	s.invalidateUpstreamProxyCache()
	jsonOK(w, map[string]string{"status": "deleted", "name": name})
}
