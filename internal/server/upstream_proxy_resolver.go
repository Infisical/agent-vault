package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/egress"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/store"
)

// upstreamProxyCacheTTL bounds how long a resolved route is remembered. Most
// requests for the same service arrive in bursts, so this turns a burst into
// one lookup while keeping operator edits (which invalidate the cache
// explicitly) visible within seconds even if invalidation is missed.
const upstreamProxyCacheTTL = 5 * time.Second

// upstreamProxyResolver resolves the egress proxy for a single brokered
// request. A newly created service routes directly unless its operator
// selects the instance default or names a profile. Older services with no
// egress selection still inherit the default. Unmatched and control-plane
// traffic also use the instance default.
//
// Nothing here is request-specific beyond the vault and matched service name,
// so results are cached briefly; see upstreamProxyCacheTTL.
type upstreamProxyResolver struct {
	s *Server

	mu         sync.RWMutex
	cache      map[string]cachedUpstreamProxy
	generation uint64
}

type cachedUpstreamProxy struct {
	proxy     *brokercore.UpstreamProxy
	expiresAt time.Time
}

// UpstreamProxyResolver returns the resolver injected into the MITM proxy. It
// stays live for the server's lifetime so profile edits take effect without a
// restart.
func (s *Server) UpstreamProxyResolver() brokercore.UpstreamProxyResolver {
	if s.upstreamRes == nil {
		s.upstreamRes = &upstreamProxyResolver{s: s, cache: make(map[string]cachedUpstreamProxy)}
	}
	return s.upstreamRes
}

// invalidateUpstreamProxyCache drops cached resolutions. Called after any
// administrative change so an edit applies to the very next request.
func (s *Server) invalidateUpstreamProxyCache() {
	if s.upstreamRes == nil {
		return
	}
	s.upstreamRes.mu.Lock()
	s.upstreamRes.generation++
	s.upstreamRes.cache = make(map[string]cachedUpstreamProxy)
	s.upstreamRes.mu.Unlock()
}

func (r *upstreamProxyResolver) ResolveUpstreamProxy(ctx context.Context, vaultID, serviceName string) (*brokercore.UpstreamProxy, error) {
	key := vaultID + "|" + serviceName
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r.mu.RLock()
		generation := r.generation
		if cached, ok := r.cache[key]; ok && time.Now().Before(cached.expiresAt) {
			r.mu.RUnlock()
			return cached.proxy, nil
		}
		r.mu.RUnlock()

		proxy, err := r.resolve(ctx, vaultID, serviceName)
		r.mu.Lock()
		if generation != r.generation {
			r.mu.Unlock()
			continue
		}
		if err == nil && ctx.Err() == nil {
			r.cache[key] = cachedUpstreamProxy{proxy: proxy, expiresAt: time.Now().Add(upstreamProxyCacheTTL)}
		}
		r.mu.Unlock()
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return proxy, nil
	}
}

func (r *upstreamProxyResolver) resolve(ctx context.Context, vaultID, serviceName string) (*brokercore.UpstreamProxy, error) {
	// 1. A matched service can select direct before any default.
	if serviceName != "" {
		name, bypass, err := r.serviceProxyRoute(ctx, vaultID, serviceName)
		if err != nil {
			return nil, err
		}
		if bypass {
			return nil, nil
		}
		if name != "" {
			p, err := r.s.store.GetUpstreamProxyByName(ctx, name)
			switch {
			case err == nil && p.Enabled:
				return r.toProfile(ctx, p)
			case errors.Is(err, sql.ErrNoRows):
				r.s.logger.Warn("service references a missing upstream proxy; falling back to instance default",
					slog.String("vault_id", vaultID),
					slog.String("service", serviceName),
					slog.String("profile", name))
			case err != nil:
				return nil, err
			default:
				// Profile exists but is disabled: honour the kill switch.
				r.s.logger.Warn("service references a disabled upstream proxy; falling back to instance default",
					slog.String("vault_id", vaultID),
					slog.String("service", serviceName),
					slog.String("profile", name))
			}
		}
	}

	// 2. Instance-level default covers control-plane and unmatched traffic,
	//    explicitly opted-in services, and older services with no selection.
	def, err := r.s.store.GetDefaultUpstreamProxy(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return r.toProfile(ctx, def)
}

// serviceProxyRoute finds the egress choice for a named service. It reads the
// vault's broker config the same way the service handlers do, so there is
// exactly one interpretation of "the services for this vault".
func (r *upstreamProxyResolver) serviceProxyRoute(ctx context.Context, vaultID, serviceName string) (string, bool, error) {
	bc, err := r.s.store.GetBrokerConfig(ctx, vaultID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	if bc == nil || bc.ServicesJSON == "" {
		return "", false, nil
	}
	var services []broker.Service
	if err := json.Unmarshal([]byte(bc.ServicesJSON), &services); err != nil {
		return "", false, err
	}
	for _, svc := range services {
		if svc.Name == serviceName {
			if (svc.BypassUpstreamProxy && (svc.UpstreamProxy != "" || svc.UseUpstreamProxy)) ||
				(svc.UseUpstreamProxy && svc.UpstreamProxy != "") {
				return "", false, errors.New("stored service has conflicting upstream proxy settings")
			}
			return svc.UpstreamProxy, svc.BypassUpstreamProxy, nil
		}
	}
	return "", false, nil
}

// toProfile decrypts stored proxy credentials into the runtime profile. The
// plaintext exists only in memory and only long enough to open a socket.
func (r *upstreamProxyResolver) toProfile(ctx context.Context, p *store.UpstreamProxy) (*brokercore.UpstreamProxy, error) {
	_ = ctx
	profile := &brokercore.UpstreamProxy{
		Name:       p.Name,
		Scheme:     p.Scheme,
		Host:       p.Host,
		NoProxy:    p.NoProxy,
		ProxyCAPEM: p.ProxyCAPEM,
		OnFailure:  p.OnFailure,
	}
	if len(p.UsernameCT) > 0 {
		user, err := crypto.Decrypt(p.UsernameCT, p.UsernameNonce, r.s.encKey)
		if err != nil {
			return nil, err
		}
		profile.Username = string(user)
		crypto.WipeBytes(user)
	}
	if len(p.PasswordCT) > 0 {
		pass, err := crypto.Decrypt(p.PasswordCT, p.PasswordNonce, r.s.encKey)
		if err != nil {
			return nil, err
		}
		profile.Password = string(pass)
		crypto.WipeBytes(pass)
	}
	return profile, nil
}

// --- Control-plane egress ---
//
// Requests the server makes on its own behalf (OAuth token exchanges, SMTP
// notifications, external secret-store syncs) are not brokered services, so
// there is no matched service to consult: they always use the instance
// default profile. They still route through the same egress machinery so an
// operator's "everything leaves through this proxy" promise holds for the
// whole process.

// egressRoundTripper picks a transport per request from the instance default
// profile. Without a default profile every request uses the caller's base
// transport, which keeps today's behaviour for operators who configure
// nothing.
type egressRoundTripper struct {
	base     *http.Transport
	resolver brokercore.UpstreamProxyResolver
	registry *egress.Registry
	logger   *slog.Logger
}

func (t *egressRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	profile, err := t.resolver.ResolveUpstreamProxy(req.Context(), "", "")
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	if profile == nil {
		return t.base.RoundTrip(req)
	}
	addr, err := egress.TargetAddr(req.URL)
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	if egress.Bypass(profile.NoProxy, addr) {
		return t.base.RoundTrip(req)
	}
	transport, err := t.registry.Transport(profile)
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	return egress.RoundTripWithFallback(req, profile, transport, t.base, t.logger)
}

// ControlPlaneRoundTripper wraps base so control-plane HTTP calls honour the
// instance default egress proxy.
func (s *Server) ControlPlaneRoundTripper(base *http.Transport) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport.(*http.Transport).Clone()
		base.DialContext = netguard.SafeDialContext(netguard.AllowPrivateFromEnv())
	}
	return &egressRoundTripper{
		base:     base,
		resolver: s.UpstreamProxyResolver(),
		registry: egress.NewRegistry(func() *http.Transport { return base.Clone() }, s.logger, true),
		logger:   s.logger,
	}
}

// controlPlaneEgress returns the registry shared by control-plane callers.
// Direct and proxied transports share the caller's tuning because each base
// transport is cloned on use.
func (s *Server) controlPlaneEgress() *egress.Registry {
	s.controlPlaneOnce.Do(func() {
		s.controlPlaneRegistry = egress.NewRegistry(func() *http.Transport {
			tr := http.DefaultTransport.(*http.Transport).Clone()
			tr.DialContext = netguard.SafeDialContext(netguard.AllowPrivateFromEnv())
			return tr
		}, s.logger, true)
	})
	return s.controlPlaneRegistry
}

// controlPlaneDial routes SMTP through the instance default, including HTTP
// CONNECT and SOCKS tunnels. Only proxy-hop unavailability permits fail-open.
func (s *Server) controlPlaneDial() func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		direct := func() (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
		}
		profile, err := s.UpstreamProxyResolver().ResolveUpstreamProxy(ctx, "", "")
		if err != nil {
			return nil, err
		}
		if profile == nil || egress.Bypass(profile.NoProxy, addr) {
			return direct()
		}
		tunnel, err := s.controlPlaneEgress().Tunnel(profile)
		if err != nil {
			return nil, err
		}
		conn, err := tunnel(ctx, network, addr)
		if err != nil && profile.FailureMode() == "fail_open" && errors.Is(err, egress.ErrProxyUnreachable) && ctx.Err() == nil {
			s.logger.Warn("SMTP egress proxy unreachable; dialling directly", slog.String("profile", profile.Name))
			return direct()
		}
		return conn, err
	}
}
