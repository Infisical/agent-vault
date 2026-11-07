package mitm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/egress"
)

// upstreamRoute is the per-request answer to "how do I reach this upstream?".
// The zero-ish value returned when nothing is configured carries the proxy's
// baseline transport, which is exactly the behaviour that existed before
// egress proxies did.
type upstreamRoute struct {
	transport *http.Transport
	// tunnel is non-nil only when the route goes through a proxy, and only
	// WebSocket upgrades use it: a hijacked connection needs the raw
	// tunneled net.Conn rather than anything net/http can RoundTrip.
	tunnel  egress.TunnelDialer
	profile *brokercore.UpstreamProxy
}

// routeFor resolves the egress route for one brokered request. host is the
// upstream address in host:port form and is used for NO_PROXY matching.
//
// Errors from resolution and construction are closed failures; only an
// explicit nil profile selects the baseline direct transport.
func (p *Proxy) routeFor(ctx context.Context, vaultID, serviceName, host string) (upstreamRoute, error) {
	direct := upstreamRoute{transport: p.upstream}
	if p.upstreamRes == nil {
		return direct, nil
	}
	if p.egress == nil {
		return upstreamRoute{}, fmt.Errorf("upstream proxy registry is unavailable")
	}

	profile, err := p.upstreamRes.ResolveUpstreamProxy(ctx, vaultID, serviceName)
	if err != nil {
		p.logger.Warn("upstream proxy resolution failed",
			slog.String("vault_id", vaultID),
			slog.String("service", serviceName),
			slog.String("error", err.Error()))
		return upstreamRoute{}, fmt.Errorf("upstream proxy resolution failed")
	}
	if profile == nil {
		return direct, nil
	}
	if egress.Bypass(profile.NoProxy, host) {
		p.logger.Debug("request bypasses upstream proxy (no_proxy)",
			slog.String("host", host),
			slog.String("profile", profile.Name))
		return direct, nil
	}

	transport, transportErr := p.egress.Transport(profile)
	tunnel, tunnelErr := p.egress.Tunnel(profile)
	if transportErr != nil || tunnelErr != nil {
		buildErr := transportErr
		if buildErr == nil {
			buildErr = tunnelErr
		}
		p.logger.Warn("upstream proxy profile is unusable",
			slog.String("profile", profile.Name),
			slog.String("scheme", profile.Scheme),
			slog.String("error", buildErr.Error()))
		return upstreamRoute{}, fmt.Errorf("upstream proxy %q is unusable", profile.Name)
	}

	p.logger.Debug("routing request through upstream proxy",
		slog.String("host", host),
		slog.String("profile", profile.Name),
		slog.String("scheme", profile.Scheme))

	return upstreamRoute{transport: transport, tunnel: tunnel, profile: profile}, nil
}

func (p *Proxy) roundTrip(outReq *http.Request, route upstreamRoute, target string) (*http.Response, error) {
	return egress.RoundTripWithFallback(outReq, route.profile, route.transport, p.upstream, p.logger)
}

// dial opens the next hop for a hijacked connection (WebSocket upgrades),
// applying the same fail_open policy as roundTrip: a proxy that cannot be
// reached is swapped for the baseline direct dial, everything else is
// returned as-is.
func (p *Proxy) dial(ctx context.Context, addr string, route upstreamRoute, transport *http.Transport) (net.Conn, error) {
	dialCtx := transport.DialContext
	if route.tunnel != nil {
		dialCtx = route.tunnel
	}
	if dialCtx == nil {
		dialer := &net.Dialer{}
		dialCtx = dialer.DialContext
	}

	conn, err := dialCtx(ctx, "tcp", addr)
	if err == nil || route.tunnel == nil || route.profile == nil {
		return conn, err
	}
	if route.profile.FailureMode() != brokercore.UpstreamProxyFailOpen ||
		!errors.Is(err, egress.ErrProxyUnreachable) || ctx.Err() != nil {
		return conn, err
	}

	p.logger.Warn("egress proxy unreachable; dialling upstream directly under fail_open",
		slog.String("profile", route.profile.Name),
		slog.String("target", addr),
		slog.String("host", route.profile.Host),
		slog.String("error", err.Error()))
	if transport.DialContext != nil {
		return transport.DialContext(ctx, "tcp", addr)
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
}
