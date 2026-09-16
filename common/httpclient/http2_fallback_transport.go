package httpclient

import (
	"context"
	stdTLS "crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

var errHTTP2Fallback = E.New("fallback to HTTP/1.1")

type http2FallbackTransport struct {
	h2Transport       *http2.Transport
	h1Transport       *http1Transport
	fallbackAccess    sync.RWMutex
	fallbackAuthority map[string]struct{}
	maxFallback       int
}

func newHTTP2FallbackTransport(rawDialer N.Dialer, baseTLSConfig tls.Config, options option.HTTP2Options) (*http2FallbackTransport, error) {
	h1 := newHTTP1Transport(rawDialer, baseTLSConfig, time.Duration(options.IdleTimeout))
	h2Transport, err := ConfigureHTTP2Transport(options)
	if err != nil {
		return nil, err
	}
	h2Transport.DialTLSContext = func(ctx context.Context, network, addr string, _ *stdTLS.Config) (net.Conn, error) {
		return dialTLS(ctx, rawDialer, baseTLSConfig, M.ParseSocksaddr(addr), []string{http2.NextProtoTLS, "http/1.1"}, http2.NextProtoTLS)
	}
	return &http2FallbackTransport{
		h2Transport:       h2Transport,
		h1Transport:       h1,
		fallbackAuthority: make(map[string]struct{}),
		maxFallback:       256,
	}, nil
}

func (t *http2FallbackTransport) isH2Fallback(authority string) bool {
	if authority == "" {
		return false
	}
	t.fallbackAccess.RLock()
	_, found := t.fallbackAuthority[authority]
	t.fallbackAccess.RUnlock()
	return found
}

func (t *http2FallbackTransport) markH2Fallback(authority string) {
	if authority == "" {
		return
	}
	t.fallbackAccess.Lock()
	if _, found := t.fallbackAuthority[authority]; !found && t.maxFallback > 0 && len(t.fallbackAuthority) >= t.maxFallback {
		// ALPN capability is stable enough to cache, but a long-lived process
		// must not retain an unbounded host set from dynamic endpoints. Any entry
		// can be probed again safely when the small cache reaches its limit.
		for cachedAuthority := range t.fallbackAuthority {
			delete(t.fallbackAuthority, cachedAuthority)
			break
		}
	}
	t.fallbackAuthority[authority] = struct{}{}
	t.fallbackAccess.Unlock()
}

func (t *http2FallbackTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return t.roundTrip(request, true)
}

func (t *http2FallbackTransport) roundTrip(request *http.Request, allowHTTP1Fallback bool) (*http.Response, error) {
	if request.URL.Scheme != "https" || requestRequiresHTTP1(request) {
		return t.h1Transport.RoundTrip(request)
	}
	authority := requestAuthority(request)
	if t.isH2Fallback(authority) {
		if !allowHTTP1Fallback {
			return nil, errHTTP2Fallback
		}
		return t.h1Transport.RoundTrip(request)
	}
	response, err := t.h2Transport.RoundTrip(request)
	if err == nil {
		return response, nil
	}
	if !errors.Is(err, errHTTP2Fallback) || !allowHTTP1Fallback {
		return nil, err
	}
	t.markH2Fallback(authority)
	// TLS/ALPN fallback can occur after request bytes have been accepted by a
	// peer. Preserve non-idempotent requests unless the caller opted into an
	// idempotency-key protected retry.
	if !requestReplayable(request) {
		return nil, err
	}
	return t.h1Transport.RoundTrip(cloneRequestForRetry(request))
}

func (t *http2FallbackTransport) CloseIdleConnections() {
	t.h1Transport.CloseIdleConnections()
	t.h2Transport.CloseIdleConnections()
}

func (t *http2FallbackTransport) Close() error {
	t.CloseIdleConnections()
	return nil
}
