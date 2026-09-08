package httpclient

import (
	"context"
	stdTLS "crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/net/http2"
)

func TestHTTP2FallbackAuthorityIsolation(t *testing.T) {
	transport := &http2FallbackTransport{fallbackAuthority: make(map[string]struct{})}

	transport.markH2Fallback("a.example:443")
	if !transport.isH2Fallback("a.example:443") {
		t.Fatal("a.example:443 should be marked")
	}
	if transport.isH2Fallback("b.example:443") {
		t.Fatal("b.example:443 must remain unmarked after marking a.example")
	}

	transport.markH2Fallback("b.example:443")
	if !transport.isH2Fallback("b.example:443") {
		t.Fatal("b.example:443 should be marked after explicit mark")
	}
	if !transport.isH2Fallback("a.example:443") {
		t.Fatal("a.example:443 mark must survive marking another authority")
	}
}

func TestHTTP2FallbackDoesNotReplayNonIdempotentRequest(t *testing.T) {
	transport := &http2FallbackTransport{
		h2Transport: &http2.Transport{
			DialTLSContext: func(context.Context, string, string, *stdTLS.Config) (net.Conn, error) {
				return nil, errHTTP2Fallback
			},
		},
		fallbackAuthority: make(map[string]struct{}),
	}
	request, err := http.NewRequest(http.MethodPost, "https://example.com/", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.RoundTrip(request)
	if response != nil {
		t.Fatal("non-idempotent request must not be replayed through HTTP/1.1")
	}
	if !errors.Is(err, errHTTP2Fallback) {
		t.Fatalf("got %v, want HTTP/2 fallback error", err)
	}
}

func TestHTTP2FallbackEmptyAuthorityNoOp(t *testing.T) {
	transport := &http2FallbackTransport{fallbackAuthority: make(map[string]struct{})}

	transport.markH2Fallback("")
	if len(transport.fallbackAuthority) != 0 {
		t.Fatalf("empty authority must not be stored, got %d entries", len(transport.fallbackAuthority))
	}
	if transport.isH2Fallback("") {
		t.Fatal("isH2Fallback must be false for empty authority")
	}
}

func TestHTTP2FallbackCacheIsBounded(t *testing.T) {
	transport := &http2FallbackTransport{
		fallbackAuthority: map[string]struct{}{
			"old.example:443": {},
			"new.example:443": {},
		},
		maxFallback: 2,
	}
	transport.markH2Fallback("latest.example:443")
	if len(transport.fallbackAuthority) != 2 {
		t.Fatalf("fallback cache must remain bounded, got %d entries", len(transport.fallbackAuthority))
	}
	if _, found := transport.fallbackAuthority["latest.example:443"]; !found {
		t.Fatal("latest fallback authority must be retained")
	}
}
