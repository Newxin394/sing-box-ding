package http

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	sHTTP "github.com/sagernet/sing/protocol/http"
)

func TestHTTPAndDingRejectUDPWithoutDelegate(t *testing.T) {
	ctx := context.Background()
	logger := log.NewNOPFactory().NewLogger("test")
	httpOutbound, err := NewOutbound(ctx, nil, logger, "http-test", option.HTTPOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 8080},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = httpOutbound.DialContext(ctx, "udp", M.ParseSocksaddr("example.com:443"))
	if err == nil || !strings.Contains(err.Error(), "UDP is not supported by outbound: http-test") {
		t.Fatalf("unexpected HTTP UDP error: %v", err)
	}

	ding := newDingClient(sHTTP.Options{Server: M.ParseSocksaddr("127.0.0.1:8080")}, "gw.example")
	_, err = ding.DialContext(ctx, "udp", M.ParseSocksaddr("example.com:443"))
	if err == nil || !strings.Contains(err.Error(), "UDP is not supported by ding-direct HTTP outbound") {
		t.Fatalf("unexpected ding UDP dial error: %v", err)
	}
	_, err = ding.ListenPacket(ctx, M.ParseSocksaddr("example.com:443"))
	if err == nil || !strings.Contains(err.Error(), "UDP is not supported by ding-direct HTTP outbound") {
		t.Fatalf("unexpected ding UDP packet error: %v", err)
	}
}

func TestOutboundAdvertisesUDPWhenDelegating(t *testing.T) {
	o, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().NewLogger("http"), "test", option.HTTPOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 8080},
		UDPOutbound:   "direct",
	})
	if err != nil {
		t.Fatal(err)
	}
	networks := o.Network()
	var hasTCP, hasUDP bool
	for _, n := range networks {
		if n == "tcp" {
			hasTCP = true
		}
		if n == "udp" {
			hasUDP = true
		}
	}
	if !hasTCP || !hasUDP {
		t.Fatalf("expected tcp+udp, got %v", networks)
	}
	// Without udp_outbound the outbound must still be TCP-only.
	o2, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().NewLogger("http"), "test2", option.HTTPOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 8080},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range o2.Network() {
		if n == "udp" {
			t.Fatal("http outbound without udp_outbound must not offer udp")
		}
	}
}
