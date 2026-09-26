package http

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	sHTTP "github.com/sagernet/sing/protocol/http"
)

func TestOrdinaryHTTPHasNativeUDPButWithAtKeepsHTTP1Only(t *testing.T) {
	ctx := context.Background()
	factory := log.NewNOPFactory()
	ordinary, err := NewOutbound(ctx, nil, factory.NewLogger("ordinary"), "ordinary", option.HTTPOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 8080},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ordinary.(*Outbound).nativeClient == nil {
		t.Fatal("ordinary HTTP did not use official native client")
	}
	if !common.Contains(ordinary.Network(), N.NetworkUDP) {
		t.Fatalf("ordinary HTTP should advertise native UDP, got %v", ordinary.Network())
	}
	withAt, err := NewOutbound(ctx, nil, factory.NewLogger("with-at"), "with-at", option.HTTPOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 8080},
		Headers:       badoption.HTTPHeader{"With-At": badoption.Listable[string]{"gw.example"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if withAt.(*Outbound).nativeClient != nil {
		t.Fatal("With-At must retain the dedicated HTTP/1 path")
	}
	if common.Contains(withAt.Network(), N.NetworkUDP) {
		t.Fatalf("With-At without explicit UDP delegate must remain TCP-only, got %v", withAt.Network())
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
	// Native HTTP now supports UDP itself; the explicit delegate remains an override.
	o2, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().NewLogger("http"), "test2", option.HTTPOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 8080},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !common.Contains(o2.Network(), N.NetworkUDP) {
		t.Fatalf("native HTTP must advertise UDP, got %v", o2.Network())
	}
}
