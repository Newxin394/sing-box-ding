package http

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

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
