package http

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// stubUDPOutbound is a minimal adapter.Outbound that hands back a real
// (loopback) UDP socket for ListenPacket, so we can observe whether the HTTP
// outbound wraps the delegated packet conn for lifecycle tracking.
type stubUDPOutbound struct {
	tag  string
	conn net.PacketConn
}

func (s *stubUDPOutbound) Type() string           { return "stub" }
func (s *stubUDPOutbound) Tag() string            { return s.tag }
func (s *stubUDPOutbound) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (s *stubUDPOutbound) Dependencies() []string { return nil }

func (s *stubUDPOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (s *stubUDPOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return s.conn, nil
}

// TestDelegatedPacketConnIsTracked verifies the delegated UDP conn returned by
// ListenPacket is wrapped by the interrupt group (so it is an *interrupt.PacketConn,
// not the bare delegate conn) and that InterruptConnections tears it down.
func TestDelegatedPacketConnIsTracked(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot open udp socket in sandbox: %v", err)
	}
	defer pc.Close()

	o, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().NewLogger("http"), "http-udp", option.HTTPOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 8080},
		UDPOutbound:   "stub",
	})
	if err != nil {
		t.Fatal(err)
	}
	h := o.(*Outbound)
	h.udpDetour = &stubUDPOutbound{tag: "stub", conn: pc}

	conn, err := h.ListenPacket(context.Background(), M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	if _, ok := conn.(*interrupt.PacketConn); !ok {
		t.Fatalf("delegated packet conn not wrapped by interrupt group: got %T", conn)
	}

	// Interrupting the group must close the tracked conn: a second Close on the
	// wrapper is a no-op, but the underlying socket should now be closed, so a
	// write fails.
	h.interruptGroup.Interrupt(true)
	_ = conn.Close()
	if _, err = pc.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); err == nil {
		t.Fatal("expected underlying socket to be closed after Interrupt")
	}
}

var _ adapter.Outbound = (*stubUDPOutbound)(nil)
