package group

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestSelectorUpdateGuard(t *testing.T) {
	s := &Selector{outbounds: map[string]adapter.Outbound{
		"a": &testSelectorOutbound{Adapter: outbound.NewAdapter("test", "a", []string{N.NetworkTCP}, nil)},
		"b": &testSelectorOutbound{Adapter: outbound.NewAdapter("test", "b", []string{N.NetworkTCP}, nil)},
	}, interruptGroup: interrupt.NewGroup()}
	s.selected.Store(s.outbounds["a"])
	guardErr := errors.New("guard rejected update")
	guard := s.RegisterUpdateGuard(func(previous, selected string) error { return guardErr })
	if err := s.SelectOutboundContext("b"); !errors.Is(err, guardErr) || s.Now() != "a" {
		t.Fatalf("guard did not reject update: %v, now=%s", err, s.Now())
	}
	s.UnregisterUpdateGuard(guard)
	if err := s.SelectOutboundContext("b"); err != nil || s.Now() != "b" {
		t.Fatalf("selector update failed: %v", err)
	}
	a, b := new(int), new(int)
	if err := s.ClaimController(a); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimController(b); err == nil {
		t.Fatal("expected controller conflict")
	}
	s.ReleaseController(a)
	if err := s.ClaimController(b); err != nil {
		t.Fatal(err)
	}
}

type testSelectorOutbound struct{ outbound.Adapter }

func (o *testSelectorOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (o *testSelectorOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

var _ adapter.Outbound = (*testSelectorOutbound)(nil)
