package group

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// fixedNetworkOutbound is a minimal adapter.Outbound whose advertised network
// set is fixed at construction, so tests can model both a UDP-capable member
// (VLESS/VMess) and a TCP-only member (plain HTTP).
type fixedNetworkOutbound struct {
	adapter.Outbound
	tag      string
	networks []string
}

func (o *fixedNetworkOutbound) Tag() string { return o.tag }

func (o *fixedNetworkOutbound) Network() []string { return o.networks }

func (o *fixedNetworkOutbound) Dependencies() []string { return nil }

func (o *fixedNetworkOutbound) Start(adapter.StartStage) error { return nil }

func (o *fixedNetworkOutbound) Close() error { return nil }

func (o *fixedNetworkOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, nil
}

func (o *fixedNetworkOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, nil
}

func selectorOptionsFor(member *fixedNetworkOutbound, udpTag, fallbackTag string) option.SelectorOutboundOptions {
	return option.SelectorOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{
			Outbounds:           []string{member.tag},
			UDPOutbound:         udpTag,
			UDPFallbackOutbound: fallbackTag,
		},
	}
}

// selectedSupportsUDP is the unit under test: it must report what the currently
// selected member can actually carry, because that decides whether the
// udp_outbound hop is needed at all.
// Network() must advertise UDP whenever a udp_outbound is configured, even if
// the currently selected member is TCP-only: the route layer rejects UDP based
// on Network() before ListenPacket ever runs, so delegation would be unreachable.
func TestSelectorNetworkAdvertisesUDPWhenDelegating(t *testing.T) {
	newSelector := func(udpTag string) *Selector {
		return &Selector{udpOutboundTag: udpTag}
	}

	t.Run("with udp_outbound", func(t *testing.T) {
		s := newSelector("delegate")
		require.Equal(t, []string{N.NetworkTCP, N.NetworkUDP}, s.Network())
	})

	t.Run("without udp_outbound follows member", func(t *testing.T) {
		s := newSelector("")
		s.selected.Store(&fixedNetworkOutbound{tag: "http", networks: []string{N.NetworkTCP}})
		require.Equal(t, []string{N.NetworkTCP}, s.Network())
	})
}

func TestSelectedSupportsUDP(t *testing.T) {
	t.Run("udp capable member", func(t *testing.T) {
		s := &Selector{}
		s.selected.Store(&fixedNetworkOutbound{tag: "vless", networks: []string{N.NetworkTCP, N.NetworkUDP}})
		require.True(t, s.selectedSupportsUDP())
	})

	t.Run("tcp only member", func(t *testing.T) {
		s := &Selector{}
		s.selected.Store(&fixedNetworkOutbound{tag: "http", networks: []string{N.NetworkTCP}})
		require.False(t, s.selectedSupportsUDP())
	})

	t.Run("nil selection delegates", func(t *testing.T) {
		s := &Selector{}
		require.False(t, s.selectedSupportsUDP(), "nil selection must delegate, never drop UDP")
	})
}

// Construction must still accept a udp_outbound pointing at an outbound that is
// not part of the selector's own members, and must still reject a self
// reference -- the new skip logic must not weaken startup validation.
func TestSelectorUDPDelegateStillValidated(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("test")

	_, err := NewSelector(context.Background(), nil, logger, "sel", option.SelectorOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{
			Outbounds:   []string{"a"},
			UDPOutbound: "sel",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "must not reference itself")

	_, err = NewSelector(context.Background(), nil, logger, "sel", option.SelectorOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{
			Outbounds:           []string{"a"},
			UDPOutbound:         "direct",
			UDPFallbackOutbound: "sel",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "must not reference itself")

	_, err = NewSelector(context.Background(), nil, logger, "sel", option.SelectorOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{
			Outbounds:           []string{"a"},
			UDPFallbackOutbound: "direct",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "requires udp_outbound")
}
