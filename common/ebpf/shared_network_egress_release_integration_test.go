//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// TestSharedNetworkEgressReleasesTrafficItDoesNotOwnIntegration covers the
// egress half of the shared packet-rewrite dataplane, which had no test at
// all before: every other program-level test in this package drives
// classifier/ingress (TCBackend's sharedIngress) or the TC delivery path.
//
// classifier/egress is reached from the host stack, so traffic arriving from
// a token address still has to be judged: only the protocols the policy
// selected and only non-fragmented packets may be taken over. Anything else
// belongs to the stack and must be released with TC_ACT_UNSPEC
// (SB_SHARED_ACT_CONTINUE). Returning TC_ACT_SHOT there drops a connection
// that policy routing never claimed in the first place.
func TestSharedNetworkEgressReleasesTrafficItDoesNotOwnIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify shared-network egress releases unselected and fragmented traffic")

	policy := newTestSharedNetworkFakeIPPolicy(t, "198.18.0.0/15")
	backend, err := PrepareSharedNetwork(nil, newTestSharedNetworkConfig(policy, false))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.Enable(); err != nil {
		t.Fatal(err)
	}
	egress := backend.EgressProgram()
	if egress == nil {
		t.Fatal("shared-network egress program is not loaded")
	}

	// PrepareSharedNetwork derives the token prefix from RedirectIPv4
	// (newTestSharedNetworkConfig uses 127.128.0.0/9), so a source inside it
	// survives ipv4_token_address and reaches the protocol/fragment checks.
	tokenSource := netip.MustParseAddr("127.200.0.10")
	destination := netip.MustParseAddr("203.0.113.10")

	const (
		ipv4ProtocolOffset = 14 + 9
		ipv4FragmentOffset = 14 + 6
		ipProtoICMP        = 1
	)

	// ICMP is neither TCP nor UDP, so selected_protocol() is false even
	// though the policy enables TCP.
	unselected := testIPv4TCPPacket(tokenSource, destination, 53000, 443)
	unselected[ipv4ProtocolOffset] = ipProtoICMP

	// A selected protocol (TCP) carrying the more-fragments bit takes the
	// fragment branch instead: a later fragment has no transport header to
	// rewrite, so it must be released too.
	fragmented := testIPv4TCPPacket(tokenSource, destination, 53000, 443)
	binary.BigEndian.PutUint16(fragmented[ipv4FragmentOffset:], 0x2000)

	for name, packet := range map[string][]byte{
		"unselected protocol": unselected,
		"IPv4 first fragment": fragmented,
	} {
		t.Run(name, func(t *testing.T) {
			action, _ := runTCProgram(t, egress, packet)
			if action != testTCActUnspec {
				t.Fatalf("egress dropped traffic it does not own: action=%d, want %d (TC_ACT_UNSPEC)",
					action, testTCActUnspec)
			}
		})
	}
}
