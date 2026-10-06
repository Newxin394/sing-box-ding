//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
	"time"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

// TestTCAssignmentCleanupCapturesBackend verifies that session cleanup carries
// the exact backend and assignment identity recorded when the binding was made.
func TestTCAssignmentCleanupCapturesBackend(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	destination := netip.MustParseAddrPort("1.1.1.1:443")
	key := testUDPSessionKey(client, 42, 7)
	backend := &commonEBPF.TCBackend{}
	assignment := commonEBPF.TCAssignment{SocketCookie: 42, InterfaceIndex: 7}
	table.setDirectAssignmentBinding(key, destination, nil, 0, assignment, backend)
	state, _ := table.load(key)
	cleanup := table.deleteWithCleanup(key, state)
	if cleanup.tcBackend != backend {
		t.Fatal("cleanup lost the backend that created the assignment")
	}
	if len(cleanup.tcAssignments) != 1 {
		t.Fatalf("unexpected assignment cleanup count: %d", len(cleanup.tcAssignments))
	}
	got := cleanup.tcAssignments[0]
	if got.destination != destination || got.keyInterfaceIndex != 0 || got.assignment != assignment {
		t.Fatalf("assignment identity changed: %+v", got)
	}
	if second := table.deleteWithCleanup(key, state); second.tcBackend != nil || len(second.tcAssignments) != 0 {
		t.Fatal("second cleanup was not a no-op")
	}
}

// TestTCAssignmentCleanupDoesNotWaitForDataPlane guards the handover path:
// reconcile holds tcDataPlane.access while purging UDP sessions, so session
// cleanup must not need that lock.
func TestTCAssignmentCleanupDoesNotWaitForDataPlane(t *testing.T) {
	dataPlane := &tcDataPlane{}
	inbound := &Inbound{tcDataPlane: dataPlane}
	dataPlane.access.Lock()
	defer dataPlane.access.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		inbound.deleteTCAssignments(
			testUDPSessionKey(netip.MustParseAddrPort("192.0.2.10:53000"), 42, 7),
			&commonEBPF.TCBackend{},
			[]tcAssignmentCleanup{{destination: netip.MustParseAddrPort("1.1.1.1:443")}},
		)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("TC assignment cleanup blocked on the data-plane lock")
	}
}
