//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
)

// TestUDPRedirectBindingIsDirect pins the predicate the setDirectBinding fast
// path relies on: only the exact zero value qualifies, so any refinement
// another writer installed forces the write path to run.
func TestUDPRedirectBindingIsDirect(t *testing.T) {
	if !(udpRedirectBinding{}).isDirect() {
		t.Fatal("zero-value binding must be reported as direct")
	}
	refined := []struct {
		name    string
		binding udpRedirectBinding
	}{
		{"reply alias", udpRedirectBinding{replyAlias: true}},
		{"connected", udpRedirectBinding{connected: true}},
		{"redirect address", udpRedirectBinding{redirectAddress: netip.MustParseAddr("127.0.0.1")}},
		{"packet info", udpRedirectBinding{packetInfo: []byte{0x01}}},
	}
	for _, testCase := range refined {
		if testCase.binding.isDirect() {
			t.Fatalf("%s binding must not be reported as direct", testCase.name)
		}
	}
}

// TestSetDirectBindingRepeatedCallIsStable covers the fast path itself: calling
// it twice for one flow must leave exactly the direct binding behind.
func TestSetDirectBindingRepeatedCallIsStable(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("10.0.0.2:41000")
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	table.setDirectBinding(client, destination, nil, 7)
	table.setDirectBinding(client, destination, nil, 7)
	state, loaded := table.load(client)
	if !loaded {
		t.Fatal("client state missing after setDirectBinding")
	}
	binding, found := state.redirectBinding(destination)
	if !found {
		t.Fatal("direct binding missing after repeated setDirectBinding")
	}
	if !binding.isDirect() {
		t.Fatalf("binding not direct after repeated call: %+v", binding)
	}
}

// TestSetDirectBindingStillClearsReplyAlias is the regression guard for the fast
// path: a binding carrying a reply alias is not "already direct", so the write
// path must still run and reset it, exactly as it did before the fast path
// existed.
func TestSetDirectBindingStillClearsReplyAlias(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("10.0.0.3:41001")
	destination := netip.MustParseAddrPort("8.8.8.8:53")
	table.setDirectBinding(client, destination, nil, 9)
	state, loaded := table.load(client)
	if !loaded {
		t.Fatal("client state missing")
	}
	state.access.Lock()
	state.bindings[destination] = udpRedirectBinding{replyAlias: true}
	state.access.Unlock()
	table.setDirectBinding(client, destination, nil, 9)
	binding, found := state.redirectBinding(destination)
	if !found {
		t.Fatal("binding disappeared")
	}
	if binding.replyAlias {
		t.Fatal("reply alias survived setDirectBinding; the fast path misclassified it")
	}
}

// TestSetDirectBindingUpdatesChangedSocketCookie covers the other half of the
// fast-path guard: a different socket cookie means a different socket, so the
// state must be rewritten rather than skipped.
func TestSetDirectBindingUpdatesChangedSocketCookie(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("10.0.0.4:41002")
	destination := netip.MustParseAddrPort("9.9.9.9:53")
	table.setDirectBinding(client, destination, nil, 11)
	table.setDirectBinding(client, destination, nil, 12)
	state, _ := table.load(client)
	if cookie := state.processSocketCookie(); cookie != 12 {
		t.Fatalf("socket cookie not updated: got %d, want 12", cookie)
	}
}
