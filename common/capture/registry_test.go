package capture

import "testing"

func TestRegistrySnapshot(t *testing.T) {
	var r Registry
	tc := &fakeOwner{name: "tc"}
	tun := &fakeOwner{name: "tun"}
	if !r.Register(ModeTC, tc) || !r.Register(ModeTUN, tun) {
		t.Fatal("register failed")
	}
	gotTC, gotTUN := r.Snapshot()
	if gotTC != tc || gotTUN != tun {
		t.Fatal("snapshot did not preserve owners")
	}
	if r.Owner(ModeNone) != nil || r.Owner(ModeTC) != tc {
		t.Fatal("owner lookup mismatch")
	}
}
