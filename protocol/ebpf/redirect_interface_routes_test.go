//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

// The netlink operations themselves need a live kernel; what these tests
// cover is everything around them: the set's bookkeeping, and the prefix
// classification the reconciliation relies on.

func TestLocalRouteSetNilReceivers(t *testing.T) {
	var set *localRouteSet
	if changed, err := set.reconcileLocalInterfaceRoutes(); changed || err != nil {
		t.Fatalf("nil reconcile = %v, %v; want false, nil", changed, err)
	}
	if err := set.close(); err != nil {
		t.Fatalf("nil close = %v", err)
	}
	if !set.isClosed() {
		t.Fatal("nil set is not closed")
	}
}

func TestLocalRouteSetCloseRemovesOwnership(t *testing.T) {
	set := newLocalRouteSet([]netip.Prefix{netip.MustParsePrefix("127.77.0.0/16")})
	if err := set.close(); err != nil {
		t.Fatalf("close = %v", err)
	}
	if !set.isClosed() {
		t.Fatal("set with no routes is not closed")
	}
	// After closing, reconciliation is a no-op even with prefixes.
	if changed, err := set.reconcileLocalInterfaceRoutes(); changed || err != nil {
		t.Fatalf("reconcile after close = %v, %v; want false, nil", changed, err)
	}
}

func TestCandidateFamilyClassification(t *testing.T) {
	tests := []struct {
		prefix netip.Prefix
		family int
		name   string
	}{
		{netip.MustParsePrefix("127.77.0.0/16"), unix.AF_INET, "ipv4"},
		{netip.MustParsePrefix("fd53:696e:672d:626f::/64"), unix.AF_INET6, "ipv6"},
		{netip.Prefix{}, unix.AF_UNSPEC, "invalid"},
	}
	for _, test := range tests {
		if family := candidateFamily(test.prefix); family != test.family {
			t.Errorf("candidateFamily(%s) = %d; want %d", test.name, family, test.family)
		}
	}
}

func TestRedirectPrefixesCollectsOnlyValid(t *testing.T) {
	// An Inbound zero value has no prefixes selected; redirectPrefixes must
	// return nothing rather than an invalid prefix entry.
	var inbound Inbound
	if prefixes := inbound.redirectPrefixes(); len(prefixes) != 0 {
		t.Fatalf("redirectPrefixes on zero inbound = %v; want empty", prefixes)
	}
}
