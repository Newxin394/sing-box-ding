//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

func addTestClsactLink(t *testing.T, name string) netlink.Link {
	t.Helper()
	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	device := &netlink.Dummy{LinkAttrs: attrs}
	if err := netlink.LinkAdd(device); err != nil {
		t.Fatalf("add test link %s: %v", name, err)
	}
	found, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("lookup test link %s: %v", name, err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(found) })
	return found
}

func hasTestClsact(t *testing.T, device netlink.Link) bool {
	t.Helper()
	qdiscs, err := netlink.QdiscList(device)
	if err != nil {
		t.Fatalf("list qdiscs on %s: %v", device.Attrs().Name, err)
	}
	for _, qdisc := range qdiscs {
		if qdisc.Type() == "clsact" {
			return true
		}
	}
	return false
}

func TestTCClsactLeaseDeletesOnlyQdiscItCreated(t *testing.T) {
	enterTestNetworkNamespace(t)
	device := addTestClsactLink(t, "sbclctest0")

	lease, err := acquireTCClsactLease(device)
	if err != nil {
		t.Fatal(err)
	}
	if lease == nil || !hasTestClsact(t, device) {
		t.Fatal("lease did not create clsact")
	}
	if err = releaseTCClsactLease(&lease); err != nil {
		t.Fatalf("release owned clsact: %v", err)
	}
	if lease != nil || hasTestClsact(t, device) {
		t.Fatal("owned empty clsact was not removed")
	}
}

func TestTCClsactLeasePreservesPreexistingQdisc(t *testing.T) {
	enterTestNetworkNamespace(t)
	device := addTestClsactLink(t, "sbclctest1")
	if err := ensureTCClsact(device); err != nil {
		t.Fatal(err)
	}

	lease, err := acquireTCClsactLease(device)
	if err != nil {
		t.Fatal(err)
	}
	if err = releaseTCClsactLease(&lease); err != nil {
		t.Fatalf("release lease over preexisting clsact: %v", err)
	}
	if !hasTestClsact(t, device) {
		t.Fatal("preexisting clsact was removed")
	}
}

func TestTCClsactLeaseWaitsForLastAttachment(t *testing.T) {
	enterTestNetworkNamespace(t)
	device := addTestClsactLink(t, "sbclctest2")
	first, err := acquireTCClsactLease(device)
	if err != nil {
		t.Fatal(err)
	}
	second, err := acquireTCClsactLease(device)
	if err != nil {
		t.Fatal(err)
	}
	if err = releaseTCClsactLease(&first); err != nil {
		t.Fatalf("release first lease: %v", err)
	}
	if first != nil || !hasTestClsact(t, device) {
		t.Fatal("first release removed a qdisc still leased by another attachment")
	}
	if err = releaseTCClsactLease(&second); err != nil {
		t.Fatalf("release final lease: %v", err)
	}
	if second != nil || hasTestClsact(t, device) {
		t.Fatal("final release did not remove the owned empty clsact")
	}
}

func TestTCClsactLeaseKeepsQdiscWithFilters(t *testing.T) {
	enterTestNetworkNamespace(t)
	device := addTestClsactLink(t, "sbclctest3")
	lease, err := acquireTCClsactLease(device)
	if err != nil {
		t.Fatal(err)
	}
	// A non-BPF filter represents another consumer. The lease must leave the
	// shared qdisc alone once any filter remains on either hook.
	filter := &netlink.MatchAll{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: device.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Priority:  10,
			Protocol:  unix.ETH_P_ALL,
		},
		Actions: []netlink.Action{&netlink.GenericAction{ActionAttrs: netlink.ActionAttrs{Action: netlink.TC_ACT_OK}}},
	}
	if err = netlink.FilterAdd(filter); err != nil {
		t.Skipf("kernel does not support matchall test filter: %v", err)
	}
	t.Cleanup(func() { _ = netlink.FilterDel(filter) })
	if err = releaseTCClsactLease(&lease); err != nil {
		t.Fatalf("release lease with a foreign filter present: %v", err)
	}
	if lease != nil || !hasTestClsact(t, device) {
		t.Fatal("qdisc with a remaining filter was removed or lease retained")
	}
}
