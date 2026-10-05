//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestUDPReplySocketPoolRunsCleanupOnEvictionAndClose(t *testing.T) {
	pool := udpReplySocketPool{capacity: 1}
	var firstCleanup atomic.Int32
	var secondCleanup atomic.Int32
	first := netip.MustParseAddrPort("203.0.113.10:1")
	second := netip.MustParseAddrPort("203.0.113.10:2")
	makeSocket := func(cleanup *atomic.Int32) func(netip.AddrPort) (*net.UDPConn, func(), error) {
		return func(netip.AddrPort) (*net.UDPConn, func(), error) {
			socket, err := newLoopbackUDPSocket(first)
			return socket, func() { cleanup.Add(1) }, err
		}
	}
	_, release, err := pool.getWithCleanup(first, makeSocket(&firstCleanup))
	if err != nil {
		t.Fatal(err)
	}
	release()
	_, release, err = pool.getWithCleanup(second, makeSocket(&secondCleanup))
	if err != nil {
		t.Fatal(err)
	}
	release()
	if got := firstCleanup.Load(); got != 1 {
		t.Fatalf("first cleanup count = %d, want 1 after eviction", got)
	}
	if err := pool.close(); err != nil {
		t.Fatal(err)
	}
	if got := firstCleanup.Load(); got != 1 {
		t.Fatalf("first cleanup count = %d after pool close, want no duplicate", got)
	}
	if got := secondCleanup.Load(); got != 1 {
		t.Fatalf("second cleanup count = %d after pool close, want 1", got)
	}
}
