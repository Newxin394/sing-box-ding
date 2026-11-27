//go:build linux

package udpio

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

func TestOOBPacketBatchKeepsValidMessages(t *testing.T) {
	receiver := listenOOBTestUDP4(t)
	if err := enableIPv4PacketInfo(receiver); err != nil {
		t.Fatal(err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := newTruncationTestReader(t, receiver, 256, 4)
	first := listenOOBTestUDP4(t)
	second := listenOOBTestUDP4(t)
	address := receiver.LocalAddr().(*net.UDPAddr).AddrPort()

	writeOOBTestDatagram(t, first, address, "too-long-1")
	writeOOBTestDatagram(t, first, address, "keep-a")
	writeOOBTestDatagram(t, second, address, "too-long-2")
	writeOOBTestDatagram(t, second, address, "")
	buffers, oobs, sources, err := reader.WaitReadOOBPackets()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(buffers)
	if len(buffers) != 2 || len(oobs) != 2 || len(sources) != 2 {
		t.Fatalf("unexpected batch sizes: %d/%d/%d", len(buffers), len(oobs), len(sources))
	}
	for index, want := range []string{"keep-a", ""} {
		if got := string(buffers[index].Bytes()); got != want {
			t.Fatalf("message %d payload = %q, want %q", index, got, want)
		}
		wantSource := []*net.UDPConn{first, second}[index].LocalAddr().(*net.UDPAddr).AddrPort()
		if sources[index].AddrPort() != wantSource || !containsPacketInfo(oobs[index], unix.IPPROTO_IP, unix.IP_PKTINFO) {
			t.Fatalf("message %d source or packet info mismatched: source=%v, want=%v, oob=%x", index, sources[index], wantSource, oobs[index])
		}
	}

	writeOOBTestDatagram(t, second, address, "next")
	next, _, _, err := reader.WaitReadOOBPackets()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(next)
	if len(next) != 1 || string(next[0].Bytes()) != "next" {
		t.Fatalf("unexpected next batch: %v", next)
	}
	if string(buffers[0].Bytes()) != "keep-a" || !buffers[1].IsEmpty() {
		t.Fatal("the next read changed previously returned buffers")
	}
}

func TestOOBPacketBatchWaitsAfterAllMessagesAreTruncated(t *testing.T) {
	receiver := listenOOBTestUDP4(t)
	if err := receiver.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := newTruncationTestReader(t, receiver, 256, 2)
	sender := listenOOBTestUDP4(t)
	address := receiver.LocalAddr().(*net.UDPAddr).AddrPort()
	writeOOBTestDatagram(t, sender, address, "too-long-1")
	writeOOBTestDatagram(t, sender, address, "too-long-2")
	writeOOBTestDatagram(t, sender, address, "keep")
	buffers, _, _, err := reader.WaitReadOOBPackets()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(buffers)
	if len(buffers) != 1 || string(buffers[0].Bytes()) != "keep" {
		t.Fatalf("expected the next valid datagram, got %v", buffers)
	}
}

func TestOOBPacketBatchControlTruncationHonorsDeadline(t *testing.T) {
	receiver := listenOOBTestUDP4(t)
	if err := enableIPv4PacketInfo(receiver); err != nil {
		t.Fatal(err)
	}
	reader := newTruncationTestReader(t, receiver, 1, 2)
	sender := listenOOBTestUDP4(t)
	writeOOBTestDatagram(t, sender, receiver.LocalAddr().(*net.UDPAddr).AddrPort(), "fits")
	if err := receiver.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffers, oobs, sources, err := reader.WaitReadOOBPackets()
	defer buf.ReleaseMulti(buffers)
	if !errors.Is(err, os.ErrDeadlineExceeded) || len(buffers)+len(oobs)+len(sources) != 0 {
		t.Fatalf("expected only a read deadline after discarding truncated control data, got %d/%d/%d: %v", len(buffers), len(oobs), len(sources), err)
	}
}

func listenOOBTestUDP4(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func newTruncationTestReader(t *testing.T, conn *net.UDPConn, oobSize, batchSize int) OOBPacketBatchReadWaiter {
	t.Helper()
	reader, created := NewOOBPacketBatchReadWaiter(conn, oobSize)
	if !created {
		t.Fatal("OOB packet batch reader was not created")
	}
	reader.InitializeReadWaiter(N.ReadWaitOptions{MTU: 8, BatchSize: batchSize})
	return reader
}

func writeOOBTestDatagram(t *testing.T, conn *net.UDPConn, destination netip.AddrPort, payload string) {
	t.Helper()
	if _, err := conn.WriteToUDPAddrPort([]byte(payload), destination); err != nil {
		t.Fatal(err)
	}
}
