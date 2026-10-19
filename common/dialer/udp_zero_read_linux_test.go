//go:build linux

package dialer

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// fakeUDPConn fakes the read path of a UDP connection so the zero-byte rule can
// be exercised without a real socket. readCount lets a test prove the wrapper
// does not consume an extra datagram.
type fakeUDPConn struct {
	readResults []readResult
	readCount   int
}

type readResult struct {
	n   int
	err error
}

func (c *fakeUDPConn) Read(b []byte) (int, error) {
	if c.readCount >= len(c.readResults) {
		return 0, os.ErrDeadlineExceeded
	}
	result := c.readResults[c.readCount]
	c.readCount++
	return result.n, result.err
}

func (c *fakeUDPConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *fakeUDPConn) Close() error                       { return nil }
func (c *fakeUDPConn) LocalAddr() net.Addr                { return nil }
func (c *fakeUDPConn) RemoteAddr() net.Addr               { return nil }
func (c *fakeUDPConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeUDPConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeUDPConn) SetWriteDeadline(t time.Time) error { return nil }

// TestZeroByteReadDoesNotSurfaceAsSuccess pins the behaviour the wrapper exists
// for: a zero-byte read that reports no error must not reach the caller, because
// a UDP relay reads that as a zero-length datagram and silently drops it.
func TestZeroByteReadDoesNotSurfaceAsSuccess(t *testing.T) {
	conn := &fakeUDPConn{readResults: []readResult{{n: 0, err: nil}}}
	wrapped := &udpConn{Conn: conn}
	n, err := wrapped.Read(make([]byte, 1500))
	if n != 0 {
		t.Fatalf("expected zero-byte read to stay zero bytes, got %d", n)
	}
	if err == nil {
		t.Fatal("zero-byte read with no error must not be reported as success")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a zero-byte read without a pending socket error must look like a timeout, got %v", err)
	}
}

// TestNormalReadPassesThrough guards the hot path: a read carrying data must be
// returned untouched, with no extra read from the underlying connection.
func TestNormalReadPassesThrough(t *testing.T) {
	conn := &fakeUDPConn{readResults: []readResult{{n: 512, err: nil}, {n: 1, err: nil}}}
	wrapped := &udpConn{Conn: conn}
	n, err := wrapped.Read(make([]byte, 1500))
	if n != 512 || err != nil {
		t.Fatalf("expected 512 bytes and no error, got %d, %v", n, err)
	}
	if conn.readCount != 1 {
		t.Fatalf("expected exactly one read on the underlying connection, got %d", conn.readCount)
	}
}

// TestSyscallErrnoInspectorFindsNoSocket documents that a connection without a
// reachable file descriptor degrades to a deadline error instead of panicking.
func TestSyscallErrnoInspectorFindsNoSocket(t *testing.T) {
	conn := &fakeUDPConn{}
	rawConn, isSyscallConn := any(conn).(syscall.Conn)
	if isSyscallConn {
		t.Fatal("fixture must not expose a syscall connection")
	}
	if rawConn != nil {
		t.Fatal("a non-syscall connection must not yield a raw connection")
	}
	var reached bool
	func() {
		defer func() {
			if recover() != nil {
				t.Fatal("inspecting a non-syscall connection must not panic")
			}
		}()
		reached = udpPendingErrorFromConn(conn) != nil
	}()
	if !reached {
		t.Fatal("a non-syscall connection must report a pending error")
	}
}
