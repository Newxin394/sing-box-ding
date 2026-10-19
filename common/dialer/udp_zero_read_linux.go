//go:build linux || android

package dialer

import (
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// udpConn turns a zero-length read back into an error.
//
// A connected UDP socket whose peer answered with ICMP port unreachable reads
// n=0, err=nil on Linux, while the pending error sits in SO_ERROR. Callers
// treat "0 bytes, no error" as a live socket and read again, so a dead flow
// spins on a zero-byte read instead of failing over. Reporting the pending
// error (os.ErrDeadlineExceeded when there is none) ends the read the way a
// truly closed socket would, without inventing a data error.
type udpConn struct {
	net.Conn
}

func (c *udpConn) SyscallConn() (syscall.RawConn, error) {
	return c.Conn.(syscall.Conn).SyscallConn()
}

func (c *udpConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err == nil && n == 0 {
		return 0, udpPendingError(c.Conn)
	}
	return n, err
}

// udpPacketConn applies the same rule to an unconnected packet connection.
type udpPacketConn struct {
	net.PacketConn
}

func (c *udpPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil && n == 0 {
		return 0, addr, udpPendingErrorFromConn(c.PacketConn)
	}
	return n, addr, err
}

// udpPendingError drains SO_ERROR so the condition is reported once, then
// degrades to os.ErrDeadlineExceeded.
func newZeroReadAwarePacketConn(conn net.PacketConn) net.PacketConn {
	if conn == nil {
		return nil
	}
	return &udpPacketConn{PacketConn: conn}
}

func udpPendingError(conn net.Conn) error {
	return udpPendingErrorFromConn(conn)
}

// udpPendingErrorFromConn reads SO_ERROR from the connection's raw socket.
//
// *net.UDPConn exposes its raw socket through SyscallConn, while other
// implementations (sing's own connections included) are not net.Conn at all, so
// the raw socket is discovered reflectively and the lookup degrades to a plain
// deadline error when it cannot be reached.
func udpPendingErrorFromConn(conn any) error {
	rawConn, isSyscallConn := conn.(syscall.Conn)
	if !isSyscallConn {
		rawConn = discoverSyscallConn(conn)
	}
	if rawConn == nil {
		return os.ErrDeadlineExceeded
	}
	syscallRawConn, err := rawConn.SyscallConn()
	if err != nil {
		return os.ErrDeadlineExceeded
	}
	var pendingErr error
	controlErr := syscallRawConn.Control(func(fd uintptr) {
		soError, soErr := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ERROR)
		if soErr != nil {
			return
		}
		if soError != 0 {
			pendingErr = os.NewSyscallError("getsockopt", unix.Errno(soError))
		}
	})
	if controlErr != nil {
		return os.ErrDeadlineExceeded
	}
	if pendingErr != nil {
		return pendingErr
	}
	return os.ErrDeadlineExceeded
}
