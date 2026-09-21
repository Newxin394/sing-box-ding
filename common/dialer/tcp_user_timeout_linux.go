//go:build linux || android

package dialer

import (
	"syscall"
	"time"

	"github.com/sagernet/sing/common/control"

	"golang.org/x/sys/unix"
)

// tcpUserTimeoutFunc sets TCP_USER_TIMEOUT (ms) on the socket. This bounds how
// long the kernel keeps retransmitting an unacked segment before it gives up
// and tears the connection down, instead of the default RTO backoff that can
// stall a dead flow for up to ~120s. On flaky cellular links this turns a
// two-minute freeze after a network flap into a fast failure that the upper
// layer can reconnect through. It deliberately does not touch RTO_MIN/RTO_MAX,
// so normal RTT jitter is unaffected.
func tcpUserTimeoutFunc(d time.Duration) control.Func {
	millis := int(d / time.Millisecond)
	return func(network, address string, conn syscall.RawConn) error {
		if millis <= 0 {
			return nil
		}
		switch network {
		case "tcp", "tcp4", "tcp6":
		default:
			return nil
		}
		var innerErr error
		err := conn.Control(func(fd uintptr) {
			innerErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, millis)
		})
		if innerErr != nil {
			return innerErr
		}
		return err
	}
}
