//go:build with_ebpf && (linux || android)

package dialer

import "net"

// setCloseHandler records the cleanup that the eBPF self-bypass wrapper runs when
// the connection closes. Only that path installs a handler, so the method lives
// behind the same build tag: without it nothing would ever call it.
func (c *slowOpenConn) setCloseHandler(handler func(*net.TCPConn)) {
	c.closeHandler.Store(handler)
}
