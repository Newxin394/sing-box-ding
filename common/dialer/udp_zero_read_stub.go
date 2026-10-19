//go:build !linux

package dialer

import "net"

// newZeroReadAwarePacketConn passes packet connections through unchanged.
//
// Reading SO_ERROR on a zero-byte datagram read is a Linux-specific concern:
// the darwin kqueue path already reports EOF through sing's IsUDPEOF, and the
// other platforms never produce a zero-byte datagram read in the first place,
// so there is nothing to correct here.
func newZeroReadAwarePacketConn(conn net.PacketConn) net.PacketConn {
	return conn
}
