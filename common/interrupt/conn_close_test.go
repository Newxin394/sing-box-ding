package interrupt

import (
	"net"
	"testing"
	"time"
)

type reentrantCloseConn struct {
	net.Conn
	callback func()
}

func (c *reentrantCloseConn) Close() error { c.callback(); return nil }

type reentrantClosePacketConn struct {
	net.PacketConn
	callback func()
}

func (c *reentrantClosePacketConn) Close() error { c.callback(); return nil }

func TestWrappedCloseAllowsGroupReentry(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			group := NewGroup()
			callback := func() { group.Interrupt(true) }
			var closeConn func() error
			if network == "tcp" {
				closeConn = group.NewConn(&reentrantCloseConn{callback: callback}, true, false).Close
			} else {
				closeConn = group.NewPacketConn(&reentrantClosePacketConn{callback: callback}, true, false).Close
			}
			done := make(chan error, 1)
			go func() { done <- closeConn() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(300 * time.Millisecond):
				t.Fatal("wrapped Close holds group lock during underlying Close callback")
			}
		})
	}
}
