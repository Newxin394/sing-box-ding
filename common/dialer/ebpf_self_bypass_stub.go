//go:build !with_ebpf || (!linux && !android)

package dialer

import (
	"net"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
)

func PrepareEBPFSelfBypass(adapter.NetworkManager, []option.Inbound) error {
	return nil
}

func CloseUnclaimedEBPFSelfBypass(adapter.NetworkManager) error {
	return nil
}

func AppendEBPFSelfBypass(_ adapter.NetworkManager, controlFunc control.Func) control.Func {
	return controlFunc
}

func RegisterEBPFSelfBypassPacketConn(_ adapter.NetworkManager, _ net.PacketConn) error {
	return nil
}

func EBPFSelfBypassCleanup(_ adapter.NetworkManager, _ syscall.RawConn) func() {
	return nil
}

func bindEBPFSelfBypassConnLifecycle(_ adapter.NetworkManager, conn net.Conn) net.Conn {
	return conn
}

func bindEBPFSelfBypassPacketConnLifecycle(_ adapter.NetworkManager, conn net.PacketConn) net.PacketConn {
	return conn
}
