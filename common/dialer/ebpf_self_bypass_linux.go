//go:build with_ebpf && (linux || android)

package dialer

import (
	"net"
	"sync"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

func PrepareEBPFSelfBypass(networkManager adapter.NetworkManager, inbounds []option.Inbound) error {
	localInstances := 0
	// The self-bypass table is an LRU hash, so its capacity is preallocated in
	// full at creation and never grows: read the override here so a device with
	// little memory can ask for a smaller one. More than one local inbound is
	// refused below, so this value is unambiguous.
	selfBypassCapacity := uint32(commonEBPF.DefaultSelfBypassCapacity)
	for _, inbound := range inbounds {
		switch inbound.Type {
		case C.TypeEBPF:
			ebpfOptions, loaded := inbound.Options.(*option.EBPFInboundOptions)
			if !loaded {
				return E.New("invalid eBPF inbound options")
			}
			localEnabled, _ := ebpfOptions.EffectiveEnablement()
			if localEnabled {
				localInstances++
				if capacity := ebpfOptions.MapCapacity; capacity != nil && capacity.SelfBypass != 0 {
					selfBypassCapacity = capacity.SelfBypass
				}
			}
		}
	}
	if localInstances > 1 {
		return E.New("only one local or hybrid eBPF inbound is supported")
	}
	if localInstances == 0 {
		return nil
	}
	tracker, err := commonEBPF.NewSelfBypass(selfBypassCapacity)
	if err != nil {
		return err
	}
	setter, loaded := networkManager.(interface {
		SetEBPFSelfBypass(*commonEBPF.SelfBypass) error
	})
	if !loaded {
		_ = tracker.Close()
		return E.New("network manager does not support eBPF self-bypass sockets")
	}
	if err = setter.SetEBPFSelfBypass(tracker); err != nil {
		_ = tracker.Close()
		return err
	}
	return nil
}

// AppendEBPFSelfBypass appends the eBPF self-bypass registration callback to a
// socket control chain. It is also used by integrations that create sockets
// outside DefaultDialer, such as endpoint-specific network stacks.
func AppendEBPFSelfBypass(networkManager adapter.NetworkManager, controlFunc control.Func) control.Func {
	provider, loaded := networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	})
	if !loaded {
		return controlFunc
	}
	selfBypassFunc := func(_ string, _ string, rawConn syscall.RawConn) error {
		tracker := provider.EBPFSelfBypass()
		if tracker == nil {
			return nil
		}
		return tracker.RegisterSocket(rawConn)
	}
	return control.Append(controlFunc, selfBypassFunc)
}

func EBPFSelfBypassCleanup(networkManager adapter.NetworkManager, rawConn syscall.RawConn) func() {
	provider, loaded := networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	})
	if !loaded {
		return nil
	}
	tracker := provider.EBPFSelfBypass()
	if tracker == nil || tracker.HasSocketReleaseHook() {
		return nil
	}
	var once sync.Once
	return func() {
		once.Do(func() { _ = tracker.UnregisterSocket(rawConn) })
	}
}

func bindEBPFSelfBypassConnLifecycle(networkManager adapter.NetworkManager, conn net.Conn) net.Conn {
	if lazy, loaded := conn.(*slowOpenConn); loaded {
		if cleanup := ebpfSelfBypassCleanupForLazyConn(networkManager, lazy); cleanup != nil {
			lazy.setCloseHandler(cleanup)
		}
		return conn
	}
	syscallConn, loaded := conn.(syscall.Conn)
	if !loaded {
		return conn
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return conn
	}
	cleanup := EBPFSelfBypassCleanup(networkManager, rawConn)
	if cleanup == nil {
		return conn
	}
	return &selfBypassConn{Conn: conn, cleanup: cleanup, rawConn: rawConn}
}

func ebpfSelfBypassCleanupForLazyConn(networkManager adapter.NetworkManager, conn *slowOpenConn) func(*net.TCPConn) {
	provider, loaded := networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	})
	if !loaded {
		return nil
	}
	tracker := provider.EBPFSelfBypass()
	if tracker == nil || tracker.HasSocketReleaseHook() {
		return nil
	}
	var once sync.Once
	return func(tcpConn *net.TCPConn) {
		once.Do(func() {
			rawConn, err := tcpConn.SyscallConn()
			if err == nil {
				_ = tracker.UnregisterSocket(rawConn)
			}
		})
	}
}

type selfBypassConn struct {
	net.Conn
	cleanup func()
	rawConn syscall.RawConn
}

func (c *selfBypassConn) Close() error {
	if c.cleanup != nil {
		c.cleanup()
	}
	return c.Conn.Close()
}

func (c *selfBypassConn) SyscallConn() (syscall.RawConn, error) { return c.rawConn, nil }
func (c *selfBypassConn) Upstream() any                         { return c.Conn }
func (c *selfBypassConn) ReaderReplaceable() bool               { return true }
func (c *selfBypassConn) WriterReplaceable() bool               { return true }

type selfBypassPacketConn struct {
	N.NetPacketConn
	cleanup func()
	rawConn syscall.RawConn
}

func newSelfBypassPacketConn(conn net.PacketConn, cleanup func(), rawConn syscall.RawConn) *selfBypassPacketConn {
	packetConn, loaded := conn.(N.NetPacketConn)
	if !loaded {
		packetConn = bufio.NewPacketConn(conn)
	}
	return &selfBypassPacketConn{NetPacketConn: packetConn, cleanup: cleanup, rawConn: rawConn}
}

func (c *selfBypassPacketConn) Close() error {
	if c.cleanup != nil {
		c.cleanup()
	}
	return c.NetPacketConn.Close()
}

func (c *selfBypassPacketConn) SyscallConn() (syscall.RawConn, error) { return c.rawConn, nil }

func bindEBPFSelfBypassPacketConnLifecycle(networkManager adapter.NetworkManager, conn net.PacketConn) net.PacketConn {
	syscallConn, loaded := conn.(syscall.Conn)
	if !loaded {
		return conn
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return conn
	}
	cleanup := EBPFSelfBypassCleanup(networkManager, rawConn)
	if cleanup == nil {
		return conn
	}
	return newSelfBypassPacketConn(conn, cleanup, rawConn)
}

func appendEBPFSelfBypass(networkManager adapter.NetworkManager, dialerControl, listenerControl control.Func) (control.Func, control.Func) {
	return AppendEBPFSelfBypass(networkManager, dialerControl), AppendEBPFSelfBypass(networkManager, listenerControl)
}
