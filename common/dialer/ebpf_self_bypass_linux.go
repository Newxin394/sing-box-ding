//go:build with_ebpf && (linux || android)

package dialer

import (
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
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

func appendEBPFSelfBypass(networkManager adapter.NetworkManager, dialerControl, listenerControl control.Func) (control.Func, control.Func) {
	provider, loaded := networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	})
	if !loaded {
		return dialerControl, listenerControl
	}
	selfBypassFunc := func(_ string, _ string, rawConn syscall.RawConn) error {
		tracker := provider.EBPFSelfBypass()
		if tracker == nil {
			return nil
		}
		return tracker.RegisterSocket(rawConn)
	}
	return control.Append(dialerControl, selfBypassFunc), control.Append(listenerControl, selfBypassFunc)
}
