//go:build with_ebpf && (linux || android)

package route

import (
	"sync"
	"sync/atomic"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

type ebpfSelfBypassState struct {
	// access serializes the hand-over between the inbound claiming the
	// tracker and the box closing it while unclaimed.
	access  sync.Mutex
	tracker atomic.Pointer[commonEBPF.SelfBypass]
	claimed bool
}

func (r *NetworkManager) SetEBPFSelfBypass(tracker *commonEBPF.SelfBypass) error {
	if tracker == nil {
		return E.New("invalid eBPF self-bypass tracker")
	}
	r.ebpfSelfBypass.access.Lock()
	defer r.ebpfSelfBypass.access.Unlock()
	if current := r.ebpfSelfBypass.tracker.Load(); current != nil && current != tracker {
		return E.New("eBPF self-bypass tracker is already configured")
	}
	r.ebpfSelfBypass.tracker.Store(tracker)
	r.ebpfSelfBypass.claimed = false
	return nil
}

func (r *NetworkManager) EBPFSelfBypass() *commonEBPF.SelfBypass {
	return r.ebpfSelfBypass.tracker.Load()
}

// ClaimEBPFSelfBypass hands the tracker over to the inbound that owns it from
// now on. It reports false when the box already closed the unclaimed tracker,
// in which case the inbound must not start.
func (r *NetworkManager) ClaimEBPFSelfBypass(tracker *commonEBPF.SelfBypass) bool {
	r.ebpfSelfBypass.access.Lock()
	defer r.ebpfSelfBypass.access.Unlock()
	if tracker == nil || r.ebpfSelfBypass.tracker.Load() != tracker {
		return false
	}
	r.ebpfSelfBypass.claimed = true
	return true
}

// CloseUnclaimedEBPFSelfBypass closes a tracker that no inbound claimed, as
// when the box is created and closed without starting, or when creation fails
// after the tracker was prepared. Dials made in the meantime may already have
// created its kernel map, so this must not be a no-op.
func (r *NetworkManager) CloseUnclaimedEBPFSelfBypass() error {
	r.ebpfSelfBypass.access.Lock()
	if r.ebpfSelfBypass.claimed {
		r.ebpfSelfBypass.access.Unlock()
		return nil
	}
	tracker := r.ebpfSelfBypass.tracker.Swap(nil)
	r.ebpfSelfBypass.access.Unlock()
	if tracker == nil {
		return nil
	}
	return tracker.Close()
}

func (r *NetworkManager) ClearEBPFSelfBypass(tracker *commonEBPF.SelfBypass) {
	r.ebpfSelfBypass.access.Lock()
	defer r.ebpfSelfBypass.access.Unlock()
	if r.ebpfSelfBypass.tracker.Load() != tracker {
		return
	}
	r.ebpfSelfBypass.claimed = false
	r.ebpfSelfBypass.tracker.CompareAndSwap(tracker, nil)
}
