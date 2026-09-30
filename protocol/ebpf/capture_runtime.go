//go:build with_ebpf && (linux || android)

package ebpf

import (
	E "github.com/sagernet/sing/common/exceptions"
)

// activateTCCapture and deactivateTCCapture are the only operations exposed to
// the capture coordinator. They deliberately touch the backend control map,
// not the attachment topology: filters, delivery veth, policy routing and
// listeners remain owned by the staged inbound lifecycle.
// SetCaptureDeferred is called by the capture coordinator factory when both a
// TUN and an eBPF inbound exist. It suppresses the inbound's self-activation in
// StartStateStart so the coordinator can establish a single-active baseline in
// StartStateStarted, eliminating the dual-capture startup window.
func (i *Inbound) SetCaptureDeferred(deferred bool) {
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	i.captureDeferred = deferred
	i.captureDeferredState.Store(deferred)
}

func (i *Inbound) activateTCCapture() error {
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	d := i.tcDataPlane
	if d == nil || d.backend == nil {
		return E.New("TC backend is not prepared")
	}
	local := ""
	if i.localTCEnabled() {
		local = i.currentDefaultInterfaceName()
		if local == "" {
			return E.New("default TC interface unavailable")
		}
	}
	shared := activeSharedInterfaces(i.sharedOptions.Interface, i.currentDefaultInterfaceName(), i.localEnabled)
	if i.sharedRewriteEnabled() {
		shared = nil
	}
	if err := d.resumeCapture(i.localTCEnabled(), i.localTCEnabled() && i.localIPv6 || i.sharedSocketAssignEnabled() && i.sharedIPv6, local, shared, i.hostAddresses()); err != nil {
		return E.Errors(err, d.suspendCapture())
	}
	i.captureDeferredState.Store(false)
	return nil
}

func (i *Inbound) deactivateTCCapture() error {
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	i.captureDeferredState.Store(true)
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	return i.tcDataPlane.suspendCapture()
}
