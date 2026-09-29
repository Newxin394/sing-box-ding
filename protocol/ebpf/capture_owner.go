//go:build with_ebpf && (linux || android)

package ebpf

import (
	"sync"

	"github.com/sagernet/sing-box/common/capture"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ capture.Owner = (*captureOwner)(nil)

type captureOwner struct {
	inbound *Inbound
	access  sync.Mutex
	active  bool
}

func (i *Inbound) CaptureOwner() capture.Owner {
	return &captureOwner{inbound: i}
}

// Prepare is deliberately side-effect free. The existing inbound lifecycle
// owns policy compilation and backend allocation; this owner only controls
// interception after the inbound has been initialized.
func (o *captureOwner) Prepare() error {
	if o == nil || o.inbound == nil {
		return E.New("nil eBPF capture owner")
	}
	return nil
}

// Activate enables the already prepared TC backend. It does not recreate
// links, routes, listeners, or maps.
func (o *captureOwner) Activate() error {
	o.access.Lock()
	defer o.access.Unlock()
	if o.active {
		return nil
	}
	backend := o.inbound.tcBackend()
	if backend == nil {
		return E.New("eBPF TC backend is not prepared")
	}
	if err := o.inbound.activateTCCapture(); err != nil {
		return E.Cause(err, "enable eBPF TC capture")
	}
	o.active = true
	return nil
}

// Deactivate disables packet interception while preserving the prepared
// links and maps for a fast, controlled mode transition.
func (o *captureOwner) Deactivate() error {
	o.access.Lock()
	defer o.access.Unlock()
	if !o.active {
		return nil
	}
	backend := o.inbound.tcBackend()
	if backend == nil {
		o.active = false
		return nil
	}
	if err := o.inbound.deactivateTCCapture(); err != nil {
		return E.Cause(err, "disable eBPF TC capture")
	}
	o.active = false
	return nil
}

func (o *captureOwner) Close() error {
	o.access.Lock()
	o.active = false
	o.access.Unlock()
	return nil
}
