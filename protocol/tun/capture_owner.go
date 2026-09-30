package tun

import (
	"errors"
	"sync"

	"github.com/sagernet/sing-box/common/capture"
)

var errTUNCaptureUnavailable = errors.New("TUN capture is unavailable")

var _ capture.Owner = (*captureOwner)(nil)

type captureOwner struct {
	inbound *Inbound
	access  sync.Mutex
	active  bool
}

func (i *Inbound) CaptureOwner() capture.Owner {
	return &captureOwner{inbound: i}
}

// SetCaptureDeferred suppresses the inbound's self-activation in the staged
// lifecycle so the capture coordinator can establish a single-active baseline.
// With deferral on, StartStateStart builds no TUN runtime and StartStatePostStart
// starts nothing; activation happens exclusively through Activate. It is called
// during construction, before any staged lifecycle runs, so no locking is needed.
func (i *Inbound) SetCaptureDeferred(deferred bool) {
	i.captureDeferred = deferred
}

func (o *captureOwner) Prepare() error {
	if o == nil || o.inbound == nil {
		return errTUNCaptureUnavailable
	}
	// Nothing to allocate up front: Activate rebuilds the TUN interface and
	// stack from scratch, because a closed NativeTun file descriptor cannot be
	// reopened. Prepare only validates the owner is wired.
	return nil
}

func (o *captureOwner) Activate() error {
	o.access.Lock()
	defer o.access.Unlock()
	if o.active {
		return nil
	}
	o.inbound.captureAccess.Lock()
	defer o.inbound.captureAccess.Unlock()
	if o.inbound.tunIf == nil || o.inbound.tunStack == nil {
		if err := o.inbound.buildTunRuntime(o.inbound.tunOptions); err != nil {
			return err
		}
	}
	if err := o.inbound.startTunCapture(); err != nil {
		return err
	}
	o.active = true
	return nil
}

func (o *captureOwner) Deactivate() error {
	o.access.Lock()
	defer o.access.Unlock()
	if !o.active {
		return nil
	}
	o.inbound.captureAccess.Lock()
	defer o.inbound.captureAccess.Unlock()
	if err := o.inbound.teardownTunCapture(); err != nil {
		return err
	}
	o.active = false
	return nil
}

func (o *captureOwner) Close() error {
	o.access.Lock()
	defer o.access.Unlock()
	o.inbound.captureAccess.Lock()
	defer o.inbound.captureAccess.Unlock()
	if o.active {
		if err := o.inbound.teardownTunCapture(); err != nil {
			return err
		}
	}
	o.active = false
	return nil
}
