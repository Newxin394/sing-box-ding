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

func (o *captureOwner) Prepare() error {
	if o == nil || o.inbound == nil {
		return errTUNCaptureUnavailable
	}
	if o.inbound.tunIf == nil || o.inbound.tunStack == nil {
		return errTUNCaptureUnavailable
	}
	return nil
}

func (o *captureOwner) Activate() error {
	o.access.Lock()
	defer o.access.Unlock()
	if o.active {
		return nil
	}
	if err := o.Prepare(); err != nil {
		return err
	}
	if o.inbound.autoRedirect != nil {
		if err := o.inbound.autoRedirect.Start(); err != nil {
			return err
		}
	}
	o.active = true
	o.inbound.captureActive = true
	return nil
}

func (o *captureOwner) Deactivate() error {
	o.access.Lock()
	defer o.access.Unlock()
	if !o.active {
		return nil
	}
	if o.inbound.autoRedirect != nil {
		if err := o.inbound.autoRedirect.Close(); err != nil {
			return err
		}
	}
	o.active = false
	o.inbound.captureActive = false
	return nil
}

func (o *captureOwner) Close() error {
	o.access.Lock()
	defer o.access.Unlock()
	if o.active && o.inbound.autoRedirect != nil {
		if err := o.inbound.autoRedirect.Close(); err != nil {
			return err
		}
	}
	o.active = false
	o.inbound.captureActive = false
	return nil
}
