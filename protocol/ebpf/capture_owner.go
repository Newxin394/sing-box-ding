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

func (o *captureOwner) Prepare() error {
	if o == nil || o.inbound == nil {
		return E.New("nil eBPF capture owner")
	}
	if o.inbound.tcBackend() == nil {
		return E.New("eBPF TC backend is not prepared")
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
	if err := o.inbound.activateTCCapture(); err != nil {
		return E.Cause(err, "enable eBPF TC capture")
	}
	o.active = true
	return nil
}

func (o *captureOwner) Deactivate() error {
	o.access.Lock()
	defer o.access.Unlock()
	if err := o.inbound.deactivateTCCapture(); err != nil {
		return E.Cause(err, "disable eBPF TC capture")
	}
	o.active = false
	return nil
}

func (o *captureOwner) Close() error {
	o.access.Lock()
	defer o.access.Unlock()
	if err := o.inbound.deactivateTCCapture(); err != nil {
		return E.Cause(err, "disable eBPF TC capture")
	}
	o.active = false
	return nil
}
