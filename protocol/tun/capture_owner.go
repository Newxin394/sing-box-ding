package tun

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

// Prepare is side-effect free. TUN allocation remains owned by the staged
// inbound lifecycle until the coordinator is wired at the manager level.
func (o *captureOwner) Prepare() error {
	if o == nil || o.inbound == nil {
		return E.New("nil TUN capture owner")
	}
	return nil
}

func (o *captureOwner) Activate() error {
	o.access.Lock()
	defer o.access.Unlock()
	if o.active {
		return nil
	}
	if o.inbound.tunIf == nil || o.inbound.tunStack == nil {
		return E.New("TUN capture is not prepared")
	}
	// The staged lifecycle has already started the TUN stack and auto-redirect.
	// This flag is the seam for the later stop/start split; it must not create a
	// second TUN interface or a second auto-redirect chain.
	o.active = true
	return nil
}

func (o *captureOwner) Deactivate() error {
	o.access.Lock()
	defer o.access.Unlock()
	if !o.active {
		return nil
	}
	// Do not close the stack here yet. The manager-level integration must first
	// add a reversible sing-tun redirect lifecycle; closing it here would tear
	// down resources the existing staged lifecycle still owns.
	o.active = false
	return nil
}

func (o *captureOwner) Close() error {
	o.access.Lock()
	o.active = false
	o.access.Unlock()
	return nil
}
