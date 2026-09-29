//go:build with_ebpf && (linux || android)

package ebpf

import (
	E "github.com/sagernet/sing/common/exceptions"
)

// activateTCCapture and deactivateTCCapture are the only operations exposed to
// the capture coordinator. They deliberately touch the backend control map,
// not the attachment topology: filters, delivery veth, policy routing and
// listeners remain owned by the staged inbound lifecycle.
func (i *Inbound) activateTCCapture() error {
	backend := i.tcBackend()
	if backend == nil {
		return E.New("TC backend is not prepared")
	}
	return backend.Enable()
}

func (i *Inbound) deactivateTCCapture() error {
	backend := i.tcBackend()
	if backend == nil {
		return nil
	}
	return backend.Disable()
}
