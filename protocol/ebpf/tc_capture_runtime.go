//go:build with_ebpf && (linux || android)

package ebpf

import (
	E "github.com/sagernet/sing/common/exceptions"
	"net/netip"
)

// suspendCapture retains program maps/listeners, but releases all packet paths.
// Failed cleanup stays owned so the next call can retry it.
func (d *tcDataPlane) suspendCapture() error {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	if d.backend != nil {
		if err := d.backend.Disable(); err != nil {
			return err
		}
	}
	err := E.Errors(closeTCInterfaceAttachments(d.attachments), d.closeRetired())
	d.attachments = openTCAttachments(d.attachments)
	if len(d.attachments) != 0 || len(d.retiredAttachments) != 0 {
		return E.Errors(err, E.New("TC attachments remain during suspension"))
	}
	err = E.Errors(err, d.routing.Close())
	if d.routing.IsClosed() {
		d.routing = nil
	}
	err = E.Errors(err, d.delivery.Close())
	if d.delivery.IsClosed() {
		d.delivery = nil
	}
	if d.routing != nil || d.delivery != nil || len(d.retiredDeliveries) != 0 {
		return E.Errors(err, E.New("TC resources remain during suspension"))
	}
	d.localInterface = ""
	d.sharedInterfaces = nil
	return err
}

func (d *tcDataPlane) resumeCapture(localEnabled, ipv6 bool, local string, shared []string, hosts []netip.Addr) error {
	d.access.Lock()
	defer d.access.Unlock()
	if d.backend == nil || d.closing {
		return E.New("TC data plane is closed")
	}
	if err := d.closeRetired(); err != nil {
		return err
	}
	var err error
	if d.routing == nil {
		d.routing, err = startTCPolicyRouting(ipv6)
		if err != nil {
			return err
		}
	}
	if err = d.backend.SetRoutingMark(d.routing.mark); err != nil {
		return err
	}
	if localEnabled && d.delivery == nil {
		d.delivery, err = d.createTCDeliveryLink()
		if err != nil {
			return err
		}
	}
	if len(d.attachments) != 0 {
		return E.New("TC activation requires detached interfaces")
	}
	d.attachments, err = d.attachTCInterfaces(local, shared)
	if err != nil {
		return err
	}
	if err = d.backend.UpdateHostAddresses(hosts); err != nil {
		return err
	}
	d.localInterface = local
	d.sharedInterfaces = append([]string(nil), shared...)
	d.hostAddresses = append([]netip.Addr(nil), hosts...)
	return d.backend.Enable()
}
