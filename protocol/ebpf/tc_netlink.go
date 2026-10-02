//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func acquireTCInterfaceLock(interfaceName string, interfaceIndex int) (*net.UnixConn, error) {
	connection, err := net.ListenUnixgram("unixgram", &net.UnixAddr{
		Name: "@sing-box-ebpf-tc-" + fmt.Sprint(interfaceIndex),
		Net:  "unixgram",
	})
	if err != nil {
		if errors.Is(err, unix.EADDRINUSE) {
			return nil, E.New("interface ", interfaceName, " is already managed by another TC eBPF inbound")
		}
		return nil, E.Cause(err, "lock TC eBPF interface ", interfaceName)
	}
	return connection, nil
}

func attachTCFilter(
	link netlink.Link,
	parent uint32,
	programFD int,
	programName string,
	handle uint16,
	priority uint16,
) (*netlink.BpfFilter, error) {
	if programFD < 0 {
		return nil, E.New("TC eBPF program is unavailable")
	}
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return nil, err
	}
	filterHandle := netlink.MakeHandle(0, handle)
	for _, existing := range filters {
		bpfFilter, isBPF := existing.(*netlink.BpfFilter)
		if isBPF && bpfFilter.Name == programName {
			if err = netlink.FilterDel(existing); err != nil && !errors.Is(err, unix.ENOENT) {
				return nil, err
			}
			continue
		}
		if existing.Attrs().Handle == filterHandle {
			return nil, E.New("TC filter handle conflict on ", link.Attrs().Name)
		}
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    filterHandle,
			Priority:  priority,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           programFD,
		Name:         programName,
		DirectAction: true,
	}
	if err = netlink.FilterAdd(filter); err != nil {
		return nil, err
	}
	return filter, nil
}

func tcFilterAttached(
	link netlink.Link,
	parent uint32,
	programName string,
	handle uint16,
	priority uint16,
) (bool, error) {
	return tcFilterAttachedByHandle(link, parent, programName, netlink.MakeHandle(0, handle), priority)
}

// tcFilterAttachedByHandle reports whether the named direct-action BPF filter
// is still installed, matching on the full 32-bit filter handle.
//
// Callers that only know the minor part of the handle should use
// tcFilterAttached; callers holding a live *netlink.BpfFilter must pass
// FilterAttrs.Handle verbatim, because truncating it to 16 bits and rebuilding
// it with MakeHandle(0, …) is only lossless while the major part is zero.
func tcFilterAttachedByHandle(
	link netlink.Link,
	parent uint32,
	programName string,
	filterHandle uint32,
	priority uint16,
) (bool, error) {
	filters, err := netlink.FilterList(link, parent)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ESRCH) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, existing := range filters {
		bpfFilter, isBPF := existing.(*netlink.BpfFilter)
		if !isBPF {
			continue
		}
		attributes := bpfFilter.Attrs()
		if attributes.Handle == filterHandle &&
			attributes.Priority == priority &&
			bpfFilter.Name == programName &&
			bpfFilter.DirectAction {
			return true, nil
		}
	}
	return false, nil
}

func detachTCFilter(filter *netlink.BpfFilter) error {
	if filter == nil {
		return nil
	}
	err := netlink.FilterDel(filter)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	if errors.Is(err, unix.EINVAL) {
		// The kernel returns EINVAL instead of ENOENT when the parent clsact
		// qdisc is already gone (netd flushes it on interface refreshes).
		// The filter cannot survive its qdisc, so treat the deletion as done
		// once a fresh filter listing confirms it is absent.
		link, linkErr := netlink.LinkByIndex(filter.LinkIndex)
		if linkErr != nil {
			// Only a vanished interface implies the filter is gone with it;
			// any other netlink failure leaves the state unknown, so report
			// the original EINVAL instead of assuming success.
			if errors.Is(linkErr, unix.ENODEV) || errors.Is(linkErr, unix.ENOENT) {
				return nil
			}
			return err
		}
		attached, checkErr := tcFilterAttachedByHandle(link, filter.Parent, filter.Name, filter.Handle, filter.Priority)
		if checkErr != nil {
			// A failed listing cannot prove that the filter disappeared. Keep the
			// original delete error so callers retain ownership instead of racing a
			// possibly live filter after a transient netlink failure.
			return err
		}
		if !attached {
			return nil
		}
	}
	return err
}

var tcClsactLeaseMu sync.Mutex
var tcClsactLeases = make(map[tcClsactLeaseKey]*tcClsactLeaseState)

type tcClsactLeaseKey struct {
	interfaceIndex int
	interfaceName  string
}

type tcClsactLease struct {
	key      tcClsactLeaseKey
	state    *tcClsactLeaseState
	released bool
}

type tcClsactLeaseState struct {
	refs int
}

// acquireTCClsactLease ensures clsact exists and records ownership only when
// this process creates it. A preexisting qdisc may belong to netd or another
// TC consumer, so it is never removed by this owner.
func acquireTCClsactLease(link netlink.Link) (*tcClsactLease, error) {
	index := link.Attrs().Index
	key := tcClsactLeaseKey{interfaceIndex: index, interfaceName: link.Attrs().Name}
	tcClsactLeaseMu.Lock()
	defer tcClsactLeaseMu.Unlock()
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return nil, err
	}
	hasClsact := false
	for _, qdisc := range qdiscs {
		if qdisc.Type() == "clsact" {
			hasClsact = true
			break
		}
	}
	state := tcClsactLeases[key]
	if hasClsact {
		if state == nil {
			return nil, nil
		}
		state.refs++
		return &tcClsactLease{key: key, state: state}, nil
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err = netlink.QdiscAdd(qdisc); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil, nil
		}
		return nil, err
	}
	if state == nil {
		state = &tcClsactLeaseState{}
		tcClsactLeases[key] = state
	}
	state.refs++
	return &tcClsactLease{key: key, state: state}, nil
}

func ensureTCAttachmentClsact(link netlink.Link, attachment *tcInterfaceAttachment) error {
	if attachment == nil {
		return E.New("TC eBPF attachment is unavailable")
	}
	if attachment.clsactLease != nil {
		return ensureTCClsact(link)
	}
	lease, err := acquireTCClsactLease(link)
	if err != nil {
		return err
	}
	attachment.clsactLease = lease
	return nil
}

// releaseTCClsactLease removes only an empty clsact created by this process.
// A foreign filter means another consumer still owns the qdisc; ownership is
// relinquished and the qdisc is left in place.
func releaseTCClsactLease(lease **tcClsactLease) error {
	if lease == nil || *lease == nil || (*lease).released {
		return nil
	}
	current := *lease
	tcClsactLeaseMu.Lock()
	defer tcClsactLeaseMu.Unlock()
	state := tcClsactLeases[current.key]
	if state == nil || state != current.state {
		current.released = true
		*lease = nil
		return nil
	}
	if state.refs > 1 {
		state.refs--
		current.released = true
		*lease = nil
		return nil
	}
	link, err := netlink.LinkByIndex(current.key.interfaceIndex)
	if err != nil {
		if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENOENT) {
			delete(tcClsactLeases, current.key)
			current.released = true
			*lease = nil
			return nil
		}
		return err
	}
	if link.Attrs() == nil || link.Attrs().Name != current.key.interfaceName {
		delete(tcClsactLeases, current.key)
		current.released = true
		*lease = nil
		return nil
	}
	var ownedQdisc netlink.Qdisc
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}
	for _, qdisc := range qdiscs {
		if qdisc.Type() == "clsact" {
			ownedQdisc = qdisc
			break
		}
	}
	if ownedQdisc == nil {
		delete(tcClsactLeases, current.key)
		current.released = true
		*lease = nil
		return nil
	}
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		filters, listErr := netlink.FilterList(link, parent)
		if listErr != nil {
			if errors.Is(listErr, unix.ENOENT) || errors.Is(listErr, unix.ENODEV) || errors.Is(listErr, unix.ESRCH) {
				continue
			}
			return listErr
		}
		if len(filters) != 0 {
			delete(tcClsactLeases, current.key)
			current.released = true
			*lease = nil
			return nil
		}
	}
	if err = netlink.QdiscDel(ownedQdisc); err != nil {
		if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENODEV) {
			return err
		}
	}
	delete(tcClsactLeases, current.key)
	current.released = true
	*lease = nil
	return nil
}

func ensureTCClsact(link netlink.Link) error {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}
	for _, qdisc := range qdiscs {
		if qdisc.Type() == "clsact" {
			return nil
		}
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err = netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}

func tcLinkNotFound(err error) bool {
	if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENOENT) {
		return true
	}
	var linkNotFoundError netlink.LinkNotFoundError
	return errors.As(err, &linkNotFoundError)
}

func tcLinkFraming(link netlink.Link) (commonEBPF.TCLinkFraming, error) {
	if link == nil || link.Attrs() == nil {
		return commonEBPF.TCLinkFramingUnsupported, E.New("invalid TC eBPF interface")
	}
	attributes := link.Attrs()
	framing := commonEBPF.ClassifyTCLinkFraming(attributes.EncapType, len(attributes.HardwareAddr))
	if framing == commonEBPF.TCLinkFramingUnsupported {
		return framing, E.New(
			"TC eBPF interface ", attributes.Name,
			" has unsupported link encapsulation ", attributes.EncapType,
		)
	}
	return framing, nil
}
