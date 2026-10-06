//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/common/process"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

func (i *Inbound) newTCConnection(
	ctx context.Context,
	backend *commonEBPF.TCBackend,
	conn net.Conn,
	metadata adapter.InboundContext,
	onClose N.CloseHandlerFunc,
) {
	source := M.SocksaddrFromNet(conn.RemoteAddr()).AddrPort()
	destination := M.SocksaddrFromNet(conn.LocalAddr()).AddrPort()
	assignment, err := backend.LookupAssignment(commonEBPF.ProtocolTCP, source, destination, 0, true)
	if err != nil {
		i.counters.assignmentLookupFailures.Add(1)
		i.tcpWarnings.errorContext(i.logger, ctx, "lookup TC eBPF TCP assignment: ", err)
		_ = conn.Close()
		return
	}
	metadata.Inbound = i.Tag()
	metadata.InboundType = i.Type()
	metadata.Source = M.SocksaddrFromNetIP(source)
	metadata.Destination = M.SocksaddrFromNetIP(destination)
	metadata.ProcessInfo = i.lookupProcessInfo(assignment.SocketCookie)
	if assignment.Path == commonEBPF.TCPathShared && assignment.SourceMACValid != 0 {
		metadata.SourceMACAddress = net.HardwareAddr(assignment.SourceMAC[:])
	}
	i.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) newTCPacket(
	backend *commonEBPF.TCBackend,
	buffer *buf.Buffer,
	oob []byte,
	source M.Socksaddr,
	takeOwnership bool,
) bool {
	_, destination, interfaceIndex, err := packetDestinationsFromOOB(oob)
	if err != nil {
		i.udpWarnings.packetInfo.warn(i.logger, "read TC eBPF UDP destination: ", err)
		return false
	}
	if !destination.IsValid() {
		i.udpWarnings.packetInfo.warn(i.logger, "TC eBPF UDP original destination is missing")
		return false
	}
	client := source.AddrPort()
	assignmentKeyInterfaceIndex := interfaceIndex
	assignment, err := backend.LookupAssignment(commonEBPF.ProtocolUDP, client, destination, assignmentKeyInterfaceIndex, false)
	if err != nil && interfaceIndex != 0 {
		assignmentKeyInterfaceIndex = 0
		assignment, err = backend.LookupAssignment(commonEBPF.ProtocolUDP, client, destination, assignmentKeyInterfaceIndex, false)
	}
	if err != nil {
		i.counters.assignmentLookupFailures.Add(1)
		i.udpWarnings.originalDestination.warn(i.logger, "lookup TC eBPF UDP assignment: ", err)
		return false
	}
	var sourceMAC net.HardwareAddr
	if assignment.Path == commonEBPF.TCPathShared && assignment.SourceMACValid != 0 {
		sourceMAC = net.HardwareAddr(assignment.SourceMAC[:])
	}
	scope := udpSessionScopeLocalTC
	if assignment.Path == commonEBPF.TCPathShared {
		scope = udpSessionScopeSharedTC
	}
	key := udpSessionKey{
		Source:         client,
		Scope:          scope,
		SocketCookie:   assignment.SocketCookie,
		InterfaceIndex: assignment.InterfaceIndex,
	}
	i.udpClientTable.setDirectAssignmentBinding(key, destination, sourceMAC, assignmentKeyInterfaceIndex, assignment)
	if takeOwnership {
		i.udpNat.NewPacketBuffer(key, buffer, source, M.SocksaddrFromNetIP(destination), nil)
		return true
	}
	i.udpNat.NewPacket(key, [][]byte{buffer.Bytes()}, source, M.SocksaddrFromNetIP(destination), nil)
	return false
}

func (i *Inbound) lookupProcessInfo(socketCookie uint64) *adapter.ConnectionOwner {
	if socketCookie == 0 || i.processTracker == nil {
		return nil
	}
	owner, err := i.processTracker.LookupOwner(socketCookie)
	if err != nil {
		i.logger.Trace("lookup eBPF socket process owner: ", err)
		return nil
	}
	// The owner lookup above is a single map hit and stays uncached because a
	// socket cookie is unique per socket. Resolving that owner into a process
	// path and package name is the expensive half -- a /proc readlink plus a
	// package manager lookup -- and every new connection from the same app
	// repeats it with an identical answer.
	if i.processInfoCache != nil {
		return i.processInfoCache.load(
			processInfoCacheKey{processID: owner.ProcessID, userID: owner.UserID},
			i.networkManager.PackageManager(),
		)
	}
	processInfo, pathErr := process.FindProcessInfoByPID(
		owner.ProcessID,
		owner.UserID,
		i.networkManager.PackageManager(),
	)
	if pathErr != nil {
		i.logger.Trace("resolve eBPF socket process path: ", pathErr)
	}
	return processInfo
}

func (i *Inbound) prepareTCPacketConnection(
	_ M.Socksaddr,
	_ M.Socksaddr,
	key udpSessionKey,
) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	ctx := log.ContextWithNewID(i.ctx)
	clientState := i.udpClientTable.loadOrCreate(key)
	writer := &tcPacketWriter{inbound: i, key: key, clientState: clientState}
	return true, ctx, writer, func(error) {
		cleanup := i.udpClientTable.deleteWithCleanup(key, clientState)
		i.deleteCgroupUDPRedirects(cleanup.cgroupRedirects)
		i.deleteTCAssignments(key, cleanup.tcAssignments)
	}
}

func (i *Inbound) deleteTCAssignments(key udpSessionKey, assignments []tcAssignmentCleanup) {
	if len(assignments) == 0 || (key.Scope != udpSessionScopeLocalTC && key.Scope != udpSessionScopeSharedTC) {
		return
	}
	i.tcDataPlaneAccess.RLock()
	dataPlane := i.tcDataPlane
	i.tcDataPlaneAccess.RUnlock()
	if dataPlane == nil {
		return
	}
	backend := dataPlane.Backend()
	if backend == nil || backend.IsClosed() {
		return
	}
	for _, cleanup := range assignments {
		if _, err := backend.RemoveAssignmentIfMatch(
			commonEBPF.ProtocolUDP,
			key.Source,
			cleanup.destination,
			cleanup.keyInterfaceIndex,
			cleanup.assignment,
		); err != nil && !errors.Is(err, unix.EBADF) {
			i.udpWarnings.cleanup.warn(i.logger, "delete TC eBPF UDP assignment: ", err)
		}
	}
}

type tcPacketWriter struct {
	inbound     *Inbound
	key         udpSessionKey
	clientState *udpClientState
}

func (w *tcPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	binding, err := w.ensureReplyBinding(destination.AddrPort())
	if err != nil {
		return err
	}
	if w.clientState.isCgroupDataPlane() {
		return w.inbound.listeners.writeUDP(buffer.Bytes(), binding.packetInfo, w.key.Source, binding.redirectAddress)
	}
	socket, release, err := w.inbound.udpReplySockets.getWithCleanup(destination.AddrPort(), w.inbound.newTCUDPReplySocket)
	if err != nil {
		return err
	}
	defer release()
	_, err = socket.conn.WriteToUDPAddrPort(buffer.Bytes(), w.key.Source)
	return err
}

func (w *tcPacketWriter) ensureReplyBinding(destinationAddress netip.AddrPort) (udpRedirectBinding, error) {
	binding, loaded := w.clientState.redirectBinding(destinationAddress)
	if !loaded && w.clientState.isCgroupDataPlane() {
		backend := w.inbound.cgroupBackendInstance()
		if backend == nil {
			return udpRedirectBinding{}, E.New("cgroup eBPF backend is closed")
		}
		redirectAddress, err := backend.ReserveUDPReplyRedirect(destinationAddress, w.inbound.listeners.selectedPort())
		if err != nil {
			return udpRedirectBinding{}, err
		}
		if !w.inbound.udpClientTable.setCgroupReplyBinding(w.key, w.clientState, destinationAddress, redirectAddress) {
			_ = backend.DeleteRedirect(commonEBPF.ProtocolUDP, netip.AddrPortFrom(redirectAddress, w.inbound.listeners.selectedPort()))
			return udpRedirectBinding{}, E.New("cgroup eBPF UDP reply binding was rejected")
		}
		binding, loaded = w.clientState.redirectBinding(destinationAddress)
	}
	if !loaded {
		if !w.clientState.hasAddressFamily(destinationAddress.Addr().Is4()) || !w.inbound.udpClientTable.setDirectReplyBinding(w.key, w.clientState, destinationAddress) {
			return udpRedirectBinding{}, E.New("TC eBPF UDP reply alias limit reached or session closed")
		}
		binding, loaded = w.clientState.redirectBinding(destinationAddress)
	}
	if !loaded {
		return udpRedirectBinding{}, E.New("TC eBPF UDP reply binding is unavailable")
	}
	return binding, nil
}

func (w *tcPacketWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	if len(buffers) == 0 || len(buffers) != len(destinations) {
		buf.ReleaseMulti(buffers)
		return os.ErrInvalid
	}
	groups := make(map[netip.AddrPort][]int)
	for index, destination := range destinations {
		groups[destination.AddrPort()] = append(groups[destination.AddrPort()], index)
	}
	bindings := make(map[netip.AddrPort]udpRedirectBinding, len(groups))
	for destination := range groups {
		binding, err := w.ensureReplyBinding(destination)
		if err != nil {
			buf.ReleaseMulti(buffers)
			return err
		}
		bindings[destination] = binding
	}
	var batchErr error
	for destination, indexes := range groups {
		groupBuffers := make([]*buf.Buffer, 0, len(indexes))
		groupDestinations := make([]M.Socksaddr, 0, len(indexes))
		for _, index := range indexes {
			groupBuffers = append(groupBuffers, buffers[index])
			groupDestinations = append(groupDestinations, M.SocksaddrFromNetIP(w.key.Source))
		}
		if w.clientState.isCgroupDataPlane() {
			sources := make([]netip.Addr, len(groupBuffers))
			for index := range sources {
				sources[index] = bindings[destination].redirectAddress
			}
			err := w.inbound.listeners.writeUDPBatch(groupBuffers, repeatPacketInfo(bindings[destination].packetInfo, len(groupBuffers)), w.key.Source, sources)
			batchErr = errors.Join(batchErr, err)
			continue
		}
		socket, release, err := w.inbound.udpReplySockets.getWithCleanup(destination, w.inbound.newTCUDPReplySocket)
		if err != nil {
			buf.ReleaseMulti(groupBuffers)
			batchErr = errors.Join(batchErr, err)
			continue
		}
		if socket.writer != nil {
			err = socket.writer.WritePacketBatch(groupBuffers, groupDestinations)
		} else {
			for _, buffer := range groupBuffers {
				if _, writeErr := socket.conn.WriteToUDPAddrPort(buffer.Bytes(), w.key.Source); writeErr != nil {
					err = errors.Join(err, writeErr)
				}
				buffer.Release()
			}
		}
		release()
		batchErr = errors.Join(batchErr, err)
	}
	return batchErr
}

func repeatPacketInfo(packetInfo []byte, count int) [][]byte {
	packetInfos := make([][]byte, count)
	for index := range packetInfos {
		packetInfos[index] = packetInfo
	}
	return packetInfos
}

func (i *Inbound) deleteCgroupUDPRedirects(addresses []netip.Addr) {
	backend := i.cgroupBackendInstance()
	if backend == nil {
		return
	}
	for _, address := range addresses {
		destination := netip.AddrPortFrom(address, i.listeners.selectedPort())
		if err := backend.DeleteRedirect(commonEBPF.ProtocolUDP, destination); err != nil && !errors.Is(err, unix.ENOENT) {
			i.udpWarnings.cleanup.warn(i.logger, "delete cgroup eBPF UDP redirect: ", err)
		}
	}
}

func (i *Inbound) newTCUDPReplySocket(source netip.AddrPort) (*net.UDPConn, func(), error) {
	network := "udp6"
	if source.Addr().Is4() {
		network = "udp4"
	}
	var selfBypass *commonEBPF.SelfBypass
	if provider, loaded := i.networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	}); loaded {
		selfBypass = provider.EBPFSelfBypass()
	}
	listenConfig := net.ListenConfig{Control: func(_ string, _ string, rawConn syscall.RawConn) error {
		err := control.Raw(rawConn, func(fd uintptr) error {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
				return err
			}
			if source.Addr().Is4() {
				return unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			}
			if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
				return err
			}
			return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
		})
		if err != nil {
			return err
		}
		if selfBypass != nil {
			return selfBypass.RegisterSocket(rawConn)
		}
		return nil
	}}
	listenConfig.Control = control.Append(listenConfig.Control, control.UDPSocketBuffer(C.UDPSocketBufferSize))
	packetConnection, err := listenConfig.ListenPacket(i.ctx, network, source.String())
	if err != nil {
		return nil, nil, E.Cause(err, "bind TC eBPF UDP reply socket to ", source)
	}
	udpConnection, loaded := packetConnection.(*net.UDPConn)
	if !loaded {
		_ = packetConnection.Close()
		return nil, nil, E.New("TC eBPF UDP reply socket has unexpected type")
	}
	var cleanup func()
	if selfBypass != nil {
		var once sync.Once
		cleanup = func() {
			once.Do(func() {
				rawConn, err := udpConnection.SyscallConn()
				if err == nil {
					_ = selfBypass.UnregisterSocket(rawConn)
				}
			})
		}
	}
	return udpConnection, cleanup, nil
}
