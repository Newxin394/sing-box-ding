//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"

	"github.com/sagernet/netlink"
	"github.com/sagernet/netlink/nl"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// localRouteSet owns the per-interface local-table routes created for the
// redirect token prefixes. The loopback routes themselves stay in
// redirect_route.go; this set only manages the interface routes
// reconcileLocalInterfaceRoutes installs, so the two owners never fight over
// the same route.
type localRouteSet struct {
	access   sync.Mutex
	prefixes []netip.Prefix
	// interfaceRoutes are the per-interface routes installed by
	// reconcileLocalInterfaceRoutes, keyed by prefix and interface.
	interfaceRoutes map[localInterfaceRouteKey]localInterfaceRoute
	closing         bool
}

type localInterfaceRouteKey struct {
	prefix    netip.Prefix
	linkIndex int
}

// localRouteProtocol marks the interface routes this file installs
// (rtm_protocol 83, unassigned in iproute2's rt_protos), so route conflict
// checks and later reconciliation can tell them apart from anyone else's
// routes.
const localRouteProtocol netlink.RouteProtocol = 83

// localRouteInterfacePriorityBase orders a prefix's interface routes after
// its loopback route, so a lookup without a required output interface keeps
// using the loopback route. Each interface route takes the base plus its
// interface index: a unique priority keeps every interface's route a separate
// entry rather than one replacing another.
const localRouteInterfacePriorityBase = 0x53000000

func newLocalRouteSet(prefixes []netip.Prefix) *localRouteSet {
	set := &localRouteSet{interfaceRoutes: make(map[localInterfaceRouteKey]localInterfaceRoute)}
	for _, prefix := range prefixes {
		set.prefixes = append(set.prefixes, prefix.Masked())
	}
	return set
}

// reconcileLocalInterfaceRoutes installs each prefix as a local route on every
// interface that is up and carries an address of the prefix's family, and
// removes the routes it installed for interfaces that no longer qualify. It
// reports whether any route changed.
//
// A socket bound to an interface (SO_BINDTODEVICE, IP_UNICAST_IF or
// IPV6_UNICAST_IF, as systemd-resolved binds the sockets for its DNS servers)
// routes with that interface as the required output device, and the kernel
// skips every route whose next hop is another device, the prefix's loopback
// route included. A connection a cgroup program redirected into the prefix
// would follow the default route out of the interface instead of reaching the
// listener. The interface route keeps the lookup local, and its source address,
// one of the interface's own, brings the listener's replies back on the
// interface the socket is bound to, so the socket accepts them.
//
// An IPv4 prefix is otherwise covered only by the kernel's 127.0.0.0/8 loopback
// route, which the more specific interface routes would take over; the
// reconciliation therefore also keeps the prefix on the loopback interface,
// ahead of them, so sockets without a bound interface keep 127.0.0.1 as their
// source. The loopback route itself is owned by redirect_route.go; what this
// function installs for loopback is only the priority that outranks the
// interface routes, never a second route.
//
// The kernel deletes a route together with its source address, so this must
// run again whenever interfaces or addresses change.
func (s *localRouteSet) reconcileLocalInterfaceRoutes() (bool, error) {
	if s == nil {
		return false, nil
	}
	s.access.Lock()
	defer s.access.Unlock()
	if s.closing || len(s.prefixes) == 0 {
		return false, nil
	}
	desired, err := desiredLocalInterfaceRoutes(s.prefixes)
	if err != nil {
		return false, err
	}
	current, err := listLocalInterfaceRoutes(s.prefixes)
	if err != nil {
		return false, err
	}
	if s.interfaceRoutes == nil {
		s.interfaceRoutes = make(map[localInterfaceRouteKey]localInterfaceRoute)
	}
	changed := false
	var routeErr error
	for key, route := range s.interfaceRoutes {
		if _, wanted := desired[key]; wanted {
			continue
		}
		if err = deleteLocalInterfaceRoute(route); err != nil {
			routeErr = E.Errors(routeErr, E.Cause(err, "remove local route for ", key.prefix, " from interface ", key.linkIndex))
			continue
		}
		delete(s.interfaceRoutes, key)
		changed = true
	}
	for key, route := range desired {
		if installed, present := current[key]; present && installed == route {
			// A matching route left by an instance that did not shut down is
			// adopted, so close removes it.
			s.interfaceRoutes[key] = route
			continue
		}
		if err = replaceLocalInterfaceRoute(route); err != nil {
			routeErr = E.Errors(routeErr, E.Cause(err, "add local route for ", key.prefix, " on interface ", key.linkIndex))
			continue
		}
		s.interfaceRoutes[key] = route
		changed = true
	}
	return changed, routeErr
}

// localInterfaceRoute is a local-table route of a redirect prefix through one
// interface, with that interface's address as the preferred source.
type localInterfaceRoute struct {
	prefix    netip.Prefix
	linkIndex int
	source    netip.Addr
	priority  uint32
}

// desiredLocalInterfaceRoutes returns the interface routes prefixes need on
// the interfaces present now, with each interface's preferred address of the
// prefix's family as the source. An interface without one has no use for the
// route: a socket bound to it cannot send that family anyway.
func desiredLocalInterfaceRoutes(prefixes []netip.Prefix) (map[localInterfaceRouteKey]localInterfaceRoute, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, E.Cause(err, "list interfaces for eBPF redirect routes")
	}
	loopbackIndex := 0
	upLinks := make(map[int]bool, len(links))
	for _, link := range links {
		attributes := link.Attrs()
		if attributes.Flags&net.FlagLoopback != 0 {
			loopbackIndex = attributes.Index
			continue
		}
		if attributes.Flags&net.FlagUp != 0 {
			upLinks[attributes.Index] = true
		}
	}
	if loopbackIndex == 0 {
		return nil, E.New("find loopback interface for eBPF redirect routes")
	}
	sources := make(map[int]map[int]netip.Addr, 2)
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		addresses, listErr := netlink.AddrList(nil, family)
		if listErr != nil {
			return nil, E.Cause(listErr, "list interface addresses for eBPF redirect routes")
		}
		preferred := make(map[int]netlink.Addr)
		for _, address := range addresses {
			if !upLinks[address.LinkIndex] {
				continue
			}
			if _, usable := localInterfaceRouteSource(address); !usable {
				continue
			}
			if existing, loaded := preferred[address.LinkIndex]; loaded &&
				!localInterfaceRouteSourcePreferred(address, existing) {
				continue
			}
			preferred[address.LinkIndex] = address
		}
		familySources := make(map[int]netip.Addr, len(preferred))
		for linkIndex, address := range preferred {
			familySources[linkIndex], _ = localInterfaceRouteSource(address)
		}
		sources[family] = familySources
	}
	desired := make(map[localInterfaceRouteKey]localInterfaceRoute)
	for _, prefix := range prefixes {
		family := candidateFamily(prefix)
		if family == unix.AF_UNSPEC {
			continue
		}
		if family == unix.AF_INET {
			desired[localInterfaceRouteKey{prefix: prefix, linkIndex: loopbackIndex}] = localInterfaceRoute{
				prefix:    prefix,
				linkIndex: loopbackIndex,
				source:    netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			}
		}
		for linkIndex, source := range sources[family] {
			desired[localInterfaceRouteKey{prefix: prefix, linkIndex: linkIndex}] = localInterfaceRoute{
				prefix:    prefix,
				linkIndex: linkIndex,
				source:    source,
				priority:  localRouteInterfacePriorityBase + uint32(linkIndex),
			}
		}
	}
	return desired, nil
}

// localInterfaceRouteSource returns address as an interface route's source if
// it can be one: an IPv4 interface's primary address, or an IPv6 address of
// global scope (which includes unique local addresses) that finished duplicate
// address detection. A link-local IPv6 address cannot address a reply without
// a zone.
func localInterfaceRouteSource(address netlink.Addr) (netip.Addr, bool) {
	if address.IPNet == nil {
		return netip.Addr{}, false
	}
	ip, loaded := netip.AddrFromSlice(address.IP)
	if !loaded {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.Addr{}, false
	}
	if ip.Is4() {
		return ip, address.Flags&unix.IFA_F_SECONDARY == 0
	}
	if address.Scope != unix.RT_SCOPE_UNIVERSE || ip.IsLinkLocalUnicast() ||
		address.Flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED) != 0 {
		return netip.Addr{}, false
	}
	return ip, true
}

// localInterfaceRouteSourcePreferred reports whether candidate is a better
// source than current: an address still preferred for new connections beats a
// deprecated one, and otherwise the address the kernel lists first is kept.
func localInterfaceRouteSourcePreferred(candidate netlink.Addr, current netlink.Addr) bool {
	return current.Flags&unix.IFA_F_DEPRECATED != 0 && candidate.Flags&unix.IFA_F_DEPRECATED == 0
}

// listLocalInterfaceRoutes returns the local-table routes for prefixes that
// carry localRouteProtocol, whoever installed them.
func listLocalInterfaceRoutes(prefixes []netip.Prefix) (map[localInterfaceRouteKey]localInterfaceRoute, error) {
	current := make(map[localInterfaceRouteKey]localInterfaceRoute)
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteListFiltered(
			family,
			&netlink.Route{Table: unix.RT_TABLE_LOCAL, Protocol: localRouteProtocol},
			netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
		if err != nil {
			return nil, E.Cause(err, "list eBPF redirect interface routes")
		}
		for _, route := range routes {
			if route.Type != unix.RTN_LOCAL {
				continue
			}
			prefix, loaded := prefixFromIPNet(route.Dst)
			if !loaded || !slices.Contains(prefixes, prefix) {
				continue
			}
			var source netip.Addr
			if route.Src != nil {
				source, _ = netip.AddrFromSlice(route.Src.IP)
				source = source.Unmap()
			}
			current[localInterfaceRouteKey{prefix: prefix, linkIndex: route.LinkIndex}] = localInterfaceRoute{
				prefix:    prefix,
				linkIndex: route.LinkIndex,
				source:    source,
				priority:  uint32(route.Priority),
			}
		}
	}
	return current, nil
}

// replaceLocalInterfaceRoute installs route in place of any route of the same
// prefix and priority. The request is built by hand because the netlink
// package also sets the source prefix length from a route's source address,
// which would make an IPv6 route source-specific; only RTA_PREFSRC is wanted.
func replaceLocalInterfaceRoute(route localInterfaceRoute) error {
	family := candidateFamily(route.prefix)
	if family == unix.AF_UNSPEC || route.source.Is4() != route.prefix.Addr().Is4() {
		return E.New("invalid eBPF redirect interface route for ", route.prefix, " from ", route.source)
	}
	request := nl.NewNetlinkRequest(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_REPLACE|unix.NLM_F_ACK)
	message := nl.NewRtMsg()
	message.Family = uint8(family)
	message.Dst_len = uint8(route.prefix.Bits())
	message.Table = unix.RT_TABLE_LOCAL
	message.Protocol = uint8(localRouteProtocol)
	message.Scope = unix.RT_SCOPE_HOST
	message.Type = unix.RTN_LOCAL
	request.AddData(message)
	request.AddData(nl.NewRtAttr(unix.RTA_DST, route.prefix.Masked().Addr().AsSlice()))
	request.AddData(nl.NewRtAttr(unix.RTA_PREFSRC, route.source.AsSlice()))
	request.AddData(nl.NewRtAttr(unix.RTA_OIF, nl.Uint32Attr(uint32(route.linkIndex))))
	request.AddData(nl.NewRtAttr(unix.RTA_PRIORITY, nl.Uint32Attr(route.priority)))
	_, err := request.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

func deleteLocalInterfaceRoute(route localInterfaceRoute) error {
	err := netlink.RouteDel(&netlink.Route{
		LinkIndex: route.linkIndex,
		Family:    candidateFamily(route.prefix),
		Dst:       prefixIPNet(route.prefix),
		Scope:     netlink.Scope(unix.RT_SCOPE_HOST),
		Table:     unix.RT_TABLE_LOCAL,
		Type:      unix.RTN_LOCAL,
		Protocol:  localRouteProtocol,
		Priority:  int(route.priority),
	})
	if err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
		return err
	}
	return nil
}

// close removes only routes owned by the set. Failed removals remain owned so
// a later close call can retry them.
func (s *localRouteSet) close() error {
	if s == nil {
		return nil
	}
	s.access.Lock()
	defer s.access.Unlock()
	s.closing = true
	var routeErr error
	for key, route := range s.interfaceRoutes {
		if err := deleteLocalInterfaceRoute(route); err != nil {
			routeErr = E.Errors(routeErr, err)
			continue
		}
		delete(s.interfaceRoutes, key)
	}
	return routeErr
}

func (s *localRouteSet) isClosed() bool {
	if s == nil {
		return true
	}
	s.access.Lock()
	defer s.access.Unlock()
	return len(s.interfaceRoutes) == 0
}

func candidateFamily(prefix netip.Prefix) int {
	if !prefix.IsValid() {
		return unix.AF_UNSPEC
	}
	if prefix.Addr().Is4() {
		return unix.AF_INET
	}
	if prefix.Addr().Is6() && !prefix.Addr().Is4In6() {
		return unix.AF_INET6
	}
	return unix.AF_UNSPEC
}

// prefixOwnsLocalInterfaceRoute reports whether prefix needs interface routes:
// only the cgroup redirect families do, because only cgroup programs redirect
// connections into the prefix in a way a bound socket can then fail to route.
func (i *Inbound) redirectPrefixes() []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, 2)
	if i.redirectIPv4Prefix.IsValid() {
		prefixes = append(prefixes, i.redirectIPv4Prefix)
	}
	if i.cgroupIPv6Enabled() || i.sharedRewriteIPv6Enabled() {
		prefixes = append(prefixes, i.redirectIPv6Prefix)
	}
	return prefixes
}

// reconcileRedirectInterfaceRoutes is the lifecycle-facing entry: it lazily
// creates the set (so a cgroup-disabled inbound never touches the route
// table) and delegates to the set's reconcile. Called under lifecycleAccess.
func (i *Inbound) reconcileRedirectInterfaceRoutes() error {
	if !i.localCgroupEnabled() {
		return nil
	}
	if i.redirectInterfaceRoutes == nil {
		prefixes := i.redirectPrefixes()
		if len(prefixes) == 0 {
			return nil
		}
		i.redirectInterfaceRoutes = newLocalRouteSet(prefixes)
	}
	_, err := i.redirectInterfaceRoutes.reconcileLocalInterfaceRoutes()
	return err
}

func (i *Inbound) closeRedirectInterfaceRoutes() error {
	routes := i.redirectInterfaceRoutes
	if routes == nil {
		return nil
	}
	i.redirectInterfaceRoutes = nil
	return routes.close()
}
