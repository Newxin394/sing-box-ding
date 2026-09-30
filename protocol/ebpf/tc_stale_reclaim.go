//go:build with_ebpf && (linux || android)

package ebpf

import (
	"os"
	"strconv"
	"strings"

	"github.com/sagernet/netlink"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// reclaimStaleTCPolicyRouting removes policy rules and loopback tables left by
// TC data planes of processes that exited without closing them. It must only be
// called while holding the "@sing-box-ebpf-tc-routing" lock: the lock admits a
// single TC routing owner, so any rule carrying the TC signature at that point
// belongs to a dead owner.
//
// A rule is reclaimed only when it is a plain single-bit fwmark rule pointing
// at a table in the TC allocation range, and that table holds exactly the TC
// loopback local routes and nothing else. TUN (masked multi-bit marks, tun0
// routes) and Android netd rules never match this signature.
func reclaimStaleTCPolicyRouting(loopbackIndex int) (int, error) {
	reclaimed := 0
	var reclaimErr error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			if family == unix.AF_INET6 {
				continue
			}
			return reclaimed, E.Cause(err, "list policy rules for TC eBPF reclaim")
		}
		for _, rule := range rules {
			if !isTCPolicyRuleSignature(rule) {
				continue
			}
			routes, ok, err := tcPolicyTableRoutes(loopbackIndex, family, rule.Table)
			if err != nil {
				reclaimErr = E.Errors(reclaimErr, err)
				continue
			}
			if !ok {
				continue
			}
			stale := tcPolicyRuleFor(family, rule.Mark, rule.Table, rule.Priority)
			if err = netlink.RuleDel(stale); !tcPolicyDeleteIgnored(err) {
				reclaimErr = E.Errors(reclaimErr, E.Cause(err, "remove stale TC eBPF policy rule ", rule.Priority))
				continue
			}
			for index := range routes {
				if err = netlink.RouteDel(&routes[index]); !tcPolicyDeleteIgnored(err) {
					reclaimErr = E.Errors(reclaimErr, E.Cause(err, "remove stale TC eBPF route in table ", rule.Table))
				}
			}
			reclaimed++
		}
	}
	return reclaimed, reclaimErr
}

func isTCPolicyRuleSignature(rule netlink.Rule) bool {
	if rule.Mark == 0 || rule.Invert || rule.Goto > 0 ||
		rule.IifName != "" || rule.OifName != "" || rule.UIDRange != nil ||
		rule.Src.IsValid() || rule.Dst.IsValid() {
		return false
	}
	if rule.Mask >= 0 && uint32(rule.Mask) != rule.Mark {
		return false
	}
	if rule.Table < tcPolicyTableMin || rule.Table > tcPolicyTableMax ||
		rule.Priority < tcPolicyPriorityMin || rule.Priority > tcPolicyPriorityMax {
		return false
	}
	for _, candidate := range tcPolicyMarkCandidates {
		if rule.Mark == candidate {
			return true
		}
	}
	return false
}

// tcPolicyTableRoutes returns the routes of a table and whether they are
// exactly the TC loopback routes (empty tables also qualify: a half-closed
// owner may have removed the routes but not the rule).
func tcPolicyTableRoutes(loopbackIndex int, family int, table int) ([]netlink.Route, bool, error) {
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, false, E.Cause(err, "inspect TC eBPF table ", table)
	}
	expected := tcPolicyRoutesForTable(loopbackIndex, family, table)
	if len(routes) > len(expected) {
		return nil, false, nil
	}
	for _, route := range routes {
		if !matchesTCPolicyRoute(route, expected) {
			return nil, false, nil
		}
	}
	return routes, true, nil
}

// reclaimStaleTCDeliveryLinks deletes sbd/sbt veth pairs whose name encodes the
// pid of a process that no longer runs sing-box. Names are "sb[dt]" + 4 hex pid
// + 4 hex sequence (see tcVethNames).
func reclaimStaleTCDeliveryLinks() (int, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return 0, E.Cause(err, "list links for TC eBPF delivery reclaim")
	}
	live := liveSingBoxPIDPrefixes()
	reclaimed := 0
	var reclaimErr error
	for _, link := range links {
		attrs := link.Attrs()
		if attrs == nil || link.Type() != "veth" {
			continue
		}
		name := attrs.Name
		if len(name) != 11 || !(strings.HasPrefix(name, "sbd") || strings.HasPrefix(name, "sbt")) {
			continue
		}
		prefix, err := strconv.ParseUint(name[3:7], 16, 16)
		if err != nil {
			continue
		}
		if _, err = strconv.ParseUint(name[7:], 16, 16); err != nil {
			continue
		}
		if live[uint16(prefix)] {
			continue
		}
		if err = netlink.LinkDel(link); err != nil && !tcLinkNotFound(err) {
			reclaimErr = E.Errors(reclaimErr, E.Cause(err, "remove stale TC eBPF delivery link ", name))
			continue
		}
		reclaimed++
	}
	return reclaimed, reclaimErr
}

func liveSingBoxPIDPrefixes() map[uint16]bool {
	live := map[uint16]bool{uint16(os.Getpid() & 0xffff): true}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return live
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile("/proc/" + entry.Name() + "/comm")
		if err != nil {
			continue
		}
		if strings.Contains(strings.TrimSpace(string(comm)), "sing-box") {
			live[uint16(pid&0xffff)] = true
		}
	}
	return live
}
