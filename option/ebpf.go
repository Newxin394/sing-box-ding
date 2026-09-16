package option

import (
	"net/netip"

	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common/json/badoption"
)

type EBPFInboundOptions struct {
	Network       NetworkList                `json:"network,omitempty"`
	UDPTimeout    UDPTimeoutCompat           `json:"udp_timeout,omitempty"`
	TCPriority    EBPFTCPriority             `json:"tc_priority,omitempty"`
	PreMatch      bool                       `json:"pre_match,omitempty"`
	BypassRuleSet badoption.Listable[string] `json:"bypass_rule_set,omitempty" reference:"rule_set"`
	Local         EBPFLocalOptions           `json:"local,omitempty"`
	Shared        EBPFSharedOptions          `json:"shared,omitempty"`
	// FakeIPICMP, when "reply", answers ICMP Echo Request packets addressed to
	// a FakeIP so a client's ping sees that address as reachable, without the
	// request ever leaving this box. It applies to whichever of local/shared
	// is enabled and has a TC data plane (local.data_plane=tc, or any shared
	// data plane) — local.data_plane=cgroup has no TC attachment for this to
	// ride on and is rejected explicitly rather than silently doing nothing.
	// The default, "off", changes nothing about existing network semantics.
	FakeIPICMP string `json:"fakeip_icmp,omitempty" enum:"off,reply"`
	// MapCapacity overrides the kernel map capacities this inbound preallocates.
	// It is not a set of upper bounds on usage: every one of these maps is an
	// LRU hash, whose entries the kernel allocates up front, so the capacity is
	// a fixed cost in locked kernel memory that exists whether or not there is
	// any traffic. Omitted fields keep the default; see EBPFMapCapacityOptions.
	MapCapacity *EBPFMapCapacityOptions `json:"map_capacity,omitempty"`
}

// EBPFMapCapacityOptions overrides the eBPF inbound's preallocated map
// capacities. Each one is worth lowering on a memory-constrained device, and
// raising on a gateway that must keep many more flows alive than the default
// allows. Every field must be within [1, 1048576]; omitted fields keep their
// default.
type EBPFMapCapacityOptions struct {
	// Assignment is the local TC flow assignment table (default 65536, roughly
	// 4.5 MB preallocated).
	Assignment uint32 `json:"assignment,omitempty"`
	// SelfBypass is the socket-cookie table the local data plane shares between
	// the dialer and the TC classifier (default 65536, roughly 1.0 MB).
	SelfBypass uint32 `json:"self_bypass,omitempty"`
	// ProcessOwner is the cgroup table that carries a socket's owning process to
	// the TC data path (default 65536, roughly 1.0 MB).
	ProcessOwner uint32 `json:"process_owner,omitempty"`
	// Cgroup overrides the cgroup local data plane's own tables.
	Cgroup *EBPFCgroupMapCapacityOptions `json:"cgroup,omitempty"`
}

// EBPFCgroupMapCapacityOptions overrides the cgroup local data plane's maps.
type EBPFCgroupMapCapacityOptions struct {
	TCPRedirect  uint32 `json:"tcp_redirect,omitempty"`
	UDPRedirect  uint32 `json:"udp_redirect,omitempty"`
	UDPPeer      uint32 `json:"udp_peer,omitempty"`
	UDPFlow      uint32 `json:"udp_flow,omitempty"`
	SocketBypass uint32 `json:"socket_bypass,omitempty"`
}

type EBPFLocalOptions struct {
	Enabled              *bool                      `json:"enabled,omitempty"`
	DNSMode              string                     `json:"dns_mode,omitempty" enum:"hijack,respect_policy,off"`
	DataPlane            string                     `json:"data_plane,omitempty" enum:"tc,cgroup"`
	CgroupPath           string                     `json:"cgroup_path,omitempty"`
	IPv6                 *bool                      `json:"ipv6,omitempty"`
	BypassPrivateAddress *bool                      `json:"bypass_private_address,omitempty"`
	BypassSelector       *EBPFBypassSelectorOptions `json:"bypass_selector,omitempty"`
	IncludeUID           badoption.Listable[uint32] `json:"include_uid,omitempty"`
	IncludeUIDRange      badoption.Listable[string] `json:"include_uid_range,omitempty"`
	ExcludeUID           badoption.Listable[uint32] `json:"exclude_uid,omitempty"`
	ExcludeUIDRange      badoption.Listable[string] `json:"exclude_uid_range,omitempty"`
	IncludeAndroidUser   badoption.Listable[int]    `json:"include_android_user,omitempty"`
	IncludePackage       badoption.Listable[string] `json:"include_package,omitempty"`
	ExcludePackage       badoption.Listable[string] `json:"exclude_package,omitempty"`
	BypassPort           badoption.Listable[uint16] `json:"bypass_port,omitempty"`
	BypassPortRange      badoption.Listable[string] `json:"bypass_port_range,omitempty"`
}

type EBPFBypassSelectorOptions struct {
	Tag                          string                     `json:"tag" reference:"outbound"`
	BypassWhen                   badoption.Listable[string] `json:"bypass_when" reference:"outbound"`
	SettleDelay                  badoption.Duration         `json:"settle_delay,omitempty"`
	FinalCheckDelay              badoption.Duration         `json:"final_check_delay,omitempty"`
	RapidSwitchWindow            badoption.Duration         `json:"rapid_switch_window,omitempty"`
	RapidSwitchThreshold         uint16                     `json:"rapid_switch_threshold,omitempty"`
	InterruptExistingConnections bool                       `json:"interrupt_existing_connections,omitempty"`
}

type EBPFSharedOptions struct {
	Enabled              *bool                            `json:"enabled,omitempty"`
	DataPlane            string                           `json:"data_plane,omitempty" enum:"socket_assign,packet_rewrite"`
	DNSMode              string                           `json:"dns_mode,omitempty" enum:"hijack,respect_policy,off"`
	Interface            badoption.Listable[string]       `json:"interface,omitempty"`
	IPv6                 *bool                            `json:"ipv6,omitempty"`
	BypassPrivateAddress *bool                            `json:"bypass_private_address,omitempty"`
	IncludeSourceCIDR    badoption.Listable[netip.Prefix] `json:"include_source_cidr,omitempty"`
	ExcludeSourceCIDR    badoption.Listable[netip.Prefix] `json:"exclude_source_cidr,omitempty"`
	IncludeMACAddress    badoption.Listable[string]       `json:"include_mac_address,omitempty"`
	ExcludeMACAddress    badoption.Listable[string]       `json:"exclude_mac_address,omitempty"`
	BypassPort           badoption.Listable[uint16]       `json:"bypass_port,omitempty"`
	BypassPortRange      badoption.Listable[string]       `json:"bypass_port_range,omitempty"`
}

// EffectiveEnablement returns the local and shared paths selected by the
// current configuration. With no explicit enablement, local interception is
// enabled by default.
func (o EBPFInboundOptions) EffectiveEnablement() (local, shared bool) {
	if o.Local.Enabled != nil || o.Shared.Enabled != nil {
		return o.Local.Enabled != nil && *o.Local.Enabled, o.Shared.Enabled != nil && *o.Shared.Enabled
	}
	return true, false
}

type EBPFTCPriority uint16

func (EBPFTCPriority) DescribeSchema(schema.Builder) (*schema.Node, error) {
	minimum := int64(1)
	maximum := uint64(1<<16 - 1)
	return &schema.Node{
		Type:    "integer",
		Minimum: &minimum,
		Maximum: &maximum,
	}, nil
}
