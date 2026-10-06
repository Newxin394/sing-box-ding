//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"slices"

	E "github.com/sagernet/sing/common/exceptions"
)

type PolicyConfig struct {
	EnableTCP           bool
	EnableUDP           bool
	Local               LocalPolicy
	SharedDNSMode       DNSMode
	SharedBypassPrivate bool
	FakeIPIPv4          netip.Prefix
	FakeIPIPv6          netip.Prefix
	// ForceInterceptIPv4/IPv6 are non-FakeIP destinations that must be
	// intercepted before every bypass decision (bypass_exclude). The kernel has
	// one force-intercept slot per family, shared with FakeIP, so a valid
	// ForceIntercept prefix may only be set where that family has no FakeIP.
	ForceInterceptIPv4 netip.Prefix
	ForceInterceptIPv6 netip.Prefix
	IncludeSourceCIDR  []netip.Prefix
	ExcludeSourceCIDR  []netip.Prefix
	IncludeSourceMAC   []MACAddress
	ExcludeSourceMAC   []MACAddress
	LocalBypassPort    []PortRange
	SharedBypassPort   []PortRange
}

// CompiledPolicy is an immutable policy snapshot shared by all eBPF data
// planes created for one inbound.
type CompiledPolicy struct {
	local                   LocalPolicy
	uidEntries              []uidLPMKey
	uidDefaultBypass        bool
	sharedDNSMode           DNSMode
	sharedBypassPrivate     bool
	fakeIPIPv4              netip.Prefix
	fakeIPIPv6              netip.Prefix
	forceInterceptIPv4      netip.Prefix
	forceInterceptIPv6      netip.Prefix
	includeSource           dualStackCIDRPrefixes
	excludeSource           dualStackCIDRPrefixes
	includeSourceMAC        []MACAddress
	excludeSourceMAC        []MACAddress
	localBypassPortEntries  []tcPortKey
	sharedBypassPortEntries []tcPortKey
}

func CompilePolicy(config PolicyConfig) (CompiledPolicy, error) {
	uidEntries, uidDefaultBypass, err := compileUIDPolicy(config.Local)
	if err != nil {
		return CompiledPolicy{}, err
	}
	fakeIPIPv4, err := normalizeAddressPrefix("IPv4 FakeIP range", config.FakeIPIPv4, true)
	if err != nil {
		return CompiledPolicy{}, err
	}
	fakeIPIPv6, err := normalizeAddressPrefix("IPv6 FakeIP range", config.FakeIPIPv6, false)
	if err != nil {
		return CompiledPolicy{}, err
	}
	forceInterceptIPv4, err := compileForceInterceptPrefix("IPv4", fakeIPIPv4, config.ForceInterceptIPv4, true)
	if err != nil {
		return CompiledPolicy{}, err
	}
	forceInterceptIPv6, err := compileForceInterceptPrefix("IPv6", fakeIPIPv6, config.ForceInterceptIPv6, false)
	if err != nil {
		return CompiledPolicy{}, err
	}
	includeIPv4, includeIPv6, err := compileBypassCIDRPolicy(config.IncludeSourceCIDR)
	if err != nil {
		return CompiledPolicy{}, E.Cause(err, "compile eBPF include source CIDR policy")
	}
	excludeIPv4, excludeIPv6, err := compileBypassCIDRPolicy(config.ExcludeSourceCIDR)
	if err != nil {
		return CompiledPolicy{}, E.Cause(err, "compile eBPF exclude source CIDR policy")
	}
	if len(includeIPv4) > maxSharedSourceCIDRPolicyEntries || len(includeIPv6) > maxSharedSourceCIDRPolicyEntries ||
		len(excludeIPv4) > maxSharedSourceCIDRPolicyEntries || len(excludeIPv6) > maxSharedSourceCIDRPolicyEntries {
		return CompiledPolicy{}, E.New("eBPF source CIDR policy exceeds map capacity")
	}
	if len(config.IncludeSourceMAC) > maxSharedSourceMACPolicyEntries ||
		len(config.ExcludeSourceMAC) > maxSharedSourceMACPolicyEntries {
		return CompiledPolicy{}, E.New("eBPF source MAC policy exceeds map capacity")
	}
	localBypassPortEntries, err := compilePortPolicy(config.LocalBypassPort, config.EnableTCP, config.EnableUDP)
	if err != nil {
		return CompiledPolicy{}, E.Cause(err, "compile local eBPF port bypass policy")
	}
	sharedBypassPortEntries, err := compilePortPolicy(config.SharedBypassPort, config.EnableTCP, config.EnableUDP)
	if err != nil {
		return CompiledPolicy{}, E.Cause(err, "compile shared eBPF port bypass policy")
	}
	local := config.Local
	local.IncludeUID = slices.Clone(local.IncludeUID)
	local.ExcludeUID = slices.Clone(local.ExcludeUID)
	return CompiledPolicy{
		local:                   local,
		uidEntries:              uidEntries,
		uidDefaultBypass:        uidDefaultBypass,
		sharedDNSMode:           config.SharedDNSMode,
		sharedBypassPrivate:     config.SharedBypassPrivate,
		fakeIPIPv4:              fakeIPIPv4,
		fakeIPIPv6:              fakeIPIPv6,
		forceInterceptIPv4:      forceInterceptIPv4,
		forceInterceptIPv6:      forceInterceptIPv6,
		includeSource:           dualStackCIDRPrefixes{ipv4: includeIPv4, ipv6: includeIPv6},
		excludeSource:           dualStackCIDRPrefixes{ipv4: excludeIPv4, ipv6: excludeIPv6},
		includeSourceMAC:        slices.Clone(config.IncludeSourceMAC),
		excludeSourceMAC:        slices.Clone(config.ExcludeSourceMAC),
		localBypassPortEntries:  localBypassPortEntries,
		sharedBypassPortEntries: sharedBypassPortEntries,
	}, nil
}

// compileForceInterceptPrefix resolves the single kernel force-intercept slot
// for one address family. FakeIP owns the slot when configured; otherwise an
// explicit bypass_exclude prefix may use it.
func compileForceInterceptPrefix(family string, fakeIP, explicit netip.Prefix, ipv4 bool) (netip.Prefix, error) {
	explicit, err := normalizeAddressPrefix(family+" force-intercept prefix", explicit, ipv4)
	if err != nil {
		return netip.Prefix{}, err
	}
	if fakeIP.IsValid() && explicit.IsValid() {
		return netip.Prefix{}, E.New(family, " force-intercept prefix ", explicit, " conflicts with FakeIP range ", fakeIP)
	}
	if explicit.IsValid() {
		return explicit, nil
	}
	return fakeIP, nil
}

func compilePortPolicy(ranges []PortRange, enableTCP, enableUDP bool) ([]tcPortKey, error) {
	var entries []tcPortKey
	for _, portRange := range ranges {
		if portRange.Start == 0 || portRange.Start > portRange.End {
			return nil, E.New("invalid eBPF port bypass range")
		}
		for port := uint32(portRange.Start); port <= uint32(portRange.End); port++ {
			if enableTCP {
				entries = append(entries, tcPortKey{Protocol: ProtocolTCP, Port: uint16(port)})
			}
			if enableUDP {
				entries = append(entries, tcPortKey{Protocol: ProtocolUDP, Port: uint16(port)})
			}
			if len(entries) > tcPortPolicyCapacity {
				return nil, E.New("eBPF port bypass policy exceeds map capacity")
			}
		}
	}
	return entries, nil
}
