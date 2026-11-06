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
	// intercepted before every bypass decision (bypass_exclude). They end up in
	// the same kernel set as the FakeIP range, because both mean "intercept
	// unconditionally", so a family may carry several of them.
	ForceInterceptIPv4 []netip.Prefix
	ForceInterceptIPv6 []netip.Prefix
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
	mustInterceptIPv4       []netip.Prefix
	mustInterceptIPv6       []netip.Prefix
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
	mustInterceptIPv4, err := compileMustInterceptPrefixes("IPv4", fakeIPIPv4, config.ForceInterceptIPv4, true)
	if err != nil {
		return CompiledPolicy{}, err
	}
	mustInterceptIPv6, err := compileMustInterceptPrefixes("IPv6", fakeIPIPv6, config.ForceInterceptIPv6, false)
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
		mustInterceptIPv4:       mustInterceptIPv4,
		mustInterceptIPv6:       mustInterceptIPv6,
		includeSource:           dualStackCIDRPrefixes{ipv4: includeIPv4, ipv6: includeIPv6},
		excludeSource:           dualStackCIDRPrefixes{ipv4: excludeIPv4, ipv6: excludeIPv6},
		includeSourceMAC:        slices.Clone(config.IncludeSourceMAC),
		excludeSourceMAC:        slices.Clone(config.ExcludeSourceMAC),
		localBypassPortEntries:  localBypassPortEntries,
		sharedBypassPortEntries: sharedBypassPortEntries,
	}, nil
}

// compileMustInterceptPrefixes resolves the must-intercept set for one address
// family: the FakeIP range of that family (when configured) unioned with the
// explicit bypass_exclude prefixes. Both mean "intercept before any bypass
// decision", so they share one set, and a set rather than a single slot is what
// lets bypass_exclude carry several prefixes. This replaces the former
// behaviour of refusing a configuration that set both.
func compileMustInterceptPrefixes(family string, fakeIP netip.Prefix, explicit []netip.Prefix, ipv4 bool) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(explicit)+1)
	if fakeIP.IsValid() {
		prefixes = append(prefixes, fakeIP)
	}
	for _, prefix := range explicit {
		normalized, err := normalizeAddressPrefix(family+" bypass_exclude prefix", prefix, ipv4)
		if err != nil {
			return nil, err
		}
		if slices.Contains(prefixes, normalized) {
			continue
		}
		prefixes = append(prefixes, normalized)
	}
	if len(prefixes) > maxMustInterceptPolicyEntries {
		return nil, E.New(family, " must-intercept configuration has ", len(prefixes),
			" prefixes, more than the eBPF map holds (", maxMustInterceptPolicyEntries, ")")
	}
	return prefixes, nil
}

// firstPrefix is what the single-slot data planes (cgroup and shared) can
// express. Configuration refuses to enable one of them for a family whose
// must-intercept set has more than one entry, so reading the first entry here
// is not a silent truncation on those planes.
func firstPrefix(prefixes []netip.Prefix) netip.Prefix {
	if len(prefixes) == 0 {
		return netip.Prefix{}
	}
	return prefixes[0]
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
