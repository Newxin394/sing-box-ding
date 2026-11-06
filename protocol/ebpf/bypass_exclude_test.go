//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestNormalizeBypassExclude(t *testing.T) {
	v4 := netip.MustParsePrefix("100.64.0.0/10")
	v6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	gotV4, gotV6, err := normalizeBypassExclude("local.bypass_exclude", []netip.Prefix{v4, v6, v4})
	if err != nil {
		t.Fatalf("valid v4+v6 rejected: %v", err)
	}
	if len(gotV4) != 1 || gotV4[0] != v4 || len(gotV6) != 1 || gotV6[0] != v6 {
		t.Fatalf("unexpected normalization: %v %v", gotV4, gotV6)
	}
	// A family may carry several prefixes now; the must-intercept set is a trie.
	secondV4 := netip.MustParsePrefix("10.0.0.0/8")
	gotV4, _, err = normalizeBypassExclude("x", []netip.Prefix{v4, secondV4})
	if err != nil || len(gotV4) != 2 || gotV4[0] != v4 || gotV4[1] != secondV4 {
		t.Fatalf("two IPv4 prefixes rejected: %v %v", gotV4, err)
	}
	secondV6 := netip.MustParsePrefix("fd00::/8")
	if _, gotV6, err = normalizeBypassExclude("x", []netip.Prefix{v6, secondV6}); err != nil || len(gotV6) != 2 {
		t.Fatalf("two IPv6 prefixes rejected: %v %v", gotV6, err)
	}
	mappedV4, _, err := normalizeBypassExclude("x", []netip.Prefix{netip.MustParsePrefix("::ffff:100.64.0.0/106")})
	if err != nil || len(mappedV4) != 1 || mappedV4[0] != v4 {
		t.Fatalf("IPv4-mapped prefix not converted: %v %v", mappedV4, err)
	}
	if _, _, err = normalizeBypassExclude("x", []netip.Prefix{netip.MustParsePrefix("::ffff:0:0/80")}); err == nil {
		t.Fatal("over-wide IPv4-mapped prefix accepted")
	}
	for _, prefix := range []string{"127.0.0.0/8", "0.0.0.0/0", "224.0.0.0/4", "::1/128", "ff00::/8"} {
		if _, _, err = normalizeBypassExclude("x", []netip.Prefix{netip.MustParsePrefix(prefix)}); err == nil {
			t.Fatalf("safety-overlapping prefix %s accepted", prefix)
		}
	}
}

// TestResolveBypassExcludeUnionsScopes covers the second half of the change:
// local and shared used to have to name the same prefix because the kernel held
// one slot, and they are unioned into the one trie the TC classifier reads now.
func TestResolveBypassExcludeUnionsScopes(t *testing.T) {
	a := netip.MustParsePrefix("100.64.0.0/10")
	b := netip.MustParsePrefix("10.8.0.0/16")
	v4, _, err := resolveBypassExclude(true, []netip.Prefix{a}, true, []netip.Prefix{b})
	if err != nil {
		t.Fatalf("differing local/shared IPv4 prefixes rejected: %v", err)
	}
	if len(v4) != 2 || v4[0] != a || v4[1] != b {
		t.Fatalf("unexpected union: %v", v4)
	}
	v4, _, err = resolveBypassExclude(true, []netip.Prefix{a}, true, []netip.Prefix{a})
	if err != nil || len(v4) != 1 || v4[0] != a {
		t.Fatalf("duplicate prefix not collapsed: %v %v", v4, err)
	}
	v4, _, err = resolveBypassExclude(false, []netip.Prefix{a}, true, []netip.Prefix{b})
	if err != nil || len(v4) != 1 || v4[0] != b {
		t.Fatalf("disabled local scope should be ignored: %v %v", v4, err)
	}
}

// TestValidateMustInterceptCapacity pins the split between the planes: TC holds a
// set, cgroup and shared hold one prefix per family, and configuration must say
// so instead of quietly dropping the extra entries.
func TestValidateMustInterceptCapacity(t *testing.T) {
	first := netip.MustParsePrefix("100.64.0.0/10")
	second := netip.MustParsePrefix("10.8.0.0/16")
	fakeIP := netip.MustParsePrefix("198.18.0.0/15")
	twoPrefixes := []netip.Prefix{first, second}
	if err := validateMustInterceptCapacity(true, localDataPlaneCgroup, false, twoPrefixes, nil, netip.Prefix{}, netip.Prefix{}); err == nil {
		t.Fatal("cgroup data plane accepted two IPv4 must-intercept prefixes")
	}
	if err := validateMustInterceptCapacity(true, localDataPlaneTC, false, twoPrefixes, nil, netip.Prefix{}, netip.Prefix{}); err != nil {
		t.Fatalf("tc data plane rejected two IPv4 must-intercept prefixes: %v", err)
	}
	if err := validateMustInterceptCapacity(false, "", true, twoPrefixes, nil, netip.Prefix{}, netip.Prefix{}); err == nil {
		t.Fatal("shared data plane accepted two IPv4 must-intercept prefixes")
	}
	// FakeIP occupies the same slot on the single-slot planes, so it counts.
	if err := validateMustInterceptCapacity(true, localDataPlaneCgroup, false, []netip.Prefix{first}, nil, fakeIP, netip.Prefix{}); err == nil {
		t.Fatal("cgroup data plane accepted a FakeIP range plus a bypass_exclude prefix")
	}
	if err := validateMustInterceptCapacity(true, localDataPlaneTC, false, []netip.Prefix{first}, nil, fakeIP, netip.Prefix{}); err != nil {
		t.Fatalf("tc data plane rejected FakeIP plus bypass_exclude: %v", err)
	}
	if err := validateMustInterceptCapacity(true, localDataPlaneCgroup, false, nil, nil, netip.Prefix{}, netip.Prefix{}); err != nil {
		t.Fatalf("empty configuration rejected: %v", err)
	}
}

func TestBypassExcludeRequiresEnabledScope(t *testing.T) {
	prefix := []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}
	if err := validateLocalOptions(false, option.EBPFLocalOptions{BypassExclude: prefix}); err == nil {
		t.Fatal("local.bypass_exclude accepted while local is disabled")
	}
	if err := validateSharedOptions(false, option.EBPFSharedOptions{BypassExclude: prefix}); err == nil {
		t.Fatal("stray shared.bypass_exclude accepted")
	}
}

func TestRedirectPrefixesAvoidBypassExclude(t *testing.T) {
	first := netip.MustParsePrefix("100.64.0.0/10")
	second := netip.MustParsePrefix("10.8.0.0/16")
	inbound := &Inbound{bypassExcludeIPv4: []netip.Prefix{first, second}}
	prefixes := inbound.forceInterceptPrefixes()
	if len(prefixes) != 2 || prefixes[0] != first || prefixes[1] != second {
		t.Fatalf("bypass_exclude missing from redirect exclusion set: %v", prefixes)
	}
}
