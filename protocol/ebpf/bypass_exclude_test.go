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
	if err != nil || gotV4 != v4 || gotV6 != v6 {
		t.Fatalf("valid v4+v6 rejected: %v %v %v", gotV4, gotV6, err)
	}
	if _, _, err = normalizeBypassExclude("x", []netip.Prefix{v4, netip.MustParsePrefix("10.0.0.0/8")}); err == nil {
		t.Fatal("two IPv4 prefixes accepted")
	}
	if _, _, err = normalizeBypassExclude("x", []netip.Prefix{v6, netip.MustParsePrefix("fd00::/8")}); err == nil {
		t.Fatal("two IPv6 prefixes accepted")
	}
	mapped, _, err := normalizeBypassExclude("x", []netip.Prefix{netip.MustParsePrefix("::ffff:100.64.0.0/106")})
	if err != nil || mapped != v4 {
		t.Fatalf("IPv4-mapped prefix not converted: %v %v", mapped, err)
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

func TestResolveBypassExclude(t *testing.T) {
	a := netip.MustParsePrefix("100.64.0.0/10")
	b := netip.MustParsePrefix("10.8.0.0/16")
	if _, _, err := resolveBypassExclude(true, []netip.Prefix{a}, true, []netip.Prefix{b}); err == nil {
		t.Fatal("differing local/shared IPv4 prefixes accepted")
	}
	v4, _, err := resolveBypassExclude(true, []netip.Prefix{a}, true, []netip.Prefix{a})
	if err != nil || v4 != a {
		t.Fatalf("identical local/shared prefix rejected: %v %v", v4, err)
	}
	v4, _, err = resolveBypassExclude(false, []netip.Prefix{a}, true, []netip.Prefix{b})
	if err != nil || v4 != b {
		t.Fatalf("disabled local scope should be ignored: %v %v", v4, err)
	}
}

func TestValidateBypassExcludeFakeIP(t *testing.T) {
	v4 := netip.MustParsePrefix("100.64.0.0/10")
	v6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	if err := validateBypassExcludeFakeIP(v4, v6, netip.Prefix{}, netip.Prefix{}); err != nil {
		t.Fatal(err)
	}
	if err := validateBypassExcludeFakeIP(v4, netip.Prefix{}, netip.MustParsePrefix("198.18.0.0/15"), netip.Prefix{}); err == nil {
		t.Fatal("IPv4 FakeIP slot conflict accepted")
	}
	if err := validateBypassExcludeFakeIP(netip.Prefix{}, v6, netip.Prefix{}, netip.MustParsePrefix("fc00::/18")); err == nil {
		t.Fatal("IPv6 FakeIP slot conflict accepted")
	}
	// Different families do not share a slot.
	if err := validateBypassExcludeFakeIP(v4, netip.Prefix{}, netip.Prefix{}, netip.MustParsePrefix("fc00::/18")); err != nil {
		t.Fatal(err)
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
	inbound := &Inbound{bypassExcludeIPv4: netip.MustParsePrefix("100.64.0.0/10")}
	prefixes := inbound.forceInterceptPrefixes()
	if len(prefixes) != 1 || prefixes[0] != inbound.bypassExcludeIPv4 {
		t.Fatalf("bypass_exclude missing from redirect exclusion set: %v", prefixes)
	}
}
