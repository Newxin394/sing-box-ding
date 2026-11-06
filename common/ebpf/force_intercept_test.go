//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
)

func TestCompilePolicyForceIntercept(t *testing.T) {
	bypassV4 := netip.MustParsePrefix("100.64.1.2/10")
	bypassV6 := netip.MustParsePrefix("fd7a:115c:a1e0::1/48")
	policy, err := CompilePolicy(PolicyConfig{
		EnableTCP:          true,
		ForceInterceptIPv4: []netip.Prefix{bypassV4},
		ForceInterceptIPv6: []netip.Prefix{bypassV6},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.mustInterceptIPv4) != 1 || policy.mustInterceptIPv4[0] != bypassV4.Masked() {
		t.Fatalf("IPv4 must-intercept not normalized: %v", policy.mustInterceptIPv4)
	}
	if len(policy.mustInterceptIPv6) != 1 || policy.mustInterceptIPv6[0] != bypassV6.Masked() {
		t.Fatalf("IPv6 must-intercept not normalized: %v", policy.mustInterceptIPv6)
	}
	if policy.fakeIPIPv4.IsValid() || policy.fakeIPIPv6.IsValid() {
		t.Fatal("bypass_exclude must not be reported as FakeIP")
	}
	vector := tcFlags(TCConfig{EnableLocal: true, EnableLocalIPv6: true}, policy)
	if vector&tcFlagMustInterceptIPv4 == 0 || vector&tcFlagMustInterceptIPv6 == 0 {
		t.Fatalf("must-intercept flags not set: %#x", vector)
	}
}

// TestCompilePolicyMustInterceptAcceptsSeveralPrefixes covers the reason the
// control block lost its one-prefix-per-family slot: bypass_exclude is allowed
// to list several prefixes in a family, and all of them have to reach the
// kernel.
func TestCompilePolicyMustInterceptAcceptsSeveralPrefixes(t *testing.T) {
	first := netip.MustParsePrefix("100.64.0.0/10")
	second := netip.MustParsePrefix("10.20.0.0/16")
	policy, err := CompilePolicy(PolicyConfig{
		ForceInterceptIPv4: []netip.Prefix{first, second, first},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.mustInterceptIPv4) != 2 {
		t.Fatalf("expected two distinct IPv4 prefixes, got %v", policy.mustInterceptIPv4)
	}
	if policy.mustInterceptIPv4[0] != first || policy.mustInterceptIPv4[1] != second {
		t.Fatalf("must-intercept order not preserved: %v", policy.mustInterceptIPv4)
	}
}

func TestCompilePolicyFakeIPJoinsMustInterceptSet(t *testing.T) {
	fakeIP := netip.MustParsePrefix("198.18.0.0/15")
	bypass := netip.MustParsePrefix("100.64.0.0/10")
	policy, err := CompilePolicy(PolicyConfig{FakeIPIPv4: fakeIP})
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.mustInterceptIPv4) != 1 || policy.mustInterceptIPv4[0] != fakeIP {
		t.Fatalf("FakeIP missing from must-intercept set: %v", policy.mustInterceptIPv4)
	}
	// FakeIP and bypass_exclude used to be mutually exclusive because they shared
	// one slot. Both mean "intercept unconditionally", so the set holds both now.
	policy, err = CompilePolicy(PolicyConfig{
		FakeIPIPv4:         fakeIP,
		ForceInterceptIPv4: []netip.Prefix{bypass},
	})
	if err != nil {
		t.Fatalf("FakeIP and bypass_exclude must coexist: %v", err)
	}
	if len(policy.mustInterceptIPv4) != 2 || policy.mustInterceptIPv4[0] != fakeIP || policy.mustInterceptIPv4[1] != bypass {
		t.Fatalf("unexpected must-intercept set: %v", policy.mustInterceptIPv4)
	}
	if _, err = CompilePolicy(PolicyConfig{ForceInterceptIPv4: []netip.Prefix{netip.MustParsePrefix("fd00::/8")}}); err == nil {
		t.Fatal("wrong-family IPv4 force-intercept accepted")
	}
}

// TestCompilePolicyMustInterceptRespectsMapCapacity keeps a configuration that
// cannot fit in the kernel map from loading half way.
func TestCompilePolicyMustInterceptRespectsMapCapacity(t *testing.T) {
	prefixes := make([]netip.Prefix, 0, maxMustInterceptPolicyEntries+1)
	for index := 0; index <= maxMustInterceptPolicyEntries; index++ {
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(index >> 8), byte(index), 0}), 24))
	}
	if _, err := CompilePolicy(PolicyConfig{ForceInterceptIPv4: prefixes}); err == nil {
		t.Fatal("oversized must-intercept set accepted")
	}
}
