//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
)

func TestCompilePolicyForceIntercept(t *testing.T) {
	bypassV4 := netip.MustParsePrefix("100.64.1.2/10")
	bypassV6 := netip.MustParsePrefix("fd7a:115c:a1e0::1/48")
	policy, err := CompilePolicy(PolicyConfig{EnableTCP: true, ForceInterceptIPv4: bypassV4, ForceInterceptIPv6: bypassV6})
	if err != nil {
		t.Fatal(err)
	}
	if policy.forceInterceptIPv4 != bypassV4.Masked() || policy.forceInterceptIPv6 != bypassV6.Masked() {
		t.Fatalf("force-intercept not normalized: %v %v", policy.forceInterceptIPv4, policy.forceInterceptIPv6)
	}
	if policy.fakeIPIPv4.IsValid() || policy.fakeIPIPv6.IsValid() {
		t.Fatal("bypass_exclude must not be reported as FakeIP")
	}
	vector := tcFlags(TCConfig{EnableLocal: true, EnableLocalIPv6: true}, policy)
	if vector&(1<<10) == 0 || vector&(1<<11) == 0 {
		t.Fatalf("force-intercept flags not set: %#x", vector)
	}
}

func TestCompilePolicyFakeIPKeepsForceSlot(t *testing.T) {
	fakeIP := netip.MustParsePrefix("198.18.0.0/15")
	policy, err := CompilePolicy(PolicyConfig{FakeIPIPv4: fakeIP})
	if err != nil {
		t.Fatal(err)
	}
	if policy.forceInterceptIPv4 != fakeIP {
		t.Fatalf("FakeIP did not occupy force slot: %v", policy.forceInterceptIPv4)
	}
	if _, err = CompilePolicy(PolicyConfig{FakeIPIPv4: fakeIP, ForceInterceptIPv4: netip.MustParsePrefix("100.64.0.0/10")}); err == nil {
		t.Fatal("FakeIP and bypass_exclude shared one IPv4 slot")
	}
	if _, err = CompilePolicy(PolicyConfig{ForceInterceptIPv4: netip.MustParsePrefix("fd00::/8")}); err == nil {
		t.Fatal("wrong-family IPv4 force-intercept accepted")
	}
}
