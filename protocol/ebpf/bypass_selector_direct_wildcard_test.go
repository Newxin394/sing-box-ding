//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// TestBypassSelectorDirectWildcardConstant pins the wildcard keyword so a
// rename cannot silently break existing configurations that rely on "直连".
func TestBypassSelectorDirectWildcardConstant(t *testing.T) {
	if option.EBPFBypassSelectorDirectWildcard != "直连" {
		t.Fatalf("direct wildcard keyword changed: %q", option.EBPFBypassSelectorDirectWildcard)
	}
}

// TestBypassSelectorMemberTriggersExplicit verifies the explicit-tag matching
// path (wildcard disabled): only members listed in bypass_when trigger a
// bypass, and an empty selection never does.
func TestBypassSelectorMemberTriggersExplicit(t *testing.T) {
	i := &Inbound{
		bypassSelectorOptions: &option.EBPFBypassSelectorOptions{
			Tags:       badoption.Listable[string]{"国内出口"},
			BypassWhen: badoption.Listable[string]{"直连"},
		},
		bypassSelectorDirectWild: false,
	}
	cases := []struct {
		selected string
		want     bool
	}{
		{"直连", true},    // listed explicitly
		{"国内免流", false}, // not listed
		{"", false},      // empty selection never bypasses
	}
	for _, c := range cases {
		if got := i.bypassSelectorMemberTriggers(c.selected); got != c.want {
			t.Fatalf("memberTriggers(%q)=%v, want %v", c.selected, got, c.want)
		}
	}
}

// TestBypassSelectorMemberTriggersNilOptions guards the fast path: with no
// options configured, nothing is ever bypassed.
func TestBypassSelectorMemberTriggersNilOptions(t *testing.T) {
	i := &Inbound{}
	if i.bypassSelectorMemberTriggers("直连") {
		t.Fatal("memberTriggers must be false when options are nil")
	}
}

// TestBypassSelectorWantsBypassAnyNoSelectors verifies OR aggregation returns
// false when there are no watched selectors (defensive: runtime never engages
// bypass without an explicit trigger).
func TestBypassSelectorWantsBypassAnyNoSelectors(t *testing.T) {
	i := &Inbound{
		bypassSelectorOptions: &option.EBPFBypassSelectorOptions{
			Tags:       badoption.Listable[string]{"国内出口"},
			BypassWhen: badoption.Listable[string]{"直连"},
		},
	}
	if i.bypassSelectorWantsBypassAny() {
		t.Fatal("wantsBypassAny must be false with no resolved selectors")
	}
}
