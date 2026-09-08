package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"

	mDNS "github.com/miekg/dns"
)

func fallbackTestMessage() *mDNS.Msg {
	return &mDNS.Msg{
		MsgHdr:   mDNS.MsgHdr{Id: 1, RecursionDesired: true},
		Question: []mDNS.Question{{Name: "fallback.example.org.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}},
	}
}

func fallbackRule(server string, fallbackRules []option.DNSFallbackRule, allowFallthrough bool) option.DNSRule {
	return option.DNSRule{
		Type:          C.RuleTypeDefault,
		FallbackRules: fallbackRules,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{AllowFallthrough: allowFallthrough},
			DNSRuleAction: option.DNSRuleAction{
				Action:       C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{Server: server},
			},
		},
	}
}

func fallbackTestRules(t *testing.T, rawRules []option.DNSRule) []adapter.DNSRule {
	t.Helper()
	rules := make([]adapter.DNSRule, 0, len(rawRules))
	for _, rawRule := range rawRules {
		rule, err := R.NewDNSRule(context.Background(), log.NewNOPFactory().Logger(), rawRule, true, false)
		require.NoError(t, err)
		require.NoError(t, rule.Start())
		t.Cleanup(func() { _ = rule.Close() })
		rules = append(rules, rule)
	}
	return rules
}

func TestDNSFallbackRuleRoutesByResponseAddress(t *testing.T) {
	t.Parallel()
	primary := &fakeDNSTransport{tag: "primary", rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("203.0.113.1")}
	fallback := &fakeDNSTransport{tag: "fallback", rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, primary, fallback)
	rules := fallbackTestRules(t, []option.DNSRule{fallbackRule("primary", []option.DNSFallbackRule{{IPCIDR: []string{"203.0.113.0/24"}, Server: "fallback"}}, false)})
	result := router.exchangeWithRules(adapter.WithContext(context.Background(), &adapter.InboundContext{Domain: "fallback.example.org", QueryType: mDNS.TypeA}), rules, fallbackTestMessage(), adapter.DNSQueryOptions{}, false)
	require.NoError(t, result.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.2"), responseAddress(t, result.response))
	require.Equal(t, int32(1), primary.queryCount.Load())
	require.Equal(t, int32(1), fallback.queryCount.Load())
}

func TestDNSFallbackRuleAcceptsPrimaryResult(t *testing.T) {
	t.Parallel()
	primary := &fakeDNSTransport{tag: "primary", rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("203.0.113.1")}
	fallback := &fakeDNSTransport{tag: "fallback", rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, primary, fallback)
	rules := fallbackTestRules(t, []option.DNSRule{fallbackRule("primary", []option.DNSFallbackRule{{IPCIDR: []string{"203.0.113.0/24"}, AcceptResult: true}}, false)})
	result := router.exchangeWithRules(adapter.WithContext(context.Background(), &adapter.InboundContext{Domain: "fallback.example.org", QueryType: mDNS.TypeA}), rules, fallbackTestMessage(), adapter.DNSQueryOptions{}, false)
	require.NoError(t, result.err)
	require.Equal(t, netip.MustParseAddr("203.0.113.1"), responseAddress(t, result.response))
	require.Equal(t, int32(0), fallback.queryCount.Load())
}

func TestDNSAllowFallthroughOnFailedPrimary(t *testing.T) {
	t.Parallel()
	primary := &fakeDNSTransport{tag: "primary", exchangeErr: context.DeadlineExceeded}
	secondary := &fakeDNSTransport{tag: "secondary", rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, primary, secondary)
	rules := fallbackTestRules(t, []option.DNSRule{
		fallbackRule("primary", nil, true),
		fallbackRule("secondary", nil, false),
	})
	result := router.exchangeWithRules(adapter.WithContext(context.Background(), &adapter.InboundContext{Domain: "fallback.example.org", QueryType: mDNS.TypeA}), rules, fallbackTestMessage(), adapter.DNSQueryOptions{}, false)
	require.NoError(t, result.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.2"), responseAddress(t, result.response))
	require.Equal(t, int32(1), primary.queryCount.Load())
	require.Equal(t, int32(1), secondary.queryCount.Load())
}

func TestDNSFallbackOnPrimaryError(t *testing.T) {
	t.Parallel()
	primary := &fakeDNSTransport{tag: "primary", exchangeErr: context.DeadlineExceeded}
	fallback := &fakeDNSTransport{tag: "fallback", rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, primary, fallback)
	rules := fallbackTestRules(t, []option.DNSRule{
		fallbackRule("primary", []option.DNSFallbackRule{{MatchAll: true, Server: "fallback"}}, false),
	})
	result := router.exchangeWithRules(adapter.WithContext(context.Background(), &adapter.InboundContext{Domain: "fallback.example.org", QueryType: mDNS.TypeA}), rules, fallbackTestMessage(), adapter.DNSQueryOptions{}, false)
	require.NoError(t, result.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.2"), responseAddress(t, result.response))
	require.Equal(t, int32(1), primary.queryCount.Load())
	require.Equal(t, int32(1), fallback.queryCount.Load())
}

func TestDNSFallbackMultiLevel(t *testing.T) {
	t.Parallel()
	primary := &fakeDNSTransport{tag: "primary", rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("203.0.113.1")}
	first := &fakeDNSTransport{tag: "first", exchangeErr: context.DeadlineExceeded}
	second := &fakeDNSTransport{tag: "second", rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, primary, first, second)
	rules := fallbackTestRules(t, []option.DNSRule{
		fallbackRule("primary", []option.DNSFallbackRule{
			{IPCIDR: []string{"203.0.113.0/24"}, Server: "first"},
			{IPCIDR: []string{"203.0.113.0/24"}, Server: "second"},
		}, false),
	})
	result := router.exchangeWithRules(adapter.WithContext(context.Background(), &adapter.InboundContext{Domain: "fallback.example.org", QueryType: mDNS.TypeA}), rules, fallbackTestMessage(), adapter.DNSQueryOptions{}, false)
	require.NoError(t, result.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.2"), responseAddress(t, result.response))
	require.Equal(t, int32(1), first.queryCount.Load())
	require.Equal(t, int32(1), second.queryCount.Load())
}

func TestDNSFallbackFailThenAllowFallthrough(t *testing.T) {
	t.Parallel()
	primary := &fakeDNSTransport{tag: "primary", exchangeErr: context.DeadlineExceeded}
	fallback := &fakeDNSTransport{tag: "fallback", exchangeErr: context.DeadlineExceeded}
	next := &fakeDNSTransport{tag: "final", rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.9")}
	router := raceTestRouter(t, primary, fallback, next)
	rules := fallbackTestRules(t, []option.DNSRule{
		fallbackRule("primary", []option.DNSFallbackRule{{MatchAll: true, Server: "fallback"}}, true),
		fallbackRule("final", nil, false),
	})
	result := router.exchangeWithRules(adapter.WithContext(context.Background(), &adapter.InboundContext{Domain: "fallback.example.org", QueryType: mDNS.TypeA}), rules, fallbackTestMessage(), adapter.DNSQueryOptions{}, false)
	require.NoError(t, result.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.9"), responseAddress(t, result.response))
	require.Equal(t, int32(1), fallback.queryCount.Load())
	require.Equal(t, int32(1), next.queryCount.Load())
}
