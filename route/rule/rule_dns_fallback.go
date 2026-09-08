package rule

import (
	"context"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

var _ adapter.DNSFallbackRule = (*DNSFallbackRule)(nil)

type DNSFallbackRule struct {
	acceptResult bool
	matchAll     bool
	items        []RuleItem
	invert       bool
	server       string
	disableCache bool
	rewriteTTL   *uint32
	clientSubnet netip.Prefix
}

func NewDNSFallbackRules(ctx context.Context, router adapter.Router, options []option.DNSFallbackRule) ([]adapter.DNSFallbackRule, error) {
	rules := make([]adapter.DNSFallbackRule, 0, len(options))
	for i, fallbackOptions := range options {
		if !fallbackOptions.IsValid() {
			return nil, E.New("fallback_rule[", i, "] missing conditions or result")
		}
		rule := &DNSFallbackRule{
			acceptResult: fallbackOptions.AcceptResult,
			matchAll:     fallbackOptions.MatchAll,
			invert:       fallbackOptions.Invert,
			server:       fallbackOptions.Server,
			disableCache: fallbackOptions.DisableCache,
			rewriteTTL:   fallbackOptions.RewriteTTL,
			clientSubnet: netip.Prefix(common.PtrValueOrDefault(fallbackOptions.ClientSubnet)),
		}
		if len(fallbackOptions.ClashMode) > 0 {
			rule.items = append(rule.items, NewClashModeItem(ctx, fallbackOptions.ClashMode))
		}
		if len(fallbackOptions.IPCIDR) > 0 {
			item, err := NewIPCIDRItem(false, fallbackOptions.IPCIDR)
			if err != nil {
				return nil, E.Cause(err, "fallback_rule[", i, "] ip_cidr")
			}
			rule.items = append(rule.items, item)
		}
		if fallbackOptions.IPIsPrivate {
			rule.items = append(rule.items, NewIPIsPrivateItem(false))
		}
		if len(fallbackOptions.RuleSet) > 0 {
			rule.items = append(rule.items, NewRuleSetItem(router, fallbackOptions.RuleSet, false, false))
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (r *DNSFallbackRule) Start() error {
	for _, item := range r.items {
		if starter, loaded := item.(interface{ Start() error }); loaded {
			if err := starter.Start(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *DNSFallbackRule) Close() error {
	for _, item := range r.items {
		if closer, loaded := item.(interface{ Close() error }); loaded {
			if err := closer.Close(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *DNSFallbackRule) Match(metadata *adapter.InboundContext) bool {
	if r.matchAll {
		return true
	}
	matched := common.All(r.items, func(item RuleItem) bool { return item.Match(metadata) })
	if r.invert {
		return !matched
	}
	return matched
}

func (r *DNSFallbackRule) String() string {
	var result string
	if r.matchAll {
		result = "match_all"
	} else {
		result = strings.Join(F.MapToString(r.items), " && ")
		if r.invert {
			result = "!(" + result + ")"
		}
	}
	if r.acceptResult {
		return result + " => accept"
	}
	return result + " => " + r.server
}

func (r *DNSFallbackRule) AcceptResult() bool  { return r.acceptResult }
func (r *DNSFallbackRule) Server() string      { return r.server }
func (r *DNSFallbackRule) DisableCache() bool  { return r.disableCache }
func (r *DNSFallbackRule) RewriteTTL() *uint32 { return r.rewriteTTL }
func (r *DNSFallbackRule) ClientSubnet() *netip.Prefix {
	if !r.clientSubnet.IsValid() {
		return nil
	}
	return &r.clientSubnet
}
