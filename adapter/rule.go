package adapter

import (
	"net/netip"

	C "github.com/sagernet/sing-box/constant"

	"github.com/miekg/dns"
)

type HeadlessRule interface {
	Match(metadata *InboundContext) bool
	RuleCount() uint64
	String() string
}

type Rule interface {
	HeadlessRule
	SimpleLifecycle
	Disabled() bool
	UUID() string
	ChangeStatus()
	Type() string
	Action() RuleAction
}

type DNSRule interface {
	Rule
	LegacyPreMatch(metadata *InboundContext) bool
	WithAddressLimit() bool
	MatchAddressLimit(metadata *InboundContext, response *dns.Msg) bool
	MatchResponseTag() string
	MatchResponseTags() []string
	MatchResponseAnonymous() bool
	Race() bool
	AllowFallthrough() bool
	FallbackRules() []DNSFallbackRule
}

type DNSFallbackRule interface {
	SimpleLifecycle
	Match(metadata *InboundContext) bool
	String() string
	AcceptResult() bool
	Server() string
	DisableCache() bool
	RewriteTTL() *uint32
	ClientSubnet() *netip.Prefix
}

type RuleAction interface {
	Type() string
	String() string
}

func IsFinalAction(action RuleAction) bool {
	switch action.Type() {
	case C.RuleActionTypeSniff, C.RuleActionTypeResolve, C.RuleActionTypeEvaluate:
		return false
	default:
		return true
	}
}
