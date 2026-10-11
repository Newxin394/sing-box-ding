package adapter

import (
	"net/netip"
	"time"

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
	RuleStatistics
	Disabled() bool
	SetDisabled(disabled bool)
	UUID() string
	ChangeStatus()
	Type() string
	Action() RuleAction
}

// RuleStatistics mirrors mihomo RuleWrapper hit accounting: the router counts
// one Hit or Miss per top-level rule it evaluates (disabled rules are skipped,
// and rules after the first final match are not evaluated). Sub-rules are not
// counted individually.
type RuleStatistics interface {
	Hit()
	Miss()
	HitCount() uint64
	HitAt() time.Time
	MissCount() uint64
	MissAt() time.Time
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
