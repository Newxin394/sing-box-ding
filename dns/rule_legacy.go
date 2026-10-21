package dns

// Legacy DNS routing mode validation.
//
// These helpers decide whether the legacy DNS routing mode must be
// enabled for a rule set and validate rules that rely on legacy-only
// behaviors. They only depend on the option schema and the
// adapter.Router interface, not on Router state.

import (
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

func defaultRuleNeedsLegacyDNSModeFromAddressFilter(rule option.DefaultDNSRule) bool {
	if rule.RuleSetIPCIDRAcceptEmpty { //nolint:staticcheck
		return true
	}
	return !rule.MatchResponse.IsEnabled() && (rule.IPAcceptAny || len(rule.IPCIDR) > 0 || rule.IPIsPrivate)
}

func hasResponseMatchFields(rule option.DefaultDNSRule) bool {
	return rule.ResponseRcode != nil ||
		len(rule.ResponseAnswer) > 0 ||
		len(rule.ResponseNs) > 0 ||
		len(rule.ResponseExtra) > 0
}

func defaultRuleDisablesLegacyDNSMode(rule option.DefaultDNSRule) bool {
	return rule.MatchResponse.IsEnabled() ||
		hasResponseMatchFields(rule) ||
		rule.Action == C.RuleActionTypeEvaluate ||
		rule.Action == C.RuleActionTypeRespond ||
		rule.IPVersion > 0 ||
		len(rule.QueryType) > 0
}

type dnsRuleModeFlags struct {
	disabled           bool
	needed             bool
	neededFromStrategy bool
}

func (f *dnsRuleModeFlags) merge(other dnsRuleModeFlags) {
	f.disabled = f.disabled || other.disabled
	f.needed = f.needed || other.needed
	f.neededFromStrategy = f.neededFromStrategy || other.neededFromStrategy
}

func resolveLegacyDNSMode(router adapter.Router, rules []option.DNSRule, metadataOverrides map[string]adapter.RuleSetMetadata) (bool, dnsRuleModeFlags, error) {
	flags, err := dnsRuleModeRequirements(router, rules, metadataOverrides)
	if err != nil {
		return false, flags, err
	}
	if flags.disabled && flags.neededFromStrategy {
		return false, flags, E.New(deprecated.OptionLegacyDNSRuleStrategy.MessageWithLink())
	}
	if flags.disabled {
		return false, flags, nil
	}
	return flags.needed, flags, nil
}

func dnsRuleModeRequirements(router adapter.Router, rules []option.DNSRule, metadataOverrides map[string]adapter.RuleSetMetadata) (dnsRuleModeFlags, error) {
	var flags dnsRuleModeFlags
	for i, rule := range rules {
		ruleFlags, err := dnsRuleModeRequirementsInRule(router, rule, metadataOverrides)
		if err != nil {
			return dnsRuleModeFlags{}, E.Cause(err, "dns rule[", i, "]")
		}
		flags.merge(ruleFlags)
	}
	return flags, nil
}

func dnsRuleModeRequirementsInRule(router adapter.Router, rule option.DNSRule, metadataOverrides map[string]adapter.RuleSetMetadata) (dnsRuleModeFlags, error) {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		return dnsRuleModeRequirementsInDefaultRule(router, rule.DefaultOptions, metadataOverrides)
	case C.RuleTypeLogical:
		flags := dnsRuleModeFlags{
			disabled: dnsRuleActionType(rule) == C.RuleActionTypeEvaluate ||
				dnsRuleActionType(rule) == C.RuleActionTypeRespond ||
				dnsRuleActionDisablesLegacyDNSMode(rule.LogicalOptions.DNSRuleAction),
			neededFromStrategy: dnsRuleActionHasStrategy(rule.LogicalOptions.DNSRuleAction),
		}
		flags.needed = flags.neededFromStrategy
		for i, subRule := range rule.LogicalOptions.Rules {
			subFlags, err := dnsRuleModeRequirementsInRule(router, subRule, metadataOverrides)
			if err != nil {
				return dnsRuleModeFlags{}, E.Cause(err, "sub rule[", i, "]")
			}
			flags.merge(subFlags)
		}
		return flags, nil
	default:
		return dnsRuleModeFlags{}, nil
	}
}

func dnsRuleModeRequirementsInDefaultRule(router adapter.Router, rule option.DefaultDNSRule, metadataOverrides map[string]adapter.RuleSetMetadata) (dnsRuleModeFlags, error) {
	flags := dnsRuleModeFlags{
		disabled:           defaultRuleDisablesLegacyDNSMode(rule) || dnsRuleActionDisablesLegacyDNSMode(rule.DNSRuleAction),
		neededFromStrategy: dnsRuleActionHasStrategy(rule.DNSRuleAction),
	}
	flags.needed = defaultRuleNeedsLegacyDNSModeFromAddressFilter(rule) || flags.neededFromStrategy
	if len(rule.RuleSet) == 0 {
		return flags, nil
	}
	if router == nil {
		return dnsRuleModeFlags{}, E.New("router service not found")
	}
	for _, tag := range rule.RuleSet {
		metadata, err := lookupDNSRuleSetMetadata(router, tag, metadataOverrides)
		if err != nil {
			return dnsRuleModeFlags{}, err
		}
		// ip_version is not a headless-rule item, so ContainsIPVersionRule is intentionally absent.
		flags.disabled = flags.disabled || metadata.ContainsDNSQueryTypeRule
		if !rule.RuleSetIPCIDRMatchSource && metadata.ContainsIPCIDRRule {
			flags.needed = true
		}
	}
	return flags, nil
}

func lookupDNSRuleSetMetadata(router adapter.Router, tag string, metadataOverrides map[string]adapter.RuleSetMetadata) (adapter.RuleSetMetadata, error) {
	if metadataOverrides != nil {
		if metadata, loaded := metadataOverrides[tag]; loaded {
			return metadata, nil
		}
	}
	ruleSet, loaded := router.RuleSet(tag)
	if !loaded {
		return adapter.RuleSetMetadata{}, E.New("rule-set not found: ", tag)
	}
	return ruleSet.Metadata(), nil
}

type dnsRuleResponseUse struct {
	needsAnonymous bool
	referencedTags []string
}

func validateLegacyDNSModeDisabledRules(router adapter.Router, rules []option.DNSRule, metadataOverrides map[string]adapter.RuleSetMetadata) ([]string, error) {
	var (
		warnings               []string
		seenAnonymousEvaluate  bool
		seenRace               bool
		definedTags            = make(map[string]bool)
		definedTagOrder        []string
		referencedTags         = make(map[string]bool)
		lastAnonymousEvaluate  = -1
		anonymousReadSinceLast bool
	)
	for i, rule := range rules {
		use, err := validateLegacyDNSModeDisabledRuleTree(router, rule, metadataOverrides)
		if err != nil {
			return nil, E.Cause(err, "validate dns rule[", i, "]")
		}
		if dnsRuleActionSpeculative(rule) && !seenRace {
			warnings = append(warnings, F.ToString("dns rule[", i, "]: `speculative` has no effect without a preceding `race` rule"))
		}
		if dnsRuleRace(rule) {
			seenRace = true
		}
		if use.needsAnonymous {
			if !seenAnonymousEvaluate {
				if len(definedTagOrder) > 0 {
					return nil, E.New("dns rule[", i, "]: response-based matching requires a preceding evaluate action without `tag`; use `match_response` with an evaluate tag to reference a tagged result")
				}
				return nil, E.New("dns rule[", i, "]: response-based matching requires a preceding evaluate action")
			}
			anonymousReadSinceLast = true
		}
		for _, tag := range use.referencedTags {
			if !definedTags[tag] {
				return nil, E.New("dns rule[", i, "]: undefined evaluate tag: ", tag)
			}
			referencedTags[tag] = true
		}
		if dnsRuleActionType(rule) == C.RuleActionTypeEvaluate {
			tag := dnsRuleActionEvaluateTag(rule)
			if tag == "" {
				if lastAnonymousEvaluate >= 0 && !anonymousReadSinceLast {
					warnings = append(warnings, F.ToString("dns rule[", lastAnonymousEvaluate, "]: evaluated response is overwritten by dns rule[", i, "] before any use"))
				}
				seenAnonymousEvaluate = true
				lastAnonymousEvaluate = i
				anonymousReadSinceLast = false
			} else {
				if definedTags[tag] {
					return nil, E.New("dns rule[", i, "]: duplicate evaluate tag: ", tag)
				}
				definedTags[tag] = true
				definedTagOrder = append(definedTagOrder, tag)
			}
		}
	}
	for _, tag := range definedTagOrder {
		if !referencedTags[tag] {
			warnings = append(warnings, F.ToString("evaluate tag is never referenced: ", tag))
		}
	}
	return warnings, nil
}

func validateEvaluateFakeIPRules(rules []option.DNSRule, transportManager adapter.DNSTransportManager) error {
	if transportManager == nil {
		return nil
	}
	for i, rule := range rules {
		if dnsRuleActionType(rule) != C.RuleActionTypeEvaluate {
			continue
		}
		server := dnsRuleActionServer(rule)
		if server == "" {
			continue
		}
		transport, loaded := transportManager.Transport(server)
		if !loaded || transport.Type() != C.DNSTypeFakeIP {
			continue
		}
		return E.New("dns rule[", i, "]: evaluate action cannot use fakeip server: ", server)
	}
	return nil
}

func validateLegacyDNSModeDisabledRuleTree(router adapter.Router, rule option.DNSRule, metadataOverrides map[string]adapter.RuleSetMetadata) (dnsRuleResponseUse, error) {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		return validateLegacyDNSModeDisabledDefaultRule(router, rule.DefaultOptions, metadataOverrides)
	case C.RuleTypeLogical:
		var use dnsRuleResponseUse
		for i, subRule := range rule.LogicalOptions.Rules {
			subUse, err := validateLegacyDNSModeDisabledRuleTree(router, subRule, metadataOverrides)
			if err != nil {
				return dnsRuleResponseUse{}, E.Cause(err, "sub rule[", i, "]")
			}
			use.needsAnonymous = use.needsAnonymous || subUse.needsAnonymous
			use.referencedTags = append(use.referencedTags, subUse.referencedTags...)
		}
		if rule.LogicalOptions.Action == C.RuleActionTypeRespond {
			if len(use.referencedTags) > 0 {
				return dnsRuleResponseUse{}, E.New("respond on a logical rule cannot bind a `match_response` tag from its sub rules; use a non-logical rule")
			}
			use.needsAnonymous = true
		}
		return use, nil
	default:
		return dnsRuleResponseUse{}, nil
	}
}

func validateLegacyDNSModeDisabledDefaultRule(router adapter.Router, rule option.DefaultDNSRule, metadataOverrides map[string]adapter.RuleSetMetadata) (dnsRuleResponseUse, error) {
	hasResponseRecords := hasResponseMatchFields(rule)
	if (hasResponseRecords || len(rule.IPCIDR) > 0 || rule.IPIsPrivate || rule.IPAcceptAny) && !rule.MatchResponse.IsEnabled() {
		return dnsRuleResponseUse{}, E.New("Response Match Fields (ip_cidr, ip_is_private, ip_accept_any, response_rcode, response_answer, response_ns, response_extra) require match_response to be enabled")
	}
	// rule_set entries are only rejected when every referenced set is pure-IP;
	// mixed sets still fall through because their non-IP branches remain matchable
	// before a DNS response is available.
	if !rule.MatchResponse.IsEnabled() && len(rule.RuleSet) > 0 {
		for _, tag := range rule.RuleSet {
			metadata, err := lookupDNSRuleSetMetadata(router, tag, metadataOverrides)
			if err != nil {
				return dnsRuleResponseUse{}, err
			}
			if metadata.ContainsIPCIDRRule && !metadata.ContainsNonIPCIDRRule {
				return dnsRuleResponseUse{}, E.New(deprecated.OptionLegacyDNSAddressFilter.MessageWithLink())
			}
		}
	}
	if rule.RuleSetIPCIDRAcceptEmpty { //nolint:staticcheck
		return dnsRuleResponseUse{}, E.New(deprecated.OptionRuleSetIPCIDRAcceptEmpty.MessageWithLink())
	}
	var use dnsRuleResponseUse
	if rule.MatchResponse.IsEnabled() {
		if responseTag := rule.MatchResponse.ResponseTag(); responseTag != "" {
			use.referencedTags = append(use.referencedTags, responseTag)
		} else {
			use.needsAnonymous = true
		}
	}
	if rule.Action == C.RuleActionTypeRespond && rule.MatchResponse.ResponseTag() == "" {
		use.needsAnonymous = true
	}
	return use, nil
}

func dnsRuleActionDisablesLegacyDNSMode(action option.DNSRuleAction) bool {
	if action.Race {
		return true
	}
	switch action.Action {
	case "", C.RuleActionTypeRoute:
		return action.RouteOptions.DisableOptimisticCache || action.RouteOptions.Speculative
	case C.RuleActionTypeEvaluate:
		return action.EvaluateOptions.DisableOptimisticCache || action.EvaluateOptions.Speculative
	case C.RuleActionTypeRouteOptions:
		return action.RouteOptionsOptions.DisableOptimisticCache
	default:
		return false
	}
}

func dnsRuleActionHasStrategy(action option.DNSRuleAction) bool {
	switch action.Action {
	case "", C.RuleActionTypeRoute:
		return C.DomainStrategy(action.RouteOptions.Strategy) != C.DomainStrategyAsIS
	case C.RuleActionTypeEvaluate:
		return C.DomainStrategy(action.EvaluateOptions.Strategy) != C.DomainStrategyAsIS
	case C.RuleActionTypeRouteOptions:
		return C.DomainStrategy(action.RouteOptionsOptions.Strategy) != C.DomainStrategyAsIS
	default:
		return false
	}
}

func dnsRuleActionType(rule option.DNSRule) string {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		if rule.DefaultOptions.Action == "" {
			return C.RuleActionTypeRoute
		}
		return rule.DefaultOptions.Action
	case C.RuleTypeLogical:
		if rule.LogicalOptions.Action == "" {
			return C.RuleActionTypeRoute
		}
		return rule.LogicalOptions.Action
	default:
		return ""
	}
}

func dnsRuleActionServer(rule option.DNSRule) string {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		if dnsRuleActionType(rule) == C.RuleActionTypeEvaluate {
			return rule.DefaultOptions.EvaluateOptions.Server
		}
		return rule.DefaultOptions.RouteOptions.Server
	case C.RuleTypeLogical:
		if dnsRuleActionType(rule) == C.RuleActionTypeEvaluate {
			return rule.LogicalOptions.EvaluateOptions.Server
		}
		return rule.LogicalOptions.RouteOptions.Server
	default:
		return ""
	}
}

func dnsRuleActionEvaluateTag(rule option.DNSRule) string {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		return rule.DefaultOptions.EvaluateOptions.Tag
	case C.RuleTypeLogical:
		return rule.LogicalOptions.EvaluateOptions.Tag
	default:
		return ""
	}
}

func dnsRuleActionSpeculative(rule option.DNSRule) bool {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		if dnsRuleActionType(rule) == C.RuleActionTypeEvaluate {
			return rule.DefaultOptions.EvaluateOptions.Speculative
		}
		return rule.DefaultOptions.RouteOptions.Speculative
	case C.RuleTypeLogical:
		if dnsRuleActionType(rule) == C.RuleActionTypeEvaluate {
			return rule.LogicalOptions.EvaluateOptions.Speculative
		}
		return rule.LogicalOptions.RouteOptions.Speculative
	default:
		return false
	}
}

func dnsRuleRace(rule option.DNSRule) bool {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		return rule.DefaultOptions.Race
	case C.RuleTypeLogical:
		return rule.LogicalOptions.Race
	default:
		return false
	}
}
