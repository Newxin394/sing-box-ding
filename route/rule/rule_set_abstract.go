package rule

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"

	"go4.org/netipx"
)

type ruleSetSnapshot struct {
	rules     []adapter.HeadlessRule
	ruleCount uint64
	metadata  adapter.RuleSetMetadata
}

func (s *ruleSetSnapshot) Match(metadata *adapter.InboundContext) bool {
	return matchAnyHeadlessRule(s.rules, metadata)
}

func (s *ruleSetSnapshot) RuleCount() uint64 {
	return s.ruleCount
}

func (s *ruleSetSnapshot) String() string {
	return strings.Join(F.MapToString(s.rules), " ")
}

func (s *ruleSetSnapshot) mergeableRule() *DefaultHeadlessRule {
	return mergeableRuleIn(s.rules)
}

type abstractRuleSet struct {
	ctx         context.Context
	logger      logger.ContextLogger
	tag         string
	access      sync.RWMutex
	sType       string
	path        string
	format      string
	rules       []adapter.HeadlessRule
	snapshot    atomic.Pointer[ruleSetSnapshot]
	ruleCount   uint64
	metadata    adapter.RuleSetMetadata
	lastUpdated time.Time
	callbacks   list.List[adapter.RuleSetUpdateCallback]
	refs        atomic.Int32
}

func (s *abstractRuleSet) Name() string {
	return s.tag
}

func (s *abstractRuleSet) Type() string {
	return s.sType
}

func (s *abstractRuleSet) Format() string {
	return s.format
}

func (s *abstractRuleSet) RuleCount() uint64 {
	return s.loadContent().ruleCount
}

func (s *abstractRuleSet) UpdatedTime() time.Time {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.lastUpdated
}

func (s *abstractRuleSet) setUpdatedTime(updatedAt time.Time) {
	s.access.Lock()
	defer s.access.Unlock()
	s.lastUpdated = updatedAt
}

func (s *abstractRuleSet) loadContent() *ruleSetSnapshot {
	if snapshot := s.snapshot.Load(); snapshot != nil {
		return snapshot
	}
	// Keep zero-value and test-constructed rule sets functional. Production
	// rule sets publish immutable content and keep the lock-free read path.
	s.access.RLock()
	content := &ruleSetSnapshot{rules: s.rules, ruleCount: s.ruleCount, metadata: s.metadata}
	s.access.RUnlock()
	return content
}

func (s *abstractRuleSet) loadRules() []adapter.HeadlessRule {
	return s.loadContent().rules
}

func (s *abstractRuleSet) String() string {
	return s.loadContent().String()
}

func (s *abstractRuleSet) Metadata() adapter.RuleSetMetadata {
	return s.loadContent().metadata
}

func (s *abstractRuleSet) ExtractIPSet() []*netipx.IPSet {
	return common.FlatMap(s.loadRules(), extractIPSetFromRule)
}

func (s *abstractRuleSet) IncRef() {
	s.refs.Add(1)
}

func (s *abstractRuleSet) DecRef() {
	if s.refs.Add(-1) < 0 {
		panic("rule-set: negative refs")
	}
}

func (s *abstractRuleSet) clearRules() {
	s.access.Lock()
	s.rules = nil
	s.ruleCount = 0
	s.metadata = adapter.RuleSetMetadata{}
	s.snapshot.Store(&ruleSetSnapshot{})
	s.access.Unlock()
}

func (s *abstractRuleSet) Cleanup() {
	if s.refs.Load() == 0 {
		s.clearRules()
	}
}

func (s *abstractRuleSet) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	s.access.Lock()
	defer s.access.Unlock()
	return s.callbacks.PushBack(callback)
}

func (s *abstractRuleSet) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.callbacks.Remove(element)
}

func (s *abstractRuleSet) loadBytes(content []byte, ruleset adapter.RuleSet) error {
	var (
		ruleSet option.PlainRuleSetCompat
		err     error
	)
	switch s.format {
	case C.RuleSetFormatSource:
		ruleSet, err = json.UnmarshalExtended[option.PlainRuleSetCompat](content)
		if err != nil {
			return err
		}
	case C.RuleSetFormatBinary:
		ruleSet, err = srs.Read(bytes.NewReader(content), false)
		if err != nil {
			return err
		}
	default:
		return E.New("unknown rule-set format: ", s.format)
	}
	plainRuleSet, err := mmapRuleSet(s.ctx, s.logger, s.tag, ruleSet).Upgrade()
	if err != nil {
		return err
	}
	return s.reloadRules(plainRuleSet.Rules, ruleset)
}

func (s *abstractRuleSet) reloadRules(headlessRules []option.HeadlessRule, ruleSet adapter.RuleSet) error {
	rules := make([]adapter.HeadlessRule, len(headlessRules))
	var err error
	var ruleCount uint64
	for i, ruleOptions := range headlessRules {
		rule, err := NewHeadlessRule(s.ctx, ruleOptions)
		if err != nil {
			return E.Cause(err, "parse rule_set.rules.[", i, "]")
		}
		rules[i] = rule
		ruleCount += rule.RuleCount()
	}
	metadata := buildRuleSetMetadata(headlessRules)
	err = validateRuleSetMetadataUpdate(s.ctx, s.tag, metadata)
	if err != nil {
		return err
	}
	s.access.Lock()
	s.rules = rules
	s.ruleCount = ruleCount
	s.metadata = metadata
	s.snapshot.Store(&ruleSetSnapshot{rules: rules, ruleCount: ruleCount, metadata: metadata})
	callbacks := s.callbacks.Array()
	s.access.Unlock()
	for _, callback := range callbacks {
		callback(ruleSet)
	}
	return nil
}

func (s *abstractRuleSet) Match(metadata *adapter.InboundContext) bool {
	return s.loadContent().Match(metadata)
}
