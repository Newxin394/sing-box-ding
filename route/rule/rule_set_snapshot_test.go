package rule

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestAbstractRuleSetSnapshotReadPath(t *testing.T) {
	ruleSet := &abstractRuleSet{}
	first := []adapter.HeadlessRule{}
	ruleSet.snapshot.Store(&ruleSetSnapshot{rules: first})
	if got := ruleSet.loadRules(); got == nil {
		t.Fatal("snapshot read returned nil")
	}

	fallback := []adapter.HeadlessRule{}
	ruleSet.rules = fallback
	ruleSet.snapshot.Store(nil)
	if got := ruleSet.loadRules(); got == nil {
		t.Fatal("zero-value fallback read returned nil")
	}
}

func TestAbstractRuleSetClearRulesClearsSnapshot(t *testing.T) {
	ruleSet := &abstractRuleSet{}
	ruleSet.snapshot.Store(&ruleSetSnapshot{rules: []adapter.HeadlessRule{}})
	ruleSet.clearRules()
	if got := ruleSet.snapshot.Load(); got != nil {
		t.Fatal("clearRules left an active snapshot")
	}
}
