package group

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

func newTestScheduler(interval time.Duration) (urlTestProbeScheduler, *urlTestHealthState) {
	health := &urlTestHealthState{}
	return urlTestProbeScheduler{interval: interval, health: health, dialFailures: &urlTestDialFailures{}}, health
}

func TestScheduledPolicyProbesUnprobedTag(t *testing.T) {
	scheduler, _ := newTestScheduler(time.Minute)
	policy := scheduler.scheduledPolicy(func() map[string]struct{} { return nil })
	if !policy.shouldProbe("tag", nil, time.Now()) {
		t.Error("never-probed tag should be probed")
	}
}

func TestScheduledPolicyHotTagUsesFastInterval(t *testing.T) {
	scheduler, health := newTestScheduler(time.Minute)
	health.record("hot", true, time.Now())
	hot := map[string]struct{}{"hot": {}}
	policy := scheduler.scheduledPolicy(func() map[string]struct{} { return hot })
	if !policy.shouldProbe("hot", nil, time.Now().Add(time.Minute)) {
		t.Error("hot tag should use the fast interval")
	}
	// Non-hot members need the cold multiplier: 4x interval minus
	// half-interval tolerance = 3m30s elapsed.
	lastProbe := time.Now()
	health.record("cold", true, lastProbe)
	if policy.shouldProbe("cold", nil, lastProbe.Add(3*time.Minute+20*time.Second)) {
		t.Error("cold tag should not be probed before the cold interval")
	}
	if !policy.shouldProbe("cold", nil, time.Now().Add(4*time.Minute)) {
		t.Error("cold tag should be probed after the cold interval")
	}
}

func TestScheduledPolicyBackoffAfterFailure(t *testing.T) {
	scheduler, health := newTestScheduler(time.Minute)
	now := time.Now()
	health.record("failed", false, now)
	health.record("failed", false, now) // 2 failures -> backoff 2x
	policy := scheduler.scheduledPolicy(func() map[string]struct{} { return nil })
	if policy.shouldProbe("failed", nil, now.Add(90*time.Second-time.Second)) {
		t.Error("failed tag should still be in backoff")
	}
	if !policy.shouldProbe("failed", nil, now.Add(4*time.Minute)) {
		t.Error("failed tag should be probed after backoff expires")
	}
}

func TestScheduledPolicyFavorsHistoryOverLastProbe(t *testing.T) {
	scheduler, health := newTestScheduler(time.Minute)
	now := time.Now()
	health.record("tag", true, now.Add(-2*time.Minute))
	history := &adapter.URLTestHistory{Time: now}
	policy := scheduler.scheduledPolicy(func() map[string]struct{} { return map[string]struct{}{"tag": {}} })
	// History is newer than lastProbe: probe must wait a full interval
	// (period minus half-interval tolerance = 30s).
	if policy.shouldProbe("tag", history, now.Add(29*time.Second)) {
		t.Error("probe should respect newer history time")
	}
	if !policy.shouldProbe("tag", history, now.Add(31*time.Second)) {
		t.Error("probe should fire once the interval elapses")
	}
}

func TestDialFailureAndNetworkChangedPolicies(t *testing.T) {
	scheduler, _ := newTestScheduler(time.Minute)
	dial := scheduler.dialFailurePolicy(map[string]struct{}{"a": {}})
	if !dial.onlyForced || !dial.preserveHistory || dial.networkChanged {
		t.Errorf("unexpected dial failure policy: %+v", dial)
	}
	if len(dial.forceTags) != 1 || dial.shouldProbe != nil {
		t.Error("dial failure policy should force exactly the failing tags")
	}
	network := scheduler.networkChangedPolicy(map[string]struct{}{"b": {}})
	if !network.networkChanged || !network.onlyForced || !network.preserveHistory {
		t.Errorf("unexpected network changed policy: %+v", network)
	}
}
