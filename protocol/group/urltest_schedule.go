package group

import (
	"sort"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	N "github.com/sagernet/sing/common/network"
)

// urlTestProbeScheduler holds the shared scheduling state used by URLTest and
// LoadBalance groups to decide when members are probed.
type urlTestProbeScheduler struct {
	interval     time.Duration
	health       *urlTestHealthState
	dialFailures *urlTestDialFailures
}

// scheduledPolicy returns the periodic probe policy. Tags supplied by hotTags
// (recently selected or fastest members) keep the fast refresh interval;
// remaining members use the cold multiplier, or a failure backoff.
func (s urlTestProbeScheduler) scheduledPolicy(hotTags func() map[string]struct{}) *urlTestProbePolicy {
	return &urlTestProbePolicy{
		preserveHistory: true,
		onResult:        s.health.record,
		shouldProbe: func(tag string, history *adapter.URLTestHistory, now time.Time) bool {
			health := s.health.get(tag)
			lastProbe := health.lastProbe
			if history != nil && history.Time.After(lastProbe) {
				lastProbe = history.Time
			}
			if lastProbe.IsZero() {
				return true
			}
			period := s.interval
			if _, hot := hotTags()[tag]; !hot {
				period = urlTestColdRefreshIntervals * s.interval
				if health.failures > 0 {
					period = health.backoff(s.interval)
				}
			}
			return now.Sub(lastProbe) >= period-s.interval/2
		},
	}
}

// dialFailurePolicy returns the policy used after a member accumulates enough
// dial failures, probing only the failing outbound (plus its group tag).
func (s urlTestProbeScheduler) dialFailurePolicy(forceTags map[string]struct{}) *urlTestProbePolicy {
	return &urlTestProbePolicy{
		forceTags:       forceTags,
		onlyForced:      true,
		preserveHistory: true,
		onResult:        s.health.record,
	}
}

// networkChangedPolicy returns the policy used after a network change, probing
// only forced tags while preserving existing history.
func (s urlTestProbeScheduler) networkChangedPolicy(forceTags map[string]struct{}) *urlTestProbePolicy {
	return &urlTestProbePolicy{
		forceTags:       forceTags,
		onlyForced:      true,
		networkChanged:  true,
		preserveHistory: true,
		onResult:        s.health.record,
	}
}

// urlTestTopTags returns the tags of the fastest outbounds (up to
// urlTestHotCandidates), including their TCP/UDP real tags when resolvable.
func urlTestTopTags(outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, outbounds []adapter.Outbound) map[string]struct{} {
	top := make(map[string]struct{}, urlTestHotCandidates*3)
	type candidate struct {
		tag   string
		delay uint16
	}
	candidates := make([]candidate, 0, len(outbounds))
	for _, outbound := range outbounds {
		if outbound == nil {
			continue
		}
		if outboundHistory := history.LoadURLTestHistory(RealTag(outbound, N.NetworkTCP)); outboundHistory != nil {
			candidates = append(candidates, candidate{outbound.Tag(), outboundHistory.Delay})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].delay < candidates[j].delay })
	for _, candidate := range candidates[:min(len(candidates), urlTestHotCandidates)] {
		top[candidate.tag] = struct{}{}
		if outbound, loaded := outboundManager.Outbound(candidate.tag); loaded {
			top[RealTag(outbound, N.NetworkTCP)] = struct{}{}
			top[RealTag(outbound, N.NetworkUDP)] = struct{}{}
		}
	}
	return top
}
