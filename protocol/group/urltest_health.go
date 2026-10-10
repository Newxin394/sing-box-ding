package group

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

const (
	urlTestHotCandidates          = 3
	urlTestColdRefreshIntervals   = 4
	urlTestMaxFailureBackoff      = 8
	urlTestNetworkRecheckCooldown = 30 * time.Second
	urlTestDialFailureThreshold   = 5
)

type urlTestMemberHealth struct {
	lastProbe time.Time
	failures  uint8
}

func (h urlTestMemberHealth) backoff(interval time.Duration) time.Duration {
	if interval <= 0 {
		return interval
	}
	backoff := interval
	for i := uint8(1); i < h.failures && backoff < urlTestMaxFailureBackoff*interval; i++ {
		backoff *= 2
	}
	return backoff
}

type urlTestHealthState struct {
	access  sync.Mutex
	members map[string]urlTestMemberHealth
	lastNet atomic.Int64
}

func (s *urlTestHealthState) record(tag string, available bool, at time.Time) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.members == nil {
		s.members = make(map[string]urlTestMemberHealth)
	}
	health := s.members[tag]
	health.lastProbe = at
	if available {
		health.failures = 0
	} else if health.failures < urlTestMaxFailureBackoff {
		health.failures++
	}
	s.members[tag] = health
}

func (s *urlTestHealthState) get(tag string) urlTestMemberHealth {
	s.access.Lock()
	defer s.access.Unlock()
	return s.members[tag]
}

func (s *urlTestHealthState) forgiveFailures() {
	s.access.Lock()
	for tag, health := range s.members {
		if health.failures > 1 {
			health.failures = 1
			s.members[tag] = health
		}
	}
	s.access.Unlock()
}

func (s *urlTestHealthState) excessive(tag string) bool {
	s.access.Lock()
	defer s.access.Unlock()
	return s.members[tag].failures >= 3
}

func (s *urlTestHealthState) allowNetworkProbe(now time.Time) bool {
	last := s.lastNet.Load()
	if last != 0 && now.Sub(time.Unix(0, last)) < urlTestNetworkRecheckCooldown {
		return false
	}
	return s.lastNet.CompareAndSwap(last, now.UnixNano())
}

type urlTestDialFailures struct {
	access sync.Mutex
	count  map[string]int32
	last   time.Time
	armed  atomic.Bool
}

func (s *urlTestDialFailures) failure(tag string, interval time.Duration) bool {
	now := time.Now()
	s.access.Lock()
	if !s.last.IsZero() && now.Sub(s.last) > interval {
		clear(s.count)
	}
	if s.count == nil {
		s.count = make(map[string]int32)
	}
	s.count[tag]++
	s.last = now
	threshold := s.count[tag] >= urlTestDialFailureThreshold
	s.access.Unlock()
	return threshold && s.armed.CompareAndSwap(false, true)
}

func (s *urlTestDialFailures) success(tag string) {
	s.access.Lock()
	delete(s.count, tag)
	s.access.Unlock()
}

func (s *urlTestDialFailures) excessive(tag string) bool {
	s.access.Lock()
	defer s.access.Unlock()
	return s.count[tag] >= urlTestDialFailureThreshold
}

func (s *urlTestDialFailures) release() {
	s.armed.Store(false)
}

func (s *urlTestDialFailures) reset() {
	s.access.Lock()
	clear(s.count)
	s.last = time.Time{}
	s.access.Unlock()
	s.armed.Store(false)
}

type urlTestProbePolicy struct {
	forceTags       map[string]struct{}
	onlyForced      bool
	networkChanged  bool
	shouldProbe     func(tag string, history *adapter.URLTestHistory, now time.Time) bool
	preserveHistory bool
	onResult        func(tag string, available bool, at time.Time)
}

func (p *urlTestProbePolicy) force(tag string) bool {
	if p == nil {
		return false
	}
	_, loaded := p.forceTags[tag]
	return loaded
}

func (p *urlTestProbePolicy) allow(tag string, history *adapter.URLTestHistory, now time.Time) bool {
	return p == nil || p.shouldProbe == nil || p.shouldProbe(tag, history, now)
}
