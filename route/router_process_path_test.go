package route

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/process"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"

	"github.com/stretchr/testify/require"
)

// processPathTestRuleSet records the update callbacks a rule-set hands out and
// replays a reload on demand, which is what a local rule-set watcher does.
type processPathTestRuleSet struct {
	adapter.RuleSet
	tag       string
	metadata  atomic.Pointer[adapter.RuleSetMetadata]
	access    sync.Mutex
	callbacks list.List[adapter.RuleSetUpdateCallback]
}

func (s *processPathTestRuleSet) Name() string { return s.tag }

func (s *processPathTestRuleSet) Metadata() adapter.RuleSetMetadata {
	metadata := s.metadata.Load()
	if metadata == nil {
		return adapter.RuleSetMetadata{}
	}
	return *metadata
}

func (s *processPathTestRuleSet) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	s.access.Lock()
	defer s.access.Unlock()
	return s.callbacks.PushBack(callback)
}

func (s *processPathTestRuleSet) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.callbacks.Remove(element)
}

func (s *processPathTestRuleSet) callbackCount() int {
	s.access.Lock()
	defer s.access.Unlock()
	return s.callbacks.Len()
}

// reload publishes new metadata and notifies the registered callbacks, in the
// order the rule-set does it.
func (s *processPathTestRuleSet) reload(metadata adapter.RuleSetMetadata) {
	s.metadata.Store(&metadata)
	s.access.Lock()
	callbacks := s.callbacks.Array()
	s.access.Unlock()
	for _, callback := range callbacks {
		callback(s)
	}
}

// processPathTestSearcher implements the optional widening interface.
type processPathTestSearcher struct {
	process.Searcher
	widened atomic.Int32
}

func (s *processPathTestSearcher) SetNeedProcessPath() {
	s.widened.Add(1)
}

func newProcessPathTestCache(t *testing.T) *freelru.Cache[processCacheKey, processCacheEntry] {
	t.Helper()
	cache := common.Must1(freelru.New[processCacheKey, processCacheEntry](256, maphash.NewHasher[processCacheKey]().Hash32, true))
	cache.SetLifetime(200 * time.Millisecond)
	return cache
}

func TestRouterProcessPathWideningOnRuleSetReload(t *testing.T) {
	ruleSet := &processPathTestRuleSet{tag: "dynamic-set"}
	searcher := &processPathTestSearcher{}
	cache := newProcessPathTestCache(t)
	cache.Add(processCacheKey{Network: "tcp"}, processCacheEntry{})
	require.NotZero(t, cache.Len())

	router := &Router{
		logger:          log.NewNOPFactory().NewLogger("router"),
		ruleSets:        []adapter.RuleSet{ruleSet},
		processSearcher: searcher,
		processCache:    cache,
	}
	require.False(t, router.needProcessPath)
	router.startProcessPathWidening()
	require.Equal(t, 1, ruleSet.callbackCount())

	// A reload that still has no process path rule must leave the scan off.
	ruleSet.reload(adapter.RuleSetMetadata{ContainsProcessRule: true})
	require.False(t, router.needProcessPath)
	require.Zero(t, searcher.widened.Load())

	// A reload introducing a process_path rule turns the scan back on, widens
	// the live searcher and drops the owners cached without paths.
	ruleSet.reload(adapter.RuleSetMetadata{ContainsProcessRule: true, ContainsProcessPathRule: true})
	require.True(t, router.needProcessPath)
	require.Equal(t, int32(1), searcher.widened.Load())
	require.Zero(t, cache.Len())

	// Further reloads are idempotent.
	ruleSet.reload(adapter.RuleSetMetadata{ContainsProcessPathRule: true})
	require.Equal(t, int32(1), searcher.widened.Load())

	router.stopProcessPathWidening()
	require.Zero(t, ruleSet.callbackCount())
}

func TestRouterProcessPathWideningSkipsWhenAlreadyNeeded(t *testing.T) {
	ruleSet := &processPathTestRuleSet{tag: "static-set"}
	router := &Router{
		logger:          log.NewNOPFactory().NewLogger("router"),
		ruleSets:        []adapter.RuleSet{ruleSet},
		needProcessPath: true,
	}
	router.startProcessPathWidening()
	// The scan is already unconditional, so no callback is registered and a
	// reload cannot turn it off.
	require.Zero(t, ruleSet.callbackCount())
}

func TestRouterProcessPathWideningWithoutSearcher(t *testing.T) {
	ruleSet := &processPathTestRuleSet{tag: "no-searcher-set"}
	router := &Router{
		logger:   log.NewNOPFactory().NewLogger("router"),
		ruleSets: []adapter.RuleSet{ruleSet},
	}
	router.startProcessPathWidening()
	// A rule-set introducing process path rules when no searcher was created at
	// start cannot be served until a restart, but it must not panic.
	ruleSet.reload(adapter.RuleSetMetadata{ContainsProcessPathRule: true})
	require.True(t, router.needProcessPath)
	router.stopProcessPathWidening()
}

func TestRouterProcessPathWideningPicksUpReloadBeforeRegistration(t *testing.T) {
	// A rule-set that was already reloaded with process path rules before the
	// callback was registered publishes that metadata from the start.
	ruleSet := &processPathTestRuleSet{tag: "raced-set"}
	ruleSet.metadata.Store(&adapter.RuleSetMetadata{ContainsProcessPathRule: true})
	searcher := &processPathTestSearcher{}
	router := &Router{
		logger:          log.NewNOPFactory().NewLogger("router"),
		ruleSets:        []adapter.RuleSet{ruleSet},
		processSearcher: searcher,
	}
	router.startProcessPathWidening()
	require.True(t, router.needProcessPath)
	require.Equal(t, int32(1), searcher.widened.Load())
	router.stopProcessPathWidening()
}
