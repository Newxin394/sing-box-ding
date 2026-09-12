//go:build with_ebpf && (linux || android)

package ebpf

import (
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/process"
	"github.com/sagernet/sing-tun"
)

const (
	// processInfoCacheShardCount spreads the cache so one slow miss does not
	// stall lookups for unrelated processes.
	processInfoCacheShardCount = 16
	// processInfoCacheShardSize bounds each shard. A phone keeps on the order of
	// a few hundred live app processes, so the whole cache stays in that range.
	processInfoCacheShardSize = 64
	// processInfoCacheTTL is deliberately short: a recycled pid inside this
	// window is vanishingly unlikely, while the hot case -- one app opening
	// many connections in a burst -- is fully covered by it.
	processInfoCacheTTL = 5 * time.Second
)

// processInfoCacheKey identifies a process by the pair the kernel reports for
// its socket. The pid alone is not enough: Android shares one pid space across
// users, so the same number can name a different app under a different uid.
type processInfoCacheKey struct {
	processID uint32
	userID    uint32
}

type processInfoCacheEntry struct {
	owner   *adapter.ConnectionOwner
	expires time.Time
}

// processInfoCache memoizes the expensive half of Inbound.lookupProcessInfo.
//
// The eBPF process tracker already turns a socket cookie into (pid, uid) with a
// single map lookup, which is cheap and stays uncached because a cookie is
// unique per socket. Turning that pair into a process path and package name is
// what costs: a /proc/<pid>/exe readlink plus a package manager lookup, and
// every new connection from the same app repeats it with an identical answer.
// Caching on (pid, uid) removes that repetition for the whole burst.
type processInfoCache struct {
	shards [processInfoCacheShardCount]processInfoCacheShard
}

type processInfoCacheShard struct {
	access  sync.RWMutex
	entries map[processInfoCacheKey]processInfoCacheEntry
}

func newProcessInfoCache() *processInfoCache {
	p := &processInfoCache{}
	for index := range p.shards {
		p.shards[index].entries = make(map[processInfoCacheKey]processInfoCacheEntry, processInfoCacheShardSize)
	}
	return p
}

func (p *processInfoCache) shardIndex(key processInfoCacheKey) uint32 {
	return (key.processID ^ key.userID) % processInfoCacheShardCount
}

func (p *processInfoCache) shardFor(key processInfoCacheKey) *processInfoCacheShard {
	return &p.shards[p.shardIndex(key)]
}

// load resolves the key to a process owner, reusing a recent resolution when
// one is available. Resolution runs outside the shard lock so a slow /proc read
// never blocks lookups for other keys.
//
// The returned owner is shared between callers and must be treated as
// read-only, which matches how InboundContext.ProcessInfo is consumed.
func (p *processInfoCache) load(key processInfoCacheKey, packageManager tun.PackageManager) *adapter.ConnectionOwner {
	shard := p.shardFor(key)
	now := time.Now()
	shard.access.RLock()
	entry, loaded := shard.entries[key]
	shard.access.RUnlock()
	if loaded && now.Before(entry.expires) {
		return entry.owner
	}
	processInfo, _ := process.FindProcessInfoByPID(key.processID, key.userID, packageManager)
	shard.access.Lock()
	if len(shard.entries) >= processInfoCacheShardSize {
		shard.evictExpiredLocked(now)
		if len(shard.entries) >= processInfoCacheShardSize {
			// Still full, so nothing here is stale: drop an arbitrary entry so a
			// burst of distinct processes cannot grow the shard without bound.
			// Map iteration order is randomized, so this is a cheap random evict.
			for evictKey := range shard.entries {
				delete(shard.entries, evictKey)
				break
			}
		}
	}
	shard.entries[key] = processInfoCacheEntry{owner: processInfo, expires: now.Add(processInfoCacheTTL)}
	shard.access.Unlock()
	return processInfo
}

// evictExpiredLocked drops entries whose TTL has passed. The caller must hold
// the shard write lock.
func (s *processInfoCacheShard) evictExpiredLocked(now time.Time) {
	for key, entry := range s.entries {
		if now.After(entry.expires) {
			delete(s.entries, key)
		}
	}
}
