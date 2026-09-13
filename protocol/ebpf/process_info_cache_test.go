//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

// TestProcessInfoCacheShardDistribution guards the shard index: a poor spread
// would funnel unrelated processes into one shard and reintroduce the
// contention the cache exists to avoid.
func TestProcessInfoCacheShardDistribution(t *testing.T) {
	cache := newProcessInfoCache()
	counts := make([]int, processInfoCacheShardCount)
	for processID := uint32(1); processID <= 4096; processID++ {
		index := cache.shardIndex(processInfoCacheKey{processID: processID, userID: 10000 + processID%5})
		if index >= processInfoCacheShardCount {
			t.Fatalf("shard index %d out of range for pid %d", index, processID)
		}
		counts[index]++
	}
	least := counts[0]
	for _, count := range counts {
		if count < least {
			least = count
		}
	}
	// A perfect spread is 256 per shard; require every shard to get the bulk of
	// that so a regression toward a degenerate index is caught.
	if least < 200 {
		t.Fatalf("shard distribution too uneven: min=%d counts=%v", least, counts)
	}
}

// TestProcessInfoCacheEvictsExpired verifies that a full shard reclaims entries
// whose TTL has passed rather than dropping live ones.
func TestProcessInfoCacheEvictsExpired(t *testing.T) {
	cache := newProcessInfoCache()
	shard := &cache.shards[0]
	now := time.Now()

	liveKey := processInfoCacheKey{processID: 4242, userID: 10123}
	shard.entries[liveKey] = processInfoCacheEntry{
		owner:   &adapter.ConnectionOwner{ProcessID: 4242},
		expires: now.Add(time.Minute),
	}
	for index := 0; index < processInfoCacheShardSize-1; index++ {
		shard.entries[processInfoCacheKey{processID: uint32(9000 + index), userID: 1000}] = processInfoCacheEntry{
			owner:   &adapter.ConnectionOwner{},
			expires: now.Add(-time.Second),
		}
	}
	shard.evictExpiredLocked(now)

	if len(shard.entries) != 1 {
		t.Fatalf("expected only the live entry to survive, got %d entries", len(shard.entries))
	}
	if _, loaded := shard.entries[liveKey]; !loaded {
		t.Fatal("live entry was evicted")
	}
}

// TestProcessInfoCacheKeySeparatesUsers guards the pid-reuse defense: the same
// pid under two uids must not collide.
func TestProcessInfoCacheKeySeparatesUsers(t *testing.T) {
	cache := newProcessInfoCache()
	first := processInfoCacheKey{processID: 777, userID: 10001}
	second := processInfoCacheKey{processID: 777, userID: 10002}
	if first == second {
		t.Fatal("keys with different user ids compare equal")
	}
	shard := &cache.shards[0]
	shard.entries[first] = processInfoCacheEntry{owner: &adapter.ConnectionOwner{UserId: 10001}, expires: time.Now().Add(time.Minute)}
	shard.entries[second] = processInfoCacheEntry{owner: &adapter.ConnectionOwner{UserId: 10002}, expires: time.Now().Add(time.Minute)}
	if len(shard.entries) != 2 {
		t.Fatalf("expected two distinct entries, got %d", len(shard.entries))
	}
}
