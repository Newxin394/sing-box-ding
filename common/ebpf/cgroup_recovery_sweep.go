//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// Bounded housekeeping for the UDP recovery table.
//
// The recovery table is an LRU map: an entry is only evicted when the map is
// full. An entry written for a listener that never receives a second packet
// therefore stays until unrelated traffic pushes it out, and the map keeps
// reporting a full occupancy that has nothing to do with live sockets.
//
// The socket release hook now stamps each recovery entry with the release time,
// so the entry has a real age and can be expired by age instead of waiting for
// LRU pressure. Upstream goes one step further and delivers the release through
// a ring buffer so userspace deletes at an exact deadline; this fork still uses
// a periodic sweep, which bounds the same leak at the sweep interval instead of
// at the notification.
//
// The lower bound for "too old" is the kernel UDP conntrack timeout, because a
// packet arriving after the flow mapping expired can no longer be redirected
// and recovery would never be consulted for it again.

const (
	// recoverySweepBatchEntries bounds how many entries one pass walks, so a
	// sweep never turns into an unbounded syscall loop.
	recoverySweepBatchEntries = 1024
	// recoverySweepFallbackBudget bounds the non-batch
	// (BPF_MAP_GET_NEXT_KEY) walk, which is one syscall per entry.
	recoverySweepFallbackBudget = 1024
)

// RecoverySweepStats describes one bounded sweep of the UDP recovery table.
type RecoverySweepStats struct {
	Scanned uint32
	Deleted uint32
	// Complete reports whether the walk reached the end of the map within the
	// batch budget. An incomplete sweep is not an error; the next pass
	// continues from the cursor.
	Complete bool
}

// MonotonicNanoseconds reads CLOCK_MONOTONIC in nanoseconds since boot.
//
// This is the unit the kernel stamps recovery entries with (flow_time_ns, i.e.
// ktime_get_ns). It is returned as a plain uint64 rather than a time.Time
// because a monotonic reading has no epoch: wrapping it in time.Time means its
// wall-clock fields hold "seconds since boot", and anything that then asks
// UnixNano of it - or subtracts a Duration from it - is computing with a value
// that only resembles a timestamp. Comparing against time.Now() would mix two
// clocks as well: a wall-clock jump (NTP step, timezone handling in a
// container) moves the cutoff by arbitrary amounts in either direction,
// silently deleting live entries or never deleting stale ones.
func MonotonicNanoseconds() (uint64, error) {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return 0, E.Cause(err, "read monotonic clock")
	}
	// Timespec's fields are int32 on 32-bit platforms (android/arm, android/386),
	// so they have to be widened explicitly.
	return uint64(int64(now.Sec))*uint64(time.Second) + uint64(int64(now.Nsec)), nil
}

// SweepUDPRecoveryBudgeted removes entries from the UDP recovery table that are
// older than maxAge, walking at most budget entries.
//
// nowNanoseconds must be a CLOCK_MONOTONIC reading in nanoseconds, see
// MonotonicNanoseconds. It is a bare uint64 rather than a time.Time on purpose:
// the kernel stamps entries in that unit, and a time.Time carrying a monotonic
// reading round-trips through UnixNano in ways that depend on its wall-clock
// fields rather than on the reading. Entries whose timestamp is unknown (zero)
// are left alone: an object built before the release hook stamped them can
// still be loaded after an upgrade, and guessing an age from a missing
// timestamp would delete state that is still serving a live flow.
func (b *CgroupBackend) SweepUDPRecoveryBudgeted(
	maxAge time.Duration,
	nowNanoseconds uint64,
	budget uint32,
) (RecoverySweepStats, error) {
	if b == nil {
		return RecoverySweepStats{}, errBackendClosed
	}
	if maxAge <= 0 {
		return RecoverySweepStats{}, E.New("recovery sweep max age must be positive")
	}
	if budget == 0 {
		budget = recoverySweepBatchEntries
	}
	b.udpRecoveryAccess.Lock()
	defer b.udpRecoveryAccess.Unlock()
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return RecoverySweepStats{}, errBackendClosed
	}
	recoveryMap := b.runtime.maps["cgroup_udp_recovery"]
	if recoveryMap == nil {
		return RecoverySweepStats{}, E.New("UDP recovery map is unavailable")
	}
	maxAgeNS := uint64(maxAge)
	// A reading younger than maxAge yields no cutoff at all: nothing can be
	// that old yet, and the subtraction would underflow into a huge cutoff that
	// expires everything.
	if nowNanoseconds <= maxAgeNS {
		return RecoverySweepStats{}, nil
	}
	cutoff := nowNanoseconds - maxAgeNS
	var (
		stats   RecoverySweepStats
		stale   []listenerLookupKey
		scratch mapScanScratch[listenerLookupKey, originalDestinationValue]
	)
	scanResult, err := scratch.scan(
		recoveryMap,
		budget,
		recoverySweepFallbackBudget,
		func(key listenerLookupKey, value originalDestinationValue) {
			stats.Scanned++
			if value.CreatedAtNS == 0 || value.CreatedAtNS > cutoff {
				return
			}
			stale = append(stale, key)
		},
	)
	stats.Scanned = scanResult.Scanned
	stats.Complete = scanResult.Complete
	if err != nil {
		return stats, E.Cause(err, "scan UDP recovery state")
	}
	// Deletion happens outside the visit callback: visiting runs while the batch
	// buffers are in use, and deleting during the walk would make the cursor
	// semantics depend on the map implementation.
	for index := range stale {
		deleteErr := deleteMap(b.udpRecoveryMapFD, unsafe.Pointer(&stale[index]))
		if deleteErr != nil && !errors.Is(deleteErr, unix.ENOENT) {
			return stats, E.Cause(deleteErr, "delete stale UDP recovery state")
		}
		stats.Deleted++
	}
	return stats, nil
}
