//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// Bounded housekeeping for the local TC flow assignment table.
//
// The assignment table is an LRU map: the kernel only drops an entry when the
// map is full, and the entry it drops is whichever one the LRU happens to pick.
// A flow that goes quiet therefore keeps its slot until unrelated traffic
// pushes it out, and when it does get pushed out the eviction can take an entry
// that is still in use. Expiring by age turns both halves of that into one
// bounded operation: aged entries leave on a schedule, so the table does not
// fill up, so the LRU does not have to guess.
//
// Expiry needs a timestamp, which the kernel now writes into every assignment
// (last_seen_ns, refreshed at most once per second to keep the write off the
// per-packet path) together with the data plane generation that produced it.
// Without the generation there is no way to tell an assignment that is merely
// old from one that describes an interface set that no longer exists; after a
// rebuild the latter are wrong the moment they are written, and waiting for
// them to age out means serving broken assignments for a full idle window.

const (
	// tcAssignmentSweepBatchEntries bounds how many entries one pass walks, so
	// a sweep never turns into an unbounded syscall loop.
	tcAssignmentSweepBatchEntries = 1024
	// tcAssignmentSweepFallbackBudget bounds the non-batch
	// (BPF_MAP_GET_NEXT_KEY) walk, which is one syscall per entry.
	tcAssignmentSweepFallbackBudget = 1024
	// tcAssignmentSweepMinimumMaxAge keeps a sweep off the kernel's own refresh
	// granularity. SB_TC_ASSIGNMENT_REFRESH_NS means a stamp can be up to one
	// second old while the flow behind it is perfectly alive, so anything at or
	// below that would delete live assignments.
	tcAssignmentSweepMinimumMaxAge = 2 * time.Second
)

// TCAssignmentSweepResult describes one bounded sweep of the assignment table.
type TCAssignmentSweepResult struct {
	Scanned uint32
	Deleted uint32
	// Superseded counts deletions caused by a generation mismatch, i.e.
	// assignments written by a data plane topology that has since been rebuilt.
	Superseded uint32
	// Expired counts deletions caused by the idle window.
	Expired uint32
	// Unstamped counts assignments left alone because they carry no timestamp,
	// so their age is unknowable. It is not an error: an object built before
	// the stamp existed can still be loaded, and guessing an age for those
	// would delete state that may still be serving a live flow.
	Unstamped uint32
	// Complete reports whether the walk reached the end of the map within the
	// batch budget. An incomplete sweep is not an error; the next pass
	// continues from the cursor.
	Complete bool
}

// tcAssignmentIdleWindow raises maxIdle to the shortest window the kernel's
// stamping granularity can honour.
func tcAssignmentIdleWindow(maxIdle time.Duration) time.Duration {
	if maxIdle < tcAssignmentSweepMinimumMaxAge {
		return tcAssignmentSweepMinimumMaxAge
	}
	return maxIdle
}

// SweepAssignments removes entries from the local TC assignment table that are
// older than maxIdle or that belong to an earlier data plane generation,
// walking at most budget entries.
//
// maxIdle below tcAssignmentSweepMinimumMaxAge is raised to it rather than
// rejected: the caller's intent is "reclaim what is idle", and a shorter window
// than the kernel can represent would only delete live entries.
func (b *TCBackend) SweepAssignments(maxIdle time.Duration, budget uint32) (TCAssignmentSweepResult, error) {
	if b == nil {
		return TCAssignmentSweepResult{}, errBackendClosed
	}
	if budget == 0 {
		budget = tcAssignmentSweepBatchEntries
	}
	maxIdle = tcAssignmentIdleWindow(maxIdle)
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return TCAssignmentSweepResult{}, errBackendClosed
	}
	assignmentMap := b.runtime.maps["tc_assignment"]
	if assignmentMap == nil {
		return TCAssignmentSweepResult{}, E.New("TC assignment map is unavailable")
	}
	generation := b.control.NetworkGeneration
	nowNanoseconds, err := MonotonicNanoseconds()
	if err != nil {
		return TCAssignmentSweepResult{}, err
	}
	maxIdleNS := uint64(maxIdle)
	// A reading younger than the idle window yields no cutoff at all: nothing
	// can be that old yet, and the subtraction would underflow into a huge
	// cutoff that expires everything.
	if nowNanoseconds <= maxIdleNS {
		return TCAssignmentSweepResult{}, nil
	}
	cutoff := nowNanoseconds - maxIdleNS
	var (
		stats   TCAssignmentSweepResult
		stale   []tcAssignKey
		scratch mapScanScratch[tcAssignKey, TCAssignment]
	)
	var reasons []bool // true = superseded, false = expired, parallel to stale
	scanResult, err := scratch.scan(
		assignmentMap,
		budget,
		tcAssignmentSweepFallbackBudget,
		func(key tcAssignKey, value TCAssignment) {
			if value.NetworkGeneration != generation {
				stale = append(stale, key)
				reasons = append(reasons, true)
				return
			}
			if value.LastSeenNS == 0 {
				stats.Unstamped++
				return
			}
			if value.LastSeenNS > cutoff {
				return
			}
			stale = append(stale, key)
			reasons = append(reasons, false)
		},
	)
	stats.Scanned = scanResult.Scanned
	stats.Complete = scanResult.Complete
	if err != nil {
		return stats, E.Cause(err, "scan TC assignment state")
	}
	// Deletion happens outside the visit callback: visiting runs while the batch
	// buffers are in use, and deleting during the walk would make the cursor
	// semantics depend on the map implementation.
	for index := range stale {
		deleteErr := deleteMap(b.assignmentMapFD, unsafe.Pointer(&stale[index]))
		if deleteErr != nil && !errors.Is(deleteErr, unix.ENOENT) {
			return stats, E.Cause(deleteErr, "delete stale TC assignment state")
		}
		stats.Deleted++
		if reasons[index] {
			stats.Superseded++
		} else {
			stats.Expired++
		}
	}
	return stats, nil
}

// AssignmentUsage reports how much of the local TC assignment table is in use.
//
// The count is an approximation under concurrent writers, which is exactly what
// a pressure signal needs: it is compared against a hysteresis threshold, not
// used to decide whether a specific entry exists.
func (b *TCBackend) AssignmentUsage() (MapUsage, error) {
	if b == nil {
		return MapUsage{}, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return MapUsage{}, errBackendClosed
	}
	assignmentMap := b.runtime.maps["tc_assignment"]
	if assignmentMap == nil {
		return MapUsage{}, E.New("TC assignment map is unavailable")
	}
	capacity := assignmentMap.MaxEntries()
	entries, err := countMapKeys(assignmentMap, uint32(unsafe.Sizeof(tcAssignKey{})), capacity)
	if err != nil {
		if isIterationAborted(err) {
			// An aborted walk means "at least this many", which for a pressure
			// signal rounds up to full instead of pretending there is room.
			return MapUsage{Entries: capacity, Capacity: capacity}, nil
		}
		return MapUsage{}, E.Cause(err, "count TC assignment entries")
	}
	return MapUsage{Entries: entries, Capacity: capacity}, nil
}
