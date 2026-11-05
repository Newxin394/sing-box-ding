//go:build with_ebpf && (linux || android)

package ebpf

import (
	"time"
)

// tcAssignmentSweepStatus is the last sweep's outcome, in the shape the
// diagnostics schema reports it.
//
// It is a snapshot rather than a set of cumulative counters because the
// question this answers is "is the table being maintained", not "how many
// entries have ever been removed": a sweep that keeps removing entries is
// healthy, while a sweep that keeps failing is not, and both look the same in a
// total.
type tcAssignmentSweepStatus struct {
	scanned    uint32
	removed    uint32
	complete   bool
	entries    uint64
	capacity   uint64
	pressured  bool
	runs       uint64
	partial    uint64
	lastAt     time.Time
	partialAt  time.Time
	failure    string
	usageKnown bool
	// expired and superseded split the removals by reason. They are not in the
	// schema (upstream counts the same work as tcAssignmentSweepMissing /
	// Superseded / InFlight against a claim table this fork does not have), so
	// they exist for the trace log only.
	expired    uint32
	superseded uint32
}

// sweepTCAssignmentsBudgeted expires idle and superseded TC flow assignments.
//
// The outcome is recorded on the inbound rather than returned, because the
// caller is a maintenance loop that has nowhere to return it to; diagnostics
// read it back later. A failure is recorded and logged rather than returned for
// the same reason the cgroup sweep treats one the same way: one unreadable table
// must not stop the loop from maintaining the rest.
func (i *Inbound) sweepTCAssignmentsBudgeted(maxIdle time.Duration, budget uint32, pressured bool) {
	backend := i.tcBackend()
	if backend == nil {
		return
	}
	stats, sweepErr := backend.SweepAssignments(maxIdle, budget)
	usage, usageErr := backend.AssignmentUsage()
	now := time.Now()
	i.tcAssignmentSweepAccess.Lock()
	status := &i.tcAssignmentSweepStatus
	status.runs++
	status.pressured = pressured
	status.lastAt = now
	status.scanned = stats.Scanned
	status.removed = stats.Deleted
	status.complete = stats.Complete
	status.expired = stats.Expired
	status.superseded = stats.Superseded
	if !stats.Complete {
		status.partial++
		status.partialAt = now
	}
	if usageErr == nil {
		status.entries = uint64(usage.Entries)
		status.capacity = uint64(usage.Capacity)
		status.usageKnown = true
	} else {
		// Keep the last known numbers rather than reporting zero: a zero
		// occupancy reads as an empty table, which is the opposite of "I could
		// not measure it".
		status.usageKnown = false
	}
	status.failure = ""
	if sweepErr != nil {
		status.failure = sweepErr.Error()
	}
	i.tcAssignmentSweepAccess.Unlock()
	if sweepErr != nil {
		i.interfaceWarnings.infrastructure.warn(i.logger, "sweep TC eBPF assignment state: ", sweepErr)
		return
	}
	if stats.Deleted == 0 {
		return
	}
	i.logger.Trace(
		"TC eBPF assignment sweep: scanned ", stats.Scanned,
		", deleted ", stats.Deleted,
		" (expired ", stats.Expired, ", superseded ", stats.Superseded,
		", unstamped ", stats.Unstamped, ")",
	)
}

// tcAssignmentSweepDiagnostics returns a copy of the last sweep's outcome.
func (i *Inbound) tcAssignmentSweepDiagnostics() tcAssignmentSweepStatus {
	i.tcAssignmentSweepAccess.Lock()
	defer i.tcAssignmentSweepAccess.Unlock()
	return i.tcAssignmentSweepStatus
}

// AssignmentSweepPressure reports whether the last pass considered the table
// pressured, for tests that need to observe the hysteresis without a kernel.
func (i *Inbound) AssignmentSweepPressure() bool {
	return i.tcAssignmentSweepDiagnostics().pressured
}
