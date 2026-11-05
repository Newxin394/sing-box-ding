//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"time"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

const (
	// mapMaintenanceInterval is the slow tick that re-reads map occupancy.
	// Map pressure is a slow signal by nature: a table fills over seconds to
	// minutes, not per packet.
	mapMaintenanceInterval = time.Minute
	// mapMaintenancePressureIdle is how often a pressured table is re-swept.
	// Short, because a table above the enter threshold is actively evicting.
	mapMaintenancePressureIdle = 15 * time.Second
	// mapMaintenanceRelaxedIdle is the same bound for a relaxed table: an
	// orphan left behind with headroom is harmless, so there is no reason to
	// pay for a walk on every tick.
	mapMaintenanceRelaxedIdle = 2 * time.Minute
	// mapMaintenanceSweepBudget bounds one pass, so a large table is drained
	// over several ticks instead of stalling the loop.
	mapMaintenanceSweepBudget = 1024
	// mapMaintenanceCooldown separates two passes so a table that stays
	// pressured cannot spin the loop.
	mapMaintenanceCooldown = 5 * time.Second
	// tcAssignmentIdlePressure and tcAssignmentIdleRelaxed are the idle windows
	// the TC assignment table is expired with.
	//
	// They are longer than the UDP recovery window (30s) on purpose: a recovery
	// entry only matters until the peer's next packet, while an assignment is
	// the flow's socket mapping and a TCP flow can legitimately be quiet for
	// minutes while its connection stays open. Expiring those at the recovery
	// window would re-assign live flows, which is cheap but pointless churn.
	tcAssignmentIdlePressure = 30 * time.Second
	tcAssignmentIdleRelaxed  = 5 * time.Minute
)

// runMapMaintenance expires the tables a late packet depends on, under map
// pressure rather than from the clock alone.
//
// The fixed-interval sweeper in cgroup_recovery_sweep.go can only answer "is
// this entry old". This loop answers the question that actually matters -- "is
// this table about to start evicting state a late packet still needs" -- and
// walks sooner when the answer is yes. With a relaxed table it still enforces
// the age bound, just without hurrying.
//
// Both data planes are covered: the local TC assignment table
// (SweepAssignments) and, when a cgroup backend exists, the UDP recovery table.
// Between passes the loop only reads occupancy, so an idle inbound costs a
// couple of map counts per minute.
func (i *Inbound) runMapMaintenance(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(mapMaintenanceInterval)
	defer ticker.Stop()
	var (
		pressure    commonEBPF.MapPressureTracker
		lastSweepAt time.Time
	)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !lastSweepAt.IsZero() && time.Since(lastSweepAt) < mapMaintenanceCooldown {
				continue
			}
			pressured := i.observeMapPressure(&pressure)
			idle := mapMaintenanceRelaxedIdle
			assignmentIdle := tcAssignmentIdleRelaxed
			if pressured {
				idle = mapMaintenancePressureIdle
				assignmentIdle = tcAssignmentIdlePressure
			}
			// The first pass always runs, so a fresh inbound enforces the age
			// bound without waiting a full interval; after that the interval
			// decides how often the table is walked.
			if !lastSweepAt.IsZero() && time.Since(lastSweepAt) < idle {
				continue
			}
			if _, err := i.sweepCgroupRecoveryBudgeted(cgroupRecoveryMaxAge, mapMaintenanceSweepBudget); err != nil {
				// sweepCgroupRecoveryBudgeted already warned; keep the loop alive
				// and retry on the next tick.
				continue
			}
			i.sweepTCAssignmentsBudgeted(assignmentIdle, mapMaintenanceSweepBudget, pressured)
			lastSweepAt = time.Now()
		}
	}
}

// startMapMaintenance starts the pressure-driven loop. Without either data
// plane there is nothing to maintain, so it returns immediately.
func (i *Inbound) startMapMaintenance(ctx context.Context) {
	if i.cgroupBackendInstance() == nil && i.tcBackend() == nil {
		return
	}
	i.recoverySweepAccess.Lock()
	defer i.recoverySweepAccess.Unlock()
	if i.maintenanceCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	i.maintenanceCancel = cancel
	i.maintenanceDone = done
	go i.runMapMaintenance(ctx, done)
}

// stopMapMaintenance stops the loop and waits for it to return, so no sweep can
// touch a backend that is being closed.
func (i *Inbound) stopMapMaintenance() {
	i.recoverySweepAccess.Lock()
	cancel, done := i.maintenanceCancel, i.maintenanceDone
	i.maintenanceCancel = nil
	i.maintenanceDone = nil
	i.recoverySweepAccess.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	if done != nil {
		<-done
	}
}

// observeMapPressure folds the fill levels of the tables a late packet depends
// on into the hysteresis, and reports the resulting state.
//
// The cgroup redirect and token tables are deliberately excluded: a sweep can
// never shrink them (their entries are live until the kernel or the release
// hook removes them), so including them would only make the loop sweep for
// nothing. The TC assignment table is included because a sweep does shrink it.
func (i *Inbound) observeMapPressure(tracker *commonEBPF.MapPressureTracker) bool {
	if backend := i.cgroupBackendInstance(); backend != nil {
		usage := backend.UDPRecoveryUsage()
		tracker.Observe(usage.Entries, usage.Capacity)
	}
	if backend := i.tcBackend(); backend != nil {
		if usage, err := backend.AssignmentUsage(); err == nil {
			tracker.Observe(usage.Entries, usage.Capacity)
		}
	}
	if shared := i.sharedRewriteInstance(); shared != nil {
		if backend := shared.sharedBackendInstance(); backend != nil {
			usage := backend.KnownFlowUsage()
			tracker.Observe(usage.Entries, usage.Capacity)
		}
	}
	return tracker.Pressured()
}
