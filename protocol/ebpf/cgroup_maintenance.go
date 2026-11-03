//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"time"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

const (
	// cgroupMaintenanceInterval is the slow tick that re-reads map occupancy.
	// Map pressure is a slow signal by nature: a table fills over seconds to
	// minutes, not per packet.
	cgroupMaintenanceInterval = time.Minute
	// cgroupMaintenancePressureIdle is how often a pressured table is re-swept.
	// Short, because a table above the enter threshold is actively evicting.
	cgroupMaintenancePressureIdle = 15 * time.Second
	// cgroupMaintenanceRelaxedIdle is the same bound for a relaxed table: an
	// orphan left behind with headroom is harmless, so there is no reason to
	// pay for a walk on every tick.
	cgroupMaintenanceRelaxedIdle = 2 * time.Minute
	// cgroupMaintenanceSweepBudget bounds one pass, so a large table is drained
	// over several ticks instead of stalling the loop.
	cgroupMaintenanceSweepBudget = 1024
	// cgroupMaintenanceCooldown separates two passes so a table that stays
	// pressured cannot spin the loop.
	cgroupMaintenanceCooldown = 5 * time.Second
)

// runCgroupMaintenance expires UDP recovery entries under map pressure rather
// than from the clock alone.
//
// The fixed-interval sweeper in cgroup_recovery_sweep.go can only answer "is
// this entry old". This loop answers the question that actually matters -- "is
// this table about to start evicting state a late packet still needs" -- and
// walks sooner when the answer is yes. With a relaxed table it still enforces
// the age bound, just without hurrying.
//
// Between passes the loop only reads occupancy, so an idle inbound costs one
// map count per minute.
func (i *Inbound) runCgroupMaintenance(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(cgroupMaintenanceInterval)
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
			if !lastSweepAt.IsZero() && time.Since(lastSweepAt) < cgroupMaintenanceCooldown {
				continue
			}
			pressured := i.observeCgroupMapPressure(&pressure)
			idle := cgroupMaintenanceRelaxedIdle
			if pressured {
				idle = cgroupMaintenancePressureIdle
			}
			// The first pass always runs, so a fresh inbound enforces the age
			// bound without waiting a full interval; after that the interval
			// decides how often the table is walked.
			if !lastSweepAt.IsZero() && time.Since(lastSweepAt) < idle {
				continue
			}
			if _, err := i.sweepCgroupRecoveryBudgeted(cgroupRecoveryMaxAge, cgroupMaintenanceSweepBudget); err != nil {
				// sweepCgroupRecoveryBudgeted already warned; keep the loop alive
				// and retry on the next tick.
				continue
			}
			lastSweepAt = time.Now()
		}
	}
}

// startCgroupMaintenance starts the pressure-driven loop. Without a cgroup
// backend there is no recovery table to maintain, so it returns immediately.
func (i *Inbound) startCgroupMaintenance(ctx context.Context) {
	if i.cgroupBackendInstance() == nil {
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
	go i.runCgroupMaintenance(ctx, done)
}

// stopCgroupMaintenance stops the loop and waits for it to return, so no sweep
// can touch a backend that is being closed.
func (i *Inbound) stopCgroupMaintenance() {
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

// observeCgroupMapPressure folds the fill levels of the tables a late packet
// depends on into the hysteresis, and reports the resulting state.
//
// The redirect and token tables are deliberately excluded: a sweep can never
// shrink them (their entries are live until the kernel or the release hook
// removes them), so including them would only make the loop sweep for nothing.
func (i *Inbound) observeCgroupMapPressure(tracker *commonEBPF.MapPressureTracker) bool {
	if backend := i.cgroupBackendInstance(); backend != nil {
		usage := backend.UDPRecoveryUsage()
		tracker.Observe(usage.Entries, usage.Capacity)
	}
	if shared := i.sharedRewriteInstance(); shared != nil {
		if backend := shared.sharedBackendInstance(); backend != nil {
			usage := backend.KnownFlowUsage()
			tracker.Observe(usage.Entries, usage.Capacity)
		}
	}
	return tracker.Pressured()
}
