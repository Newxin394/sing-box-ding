//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"testing"
	"time"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

func TestCgroupMaintenanceRequiresCgroupBackend(t *testing.T) {
	inbound := &Inbound{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inbound.startCgroupMaintenance(ctx)
	inbound.recoverySweepAccess.Lock()
	started := inbound.maintenanceCancel != nil
	inbound.recoverySweepAccess.Unlock()
	if started {
		t.Fatal("maintenance should not start without a cgroup backend")
	}
}

func TestCgroupMaintenanceStopIsIdempotent(t *testing.T) {
	inbound := &Inbound{}
	inbound.stopCgroupMaintenance()
	inbound.stopCgroupMaintenance()
}

// The maintenance loop and the fixed-interval sweeper share one code path, so a
// backend that refuses to be swept must not make the loop spin or panic.
func TestSweepCgroupRecoveryBudgetedWithoutBackendIsQuiet(t *testing.T) {
	inbound := &Inbound{}
	stats, err := inbound.sweepCgroupRecoveryBudgeted(cgroupRecoveryMaxAge, cgroupMaintenanceSweepBudget)
	if err != nil {
		t.Fatalf("sweep without a backend should not fail: %v", err)
	}
	if stats.Scanned != 0 || stats.Deleted != 0 {
		t.Fatalf("sweep without a backend did something: %+v", stats)
	}
}

// A pressured table must be walked on the short interval and a relaxed one on
// the long interval; getting this backwards is invisible in production until a
// table silently fills up, so it is pinned here.
func TestCgroupMaintenanceIntervalsOrdering(t *testing.T) {
	if cgroupMaintenancePressureIdle >= cgroupMaintenanceRelaxedIdle {
		t.Fatalf(
			"a pressured table must be swept more often than a relaxed one: pressure=%v relaxed=%v",
			cgroupMaintenancePressureIdle, cgroupMaintenanceRelaxedIdle,
		)
	}
	if cgroupMaintenanceCooldown >= cgroupMaintenancePressureIdle {
		t.Fatalf(
			"the cooldown (%v) must be shorter than the pressure interval (%v), otherwise it wins and the interval never matters",
			cgroupMaintenanceCooldown, cgroupMaintenancePressureIdle,
		)
	}
	if cgroupMaintenanceInterval < cgroupMaintenancePressureIdle {
		t.Fatalf(
			"the occupancy tick (%v) must not be faster than the shortest sweep interval (%v)",
			cgroupMaintenanceInterval, cgroupMaintenancePressureIdle,
		)
	}
}

// The maintenance loop tolerates a pressure reading it cannot take: an inbound
// that never attached has no maps, and that must read as "relaxed", not as an
// error the loop would log every minute.
func TestObserveCgroupMapPressureWithoutBackendIsRelaxed(t *testing.T) {
	inbound := &Inbound{}
	var tracker commonEBPF.MapPressureTracker
	if inbound.observeCgroupMapPressure(&tracker) {
		t.Fatal("an inbound without backends must not report map pressure")
	}
}

func TestCgroupMaintenanceStopsPromptly(t *testing.T) {
	inbound := &Inbound{}
	// Install a stopped loop by hand so the test does not need kernel objects:
	// the stop path must still cancel and wait for a goroutine.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	inbound.recoverySweepAccess.Lock()
	inbound.maintenanceCancel = cancel
	inbound.maintenanceDone = done
	inbound.recoverySweepAccess.Unlock()
	go func() {
		<-ctx.Done()
		close(done)
	}()
	deadline := time.After(5 * time.Second)
	finished := make(chan struct{})
	go func() {
		inbound.stopCgroupMaintenance()
		close(finished)
	}()
	select {
	case <-finished:
	case <-deadline:
		t.Fatal("stopCgroupMaintenance did not return after cancel")
	}
}
