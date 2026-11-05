//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"testing"
	"time"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

func TestMapMaintenanceRequiresSomeDataPlane(t *testing.T) {
	inbound := &Inbound{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inbound.startMapMaintenance(ctx)
	inbound.recoverySweepAccess.Lock()
	started := inbound.maintenanceCancel != nil
	inbound.recoverySweepAccess.Unlock()
	if started {
		t.Fatal("maintenance should not start without a data plane")
	}
}

func TestMapMaintenanceStopIsIdempotent(t *testing.T) {
	inbound := &Inbound{}
	inbound.stopMapMaintenance()
	inbound.stopMapMaintenance()
}

// The maintenance loop and the fixed-interval sweeper share one code path, so a
// backend that refuses to be swept must not make the loop spin or panic.
func TestSweepCgroupRecoveryBudgetedWithoutBackendIsQuiet(t *testing.T) {
	inbound := &Inbound{}
	stats, err := inbound.sweepCgroupRecoveryBudgeted(cgroupRecoveryMaxAge, mapMaintenanceSweepBudget)
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
func TestMapMaintenanceIntervalsOrdering(t *testing.T) {
	if mapMaintenancePressureIdle >= mapMaintenanceRelaxedIdle {
		t.Fatalf(
			"a pressured table must be swept more often than a relaxed one: pressure=%v relaxed=%v",
			mapMaintenancePressureIdle, mapMaintenanceRelaxedIdle,
		)
	}
	if mapMaintenanceCooldown >= mapMaintenancePressureIdle {
		t.Fatalf(
			"the cooldown (%v) must be shorter than the pressure interval (%v), otherwise it wins and the interval never matters",
			mapMaintenanceCooldown, mapMaintenancePressureIdle,
		)
	}
	if mapMaintenanceInterval < mapMaintenancePressureIdle {
		t.Fatalf(
			"the occupancy tick (%v) must not be faster than the shortest sweep interval (%v)",
			mapMaintenanceInterval, mapMaintenancePressureIdle,
		)
	}
}

// The maintenance loop tolerates a pressure reading it cannot take: an inbound
// that never attached has no maps, and that must read as "relaxed", not as an
// error the loop would log every minute.
func TestObserveMapPressureWithoutBackendIsRelaxed(t *testing.T) {
	inbound := &Inbound{}
	var tracker commonEBPF.MapPressureTracker
	if inbound.observeMapPressure(&tracker) {
		t.Fatal("an inbound without backends must not report map pressure")
	}
}

func TestMapMaintenanceStopsPromptly(t *testing.T) {
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
		inbound.stopMapMaintenance()
		close(finished)
	}()
	select {
	case <-finished:
	case <-deadline:
		t.Fatal("stopMapMaintenance did not return after cancel")
	}
}
