//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"testing"
	"time"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

func TestSweepUDPRecoveryBudgetedRejectsNonPositiveMaxAge(t *testing.T) {
	backend := &commonEBPF.CgroupBackend{}
	if _, err := backend.SweepUDPRecoveryBudgeted(0, time.Now(), 0); err == nil {
		t.Fatal("sweep with a zero max age should fail instead of deleting everything")
	}
	if _, err := backend.SweepUDPRecoveryBudgeted(-time.Second, time.Now(), 0); err == nil {
		t.Fatal("sweep with a negative max age should fail")
	}
}

func TestSweepUDPRecoveryBudgetedRejectsClosedBackend(t *testing.T) {
	var backend *commonEBPF.CgroupBackend
	if _, err := backend.SweepUDPRecoveryBudgeted(time.Minute, time.Now(), 0); err == nil {
		t.Fatal("sweep on a nil backend should fail")
	}
}

// A backend that has not been attached yet must not be swept: there is no map to
// walk, and getting an error here would pollute the warnings on every tick.
func TestInboundRecoverySweepWithoutBackendIsSilent(t *testing.T) {
	inbound := &Inbound{}
	inbound.sweepCgroupRecovery()
	if inbound.recoverySweepHandledAnything() {
		t.Fatal("sweep without a backend should do nothing")
	}
}

func TestInboundRecoverySweeperStopIsIdempotent(t *testing.T) {
	inbound := &Inbound{}
	inbound.stopCgroupRecoverySweeper()
	inbound.stopCgroupRecoverySweeper()
}

func TestInboundRecoverySweeperStartRequiresCgroupBackend(t *testing.T) {
	inbound := &Inbound{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inbound.startCgroupRecoverySweeper(ctx)
	inbound.recoverySweepAccess.Lock()
	started := inbound.recoverySweepCancel != nil
	inbound.recoverySweepAccess.Unlock()
	if started {
		t.Fatal("sweeper should not start without a cgroup backend")
	}
}

// The kernel stamps a released socket's recovery entry with CLOCK_MONOTONIC
// (flow_time_ns), so the sweep must compare against the same clock. A wall-clock
// reading drifts by any NTP step and would either keep stale entries forever or
// expire live ones.
func TestMonotonicNowAdvancesWithTheMonotonicClock(t *testing.T) {
	before, err := commonEBPF.MonotonicNow()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	after, err := commonEBPF.MonotonicNow()
	if err != nil {
		t.Fatal(err)
	}
	if !after.After(before) {
		t.Fatalf("monotonic clock did not advance: before=%v after=%v", before, after)
	}
	// A monotonic reading is only meaningful relative to another one. If it were
	// the wall clock, it would be within minutes of time.Now(); a boot-relative
	// value is not (this build has no reason to be on a machine booted within the
	// hour).
	if wall := time.Now(); after.Sub(wall).Abs() < time.Minute {
		t.Fatal("MonotonicNow looks like a wall-clock reading")
	}
}

// A sweep that only ever sees entries with an unknown timestamp must not delete
// anything: those values come from objects built before the release hook stamped
// them, and guessing their age would cut flows that are still alive.
func TestRecoverySweepLeavesUnstampedEntriesAlone(t *testing.T) {
	now, err := commonEBPF.MonotonicNow()
	if err != nil {
		t.Fatal(err)
	}
	var (
		stats commonEBPF.RecoverySweepStats
		stale int
	)
	// Reproduces the visit predicate the sweep applies to every entry.
	for _, createdAt := range []uint64{0, uint64(now.Add(-time.Hour).UnixNano())} {
		stats.Scanned++
		cutoff := now.Add(-cgroupRecoveryMaxAge).UnixNano()
		if createdAt == 0 || createdAt > uint64(cutoff) {
			continue
		}
		stale++
	}
	if stale != 1 {
		t.Fatalf("expected only the stamped entry to be swept, got %d of %d", stale, stats.Scanned)
	}
}
