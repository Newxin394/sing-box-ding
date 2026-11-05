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
	if _, err := backend.SweepUDPRecoveryBudgeted(0, uint64(time.Hour), 0); err == nil {
		t.Fatal("sweep with a zero max age should fail instead of deleting everything")
	}
	if _, err := backend.SweepUDPRecoveryBudgeted(-time.Second, uint64(time.Hour), 0); err == nil {
		t.Fatal("sweep with a negative max age should fail")
	}
}

func TestSweepUDPRecoveryBudgetedRejectsClosedBackend(t *testing.T) {
	var backend *commonEBPF.CgroupBackend
	if _, err := backend.SweepUDPRecoveryBudgeted(time.Minute, uint64(time.Hour), 0); err == nil {
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
func TestMonotonicNanosecondsAdvancesWithTheMonotonicClock(t *testing.T) {
	before, err := commonEBPF.MonotonicNanoseconds()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	after, err := commonEBPF.MonotonicNanoseconds()
	if err != nil {
		t.Fatal(err)
	}
	if after <= before {
		t.Fatalf("monotonic clock did not advance: before=%d after=%d", before, after)
	}
	// A monotonic reading is nanoseconds since boot, which is orders of
	// magnitude smaller than the wall clock's nanoseconds since 1970. Compare
	// against a generous floor rather than an exact value, since a device that
	// has been up for years still lands far below 1970-based counts.
	if wall := uint64(time.Now().UnixNano()); after >= wall {
		t.Fatalf("monotonic reading %d is not below the wall clock %d", after, wall)
	}
}

// A sweep that only ever sees entries with an unknown timestamp must not delete
// anything: those values come from objects built before the release hook stamped
// them, and guessing their age would cut flows that are still alive.
func TestRecoverySweepLeavesUnstampedEntriesAlone(t *testing.T) {
	nowNS, err := commonEBPF.MonotonicNanoseconds()
	if err != nil {
		t.Fatal(err)
	}
	maxAgeNS := uint64(cgroupRecoveryMaxAge)
	// The stale entry has to be older than cgroupRecoveryMaxAge but must still
	// be a value the table can hold, i.e. not underflow the subtraction on a
	// device that booted less than maxAge ago. Pick an age strictly between
	// maxAge and the current uptime, then floor it to at least maxAge+1ns.
	if nowNS <= maxAgeNS+1 {
		t.Skipf("monotonic clock is only %dns since boot, too young to build a stale entry", nowNS)
	}
	// Age it by half the uptime: guaranteed older than maxAge (since
	// uptime > maxAge) and guaranteed not to underflow.
	staleAge := nowNS / 2
	if staleAge <= maxAgeNS {
		staleAge = maxAgeNS + 1
	}
	var (
		stats commonEBPF.RecoverySweepStats
		stale int
	)
	for _, createdAt := range []uint64{0, nowNS - staleAge} {
		stats.Scanned++
		cutoff := nowNS - maxAgeNS
		if createdAt == 0 || createdAt > cutoff {
			continue
		}
		stale++
	}
	if stale != 1 {
		t.Fatalf("expected only the stamped entry to be swept, got %d of %d (now=%d, cutoff=%d)",
			stale, stats.Scanned, nowNS, nowNS-uint64(cgroupRecoveryMaxAge))
	}
}
