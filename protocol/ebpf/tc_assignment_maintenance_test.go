//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"
	"time"
)

// Generation zero means "never stamped", so the wrap has to skip it: reusing it
// would make fresh assignments look unstamped and the sweep would keep them
// forever.
func TestNextNetworkGenerationSkipsZero(t *testing.T) {
	if got := nextNetworkGeneration(0); got != 1 {
		t.Fatalf("generation 0 should advance to 1, got %d", got)
	}
	if got := nextNetworkGeneration(65535); got != 1 {
		t.Fatalf("the wrap should skip 0, got %d", got)
	}
	if got := nextNetworkGeneration(7); got != 8 {
		t.Fatalf("generation 7 should advance to 8, got %d", got)
	}
}

// A sweep without a TC data plane is what a cgroup-only inbound does on every
// tick, so it has to be silent rather than a warning per minute.
func TestSweepTCAssignmentsWithoutBackendIsSilent(t *testing.T) {
	inbound := &Inbound{}
	inbound.sweepTCAssignmentsBudgeted(time.Minute, mapMaintenanceSweepBudget, false)
	if inbound.AssignmentSweepPressure() {
		t.Fatal("a sweep without a backend must not report pressure")
	}
	status := inbound.tcAssignmentSweepDiagnostics()
	if status.runs != 0 {
		t.Fatalf("a sweep without a backend recorded a run: %+v", status)
	}
}

// The pressure window has to be shorter than the relaxed one, and both have to
// stay well above the kernel's refresh granularity, or the sweep burns CPU
// re-assigning flows that are still alive.
func TestTCAssignmentIdleWindows(t *testing.T) {
	if tcAssignmentIdlePressure >= tcAssignmentIdleRelaxed {
		t.Fatalf(
			"a pressured table must be swept more often than a relaxed one: pressure=%v relaxed=%v",
			tcAssignmentIdlePressure, tcAssignmentIdleRelaxed,
		)
	}
	if tcAssignmentIdlePressure < cgroupRecoveryMaxAge {
		t.Fatalf(
			"an assignment window (%v) shorter than the UDP recovery window (%v) would retire live flows: an assignment is a flow's socket mapping, not a pending packet",
			tcAssignmentIdlePressure, cgroupRecoveryMaxAge,
		)
	}
}
