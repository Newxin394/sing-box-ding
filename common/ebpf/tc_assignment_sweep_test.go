//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"
	"time"
)

// A nil backend is what the maintenance loop sees before the data plane is
// attached, and what it sees again after it is torn down. Both must be an error
// the caller can recognise, not a panic on a nil receiver.
func TestSweepAssignmentsRejectsClosedBackend(t *testing.T) {
	var backend *TCBackend
	if _, err := backend.SweepAssignments(time.Minute, 0); err == nil {
		t.Fatal("sweep on a nil backend should fail")
	}
	empty := &TCBackend{}
	if _, err := empty.SweepAssignments(time.Minute, 0); err == nil {
		t.Fatal("sweep on a backend without kernel objects should fail")
	}
}

func TestAssignmentUsageRejectsClosedBackend(t *testing.T) {
	var backend *TCBackend
	if _, err := backend.AssignmentUsage(); err == nil {
		t.Fatal("usage on a nil backend should fail")
	}
}

// The kernel refreshes an assignment's stamp at most once per second, so a
// window at or below that describes flows that are alive but look a second old.
// Raising it here is what keeps a short caller window from deleting them.
func TestTCAssignmentIdleWindowRaisesShortWindows(t *testing.T) {
	for _, short := range []time.Duration{0, time.Millisecond, time.Second, tcAssignmentSweepMinimumMaxAge} {
		if got := tcAssignmentIdleWindow(short); got != tcAssignmentSweepMinimumMaxAge {
			t.Fatalf("window %v should be raised to %v, got %v", short, tcAssignmentSweepMinimumMaxAge, got)
		}
	}
	longer := tcAssignmentSweepMinimumMaxAge + time.Minute
	if got := tcAssignmentIdleWindow(longer); got != longer {
		t.Fatalf("window %v should be kept as is, got %v", longer, got)
	}
}

// The stamp granularity is a kernel-side constant; pin the Go side to it so the
// two cannot drift apart silently.
func TestTCAssignmentSweepMinimumCoversTheKernelRefresh(t *testing.T) {
	const kernelRefresh = time.Second
	if tcAssignmentSweepMinimumMaxAge <= kernelRefresh {
		t.Fatalf(
			"the minimum window (%v) must stay above the kernel refresh granularity (%v), otherwise live assignments age out",
			tcAssignmentSweepMinimumMaxAge, kernelRefresh,
		)
	}
}
