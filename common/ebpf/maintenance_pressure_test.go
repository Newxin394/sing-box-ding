//go:build with_ebpf && (linux || android)

package ebpf

import "testing"

func TestMapPressureTrackerEntersAboveTheEnterRatio(t *testing.T) {
	var tracker MapPressureTracker
	if tracker.Observe(69, 100) {
		t.Fatal("69% is below the enter threshold")
	}
	if !tracker.Observe(70, 100) {
		t.Fatal("70% is the enter threshold")
	}
	if !tracker.Observe(71, 100) {
		t.Fatal("a pressured tracker stays pressured")
	}
}

// The whole point of two thresholds: a table drifting around the enter ratio
// must not flip on every tick, because each flip runs a sweep.
func TestMapPressureTrackerStaysPressuredUntilTheExitRatio(t *testing.T) {
	var tracker MapPressureTracker
	if !tracker.Observe(90, 100) {
		t.Fatal("90% should be pressured")
	}
	if !tracker.Observe(60, 100) {
		t.Fatal("60% is between the thresholds and must stay pressured")
	}
	if !tracker.Observe(51, 100) {
		t.Fatal("51% is still above the exit threshold")
	}
	if tracker.Observe(49, 100) {
		t.Fatal("49% is below the exit threshold")
	}
	// Coming back up has to cross the enter threshold again, not just the exit
	// one.
	if tracker.Observe(60, 100) {
		t.Fatal("re-entering must require the enter threshold")
	}
	if !tracker.Observe(70, 100) {
		t.Fatal("70% should re-enter pressure")
	}
}

func TestMapPressureTrackerIgnoresUnconfiguredMaps(t *testing.T) {
	var tracker MapPressureTracker
	if tracker.Observe(1, 0) {
		t.Fatal("a capacity of zero carries no signal")
	}
	if tracker.Pressured() {
		t.Fatal("an unconfigured map must not leave the tracker pressured")
	}
}

func TestMapPressureTrackerAcceptsPreclassifiedLevels(t *testing.T) {
	var tracker MapPressureTracker
	if !tracker.ObservePressure(MapPressureWarning) {
		t.Fatal("warning pressure should enter")
	}
	if !tracker.ObservePressure(MapPressureUnknown) {
		t.Fatal("an unreadable level must not clear pressure")
	}
	if tracker.ObservePressure(MapPressureHealthy) {
		t.Fatal("healthy should leave")
	}
}

func TestNilMapPressureTrackerIsRelaxed(t *testing.T) {
	var tracker *MapPressureTracker
	if tracker.Pressured() {
		t.Fatal("a nil tracker is not pressured")
	}
	if tracker.Observe(100, 100) {
		t.Fatal("a nil tracker never asks for maintenance")
	}
	if tracker.ObservePressure(MapPressureWarning) {
		t.Fatal("a nil tracker never asks for maintenance")
	}
}
