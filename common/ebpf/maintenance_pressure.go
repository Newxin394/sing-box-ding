//go:build with_ebpf && (linux || android)

package ebpf

// MapPressureEnterRatio and MapPressureExitRatio bracket the map pressure
// hysteresis.
//
// A single threshold would make a table sit exactly at its limit flap between
// "pressured" and "relaxed" on every tick, and each flap runs an expensive
// sweep. Entering at 70% and leaving at 50% means the sweeps only run while
// there is something to reclaim, and stop once headroom is back.
const (
	MapPressureEnterRatio = 0.70
	MapPressureExitRatio  = 0.50
)

// MapPressureTracker turns a sequence of map fill levels into a hysteresis
// decision.
//
// The zero value is relaxed. Callers feed it whatever entries/capacity they
// already read (the occupancy report, the userspace flow accounting) and act
// only when Observe returns true.
type MapPressureTracker struct {
	pressured bool
}

// Pressured reports whether the tracker is currently in the pressured state.
func (t *MapPressureTracker) Pressured() bool {
	return t != nil && t.pressured
}

// Observe folds one fill ratio into the state and reports whether the caller
// should run maintenance now.
//
// A capacity of zero means the map was never sized for this feature, so it
// carries no signal either way and leaves the state untouched.
func (t *MapPressureTracker) Observe(entries, capacity uint32) bool {
	if t == nil || capacity == 0 {
		return false
	}
	ratio := float64(entries) / float64(capacity)
	switch {
	case !t.pressured && ratio >= MapPressureEnterRatio:
		t.pressured = true
	case t.pressured && ratio < MapPressureExitRatio:
		t.pressured = false
	}
	return t.pressured
}

// ObservePressure feeds a level already classified by MapPressureLevel.
//
// Userspace accounting often only has the level, not the raw counts: a flow
// table under warning pressure has already crossed the enter threshold, so the
// level alone is enough to enter and healthy is enough to leave.
func (t *MapPressureTracker) ObservePressure(level string) bool {
	if t == nil {
		return false
	}
	switch level {
	case MapPressureWarning, MapPressureDegraded:
		t.pressured = true
	case MapPressureHealthy:
		t.pressured = false
	}
	return t.pressured
}
