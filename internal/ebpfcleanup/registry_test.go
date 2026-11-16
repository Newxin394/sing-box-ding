package ebpfcleanup

import (
	"errors"
	"testing"
)

func TestRetainIsIdempotent(t *testing.T) {
	t.Cleanup(func() { retryLastCleanup(t) })
	calls := 0
	entry := New(func() error {
		calls++
		return nil
	})
	Retain(entry)
	Retain(entry)
	if !Contains(entry) {
		t.Fatal("entry is not retained")
	}
	if err := Retry(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("cleanup ran %d times, want 1", calls)
	}
}

func TestReleaseStopsRetry(t *testing.T) {
	calls := 0
	entry := New(func() error {
		calls++
		return nil
	})
	Retain(entry)
	Release(entry)
	if Contains(entry) {
		t.Fatal("entry is still retained after release")
	}
	if err := Retry(); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("released cleanup ran %d times, want 0", calls)
	}
}

func TestRetryReportsFailuresAndKeepsEntries(t *testing.T) {
	t.Cleanup(func() { retryLastCleanup(t) })
	wanted := errors.New("still attached")
	entry := New(func() error { return wanted })
	Retain(entry)
	err := Retry()
	if !errors.Is(err, wanted) {
		t.Fatalf("retry error = %v, want %v", err, wanted)
	}
	// A failed cleanup stays retained so a later Close can try again.
	if !Contains(entry) {
		t.Fatal("failed entry was dropped")
	}
	Release(entry)
}

func TestNilEntryIsIgnored(t *testing.T) {
	Retain(nil)
	Release(nil)
	if Contains(nil) {
		t.Fatal("nil entry reported as retained")
	}
}

// retryLastCleanup releases everything a test retained, so one test cannot
// leak entries into the next.
func retryLastCleanup(t *testing.T) {
	t.Helper()
	_ = Retry()
	retained.access.Lock()
	entries := retained.entries
	retained.entries = nil
	retained.access.Unlock()
	for _, entry := range entries {
		_ = entry.close()
	}
}
