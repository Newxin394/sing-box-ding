package capture

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

type fakeOwner struct {
	mu sync.Mutex

	name        string
	events      *[]string
	prepareErr  error
	activateErr error
	closeErr    error
	prepareGate <-chan struct{}
	active      bool
	prepares    int
	activates   int
	deactivates int
	closes      int
}

func (o *fakeOwner) Prepare() error {
	if o.prepareGate != nil {
		<-o.prepareGate
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.prepares++
	if o.events != nil {
		*o.events = append(*o.events, o.name+":prepare")
	}
	return o.prepareErr
}

func (o *fakeOwner) Activate() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.activates++
	if o.events != nil {
		*o.events = append(*o.events, o.name+":activate")
	}
	if o.activateErr == nil {
		o.active = true
	}
	return o.activateErr
}

func (o *fakeOwner) Deactivate() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.deactivates++
	o.active = false
	if o.events != nil {
		*o.events = append(*o.events, o.name+":deactivate")
	}
	return nil
}

func (o *fakeOwner) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closes++
	o.active = false
	if o.events != nil {
		*o.events = append(*o.events, o.name+":close")
	}
	return o.closeErr
}

func (o *fakeOwner) counts() (prepares, activates, deactivates, closes int, active bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.prepares, o.activates, o.deactivates, o.closes, o.active
}

func TestCoordinatorSwitchesSingleActiveOwner(t *testing.T) {
	var events []string
	tc := &fakeOwner{name: "tc", events: &events}
	tun := &fakeOwner{name: "tun", events: &events}
	c := New(tc, tun, Options{})
	defer c.Close()

	if err := c.SwitchMode(ModeTC); err != nil {
		t.Fatal(err)
	}
	if got := c.Current(); got != ModeTC {
		t.Fatalf("current after TC = %s, want tc", got)
	}
	if err := c.SwitchMode(ModeTUN); err != nil {
		t.Fatal(err)
	}
	if got := c.Current(); got != ModeTUN {
		t.Fatalf("current after TUN = %s, want tun", got)
	}
	if err := c.SwitchMode(ModeNone); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"tc:prepare", "tc:activate",
		"tc:deactivate", "tun:prepare", "tun:activate",
		"tun:deactivate",
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %#v, want %#v", events, want)
	}
	_, tcActivates, tcDeactivates, _, tcActive := tc.counts()
	_, tunActivates, tunDeactivates, _, tunActive := tun.counts()
	if tcActivates != 1 || tcDeactivates != 1 || tcActive {
		t.Fatalf("TC counts/active = %d/%d/%v", tcActivates, tcDeactivates, tcActive)
	}
	if tunActivates != 1 || tunDeactivates != 1 || tunActive {
		t.Fatalf("TUN counts/active = %d/%d/%v", tunActivates, tunDeactivates, tunActive)
	}
}

func TestCoordinatorRestoresPreviousOwnerOnFailure(t *testing.T) {
	tc := &fakeOwner{name: "tc"}
	tun := &fakeOwner{name: "tun", activateErr: errors.New("tun unavailable")}
	c := New(tc, tun, Options{})
	defer c.Close()

	if err := c.SwitchMode(ModeTC); err != nil {
		t.Fatal(err)
	}
	if err := c.SwitchMode(ModeTUN); err == nil {
		t.Fatal("SwitchMode(TUN) succeeded, want failure")
	}
	if got := c.Current(); got != ModeTC {
		t.Fatalf("current after rollback = %s, want tc", got)
	}
	_, tcActivates, tcDeactivates, _, tcActive := tc.counts()
	_, tunActivates, tunDeactivates, _, tunActive := tun.counts()
	if tcActivates != 2 || tcDeactivates != 1 || !tcActive {
		t.Fatalf("TC rollback counts/active = %d/%d/%v", tcActivates, tcDeactivates, tcActive)
	}
	if tunActivates != 1 || tunDeactivates != 1 || tunActive {
		t.Fatalf("TUN failure cleanup counts/active = %d/%d/%v", tunActivates, tunDeactivates, tunActive)
	}
}

func TestCoordinatorDebouncesToLatestRequest(t *testing.T) {
	var events []string
	tc := &fakeOwner{name: "tc", events: &events}
	tun := &fakeOwner{name: "tun", events: &events}
	c := New(tc, tun, Options{Debounce: 25 * time.Millisecond})
	defer c.Close()

	if generation := c.RequestMode(ModeTC); generation == 0 {
		t.Fatal("RequestMode(TC) returned generation zero")
	}
	if generation := c.RequestMode(ModeTUN); generation == 0 {
		t.Fatal("RequestMode(TUN) returned generation zero")
	}
	waitForMode(t, c, ModeTUN)

	_, tcActivates, _, _, _ := tc.counts()
	_, tunActivates, _, _, _ := tun.counts()
	if tcActivates != 0 || tunActivates != 1 {
		t.Fatalf("activations after debounce = tc:%d tun:%d, want tc:0 tun:1", tcActivates, tunActivates)
	}
}

func TestCoordinatorReportsAsyncFailure(t *testing.T) {
	tun := &fakeOwner{name: "tun", activateErr: errors.New("activation failed")}
	c := New(nil, tun, Options{Debounce: 1 * time.Millisecond})
	defer c.Close()
	c.RequestMode(ModeTUN)

	select {
	case failure := <-c.Errors():
		if failure.To != ModeTUN || failure.Result != ModeNone {
			t.Fatalf("failure = %#v", failure)
		}
		if !errors.Is(failure, tun.activateErr) {
			t.Fatalf("failure does not unwrap activation error: %v", failure)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for async failure")
	}
}

func TestCoordinatorClosesBothOwners(t *testing.T) {
	tc := &fakeOwner{name: "tc"}
	tun := &fakeOwner{name: "tun"}
	c := New(tc, tun, Options{})
	if err := c.SwitchMode(ModeTC); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if got := c.Current(); got != ModeNone {
		t.Fatalf("current after close = %s, want none", got)
	}
	_, _, tcDeactivates, tcCloses, _ := tc.counts()
	_, _, tunDeactivates, tunCloses, _ := tun.counts()
	if tcDeactivates != 1 || tunDeactivates != 0 || tcCloses != 1 || tunCloses != 1 {
		t.Fatalf("close counts = tc deactivate/close %d/%d, tun %d/%d", tcDeactivates, tcCloses, tunDeactivates, tunCloses)
	}
}

func waitForMode(t *testing.T, c *Coordinator, mode Mode) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if c.Current() == mode {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for mode %s; current=%s", mode, c.Current())
}
