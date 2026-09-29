package capture

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Mode identifies the packet-capture backend that owns interception.
type Mode uint8

const (
	ModeNone Mode = iota
	ModeTC
	ModeTUN
)

func (m Mode) String() string {
	switch m {
	case ModeNone:
		return "none"
	case ModeTC:
		return "tc"
	case ModeTUN:
		return "tun"
	default:
		return fmt.Sprintf("mode(%d)", m)
	}
}

// Owner is the lifecycle seam between the coordinator and a capture backend.
//
// Prepare must leave the backend inactive and may allocate resources. Activate
// starts interception. Deactivate must be idempotent and remove every runtime
// interception resource while leaving the owner reusable. Close is final and
// is called once when the coordinator is closed.
type Owner interface {
	Prepare() error
	Activate() error
	Deactivate() error
	Close() error
}

// Failure describes an asynchronous transition failure reported by Errors.
type Failure struct {
	Generation uint64
	From       Mode
	To         Mode
	Result     Mode
	Err        error
}

func (f Failure) Error() string {
	return fmt.Sprintf("capture transition %s -> %s failed (result=%s, generation=%d): %v", f.From, f.To, f.Result, f.Generation, f.Err)
}

func (f Failure) Unwrap() error { return f.Err }

// ErrClosed is returned by synchronous operations after Close.
var ErrClosed = errors.New("capture coordinator is closed")

// Options controls the asynchronous RequestMode path.
type Options struct {
	// Debounce coalesces rapid network changes. Zero applies a request as soon
	// as the coordinator loop receives it.
	Debounce time.Duration
	// ErrorBuffer bounds asynchronous transition failures retained by Errors.
	// Zero uses a small default buffer.
	ErrorBuffer int
}

// Coordinator serializes capture ownership transitions. It deliberately
// permits only one owner to be active at a time; this is the first-stage
// architecture for Wi-Fi=TC and cellular=TUN.
type Coordinator struct {
	owners [3]Owner

	stateAccess sync.Mutex
	current     Mode
	closed      bool
	generation  uint64
	pendingMode Mode
	pendingGen  uint64
	appliedGen  uint64

	transitionAccess sync.Mutex
	debounce         time.Duration
	wake             chan struct{}
	stop             chan struct{}
	done             chan struct{}
	errors           chan Failure
}

// New constructs a coordinator. Either owner may be nil, but requesting a
// mode without an owner fails and leaves the previous mode active when it can
// be restored.
func New(tc Owner, tun Owner, options Options) *Coordinator {
	if options.ErrorBuffer <= 0 {
		options.ErrorBuffer = 16
	}
	c := &Coordinator{
		owners:   [3]Owner{nil, tc, tun},
		debounce: options.Debounce,
		wake:     make(chan struct{}, 1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		errors:   make(chan Failure, options.ErrorBuffer),
	}
	go c.run()
	return c
}

// Current returns the last successfully established mode. During a failed
// transition it is either the old mode (successful rollback) or ModeNone.
func (c *Coordinator) Current() Mode {
	c.stateAccess.Lock()
	defer c.stateAccess.Unlock()
	return c.current
}

// Errors receives failures from RequestMode. Synchronous SwitchMode returns
// its error directly and does not publish a duplicate Failure.
func (c *Coordinator) Errors() <-chan Failure { return c.errors }

// RequestMode schedules a debounced transition and returns its generation.
// Newer requests supersede older requests that have not started.
func (c *Coordinator) RequestMode(mode Mode) uint64 {
	if !validMode(mode) {
		return 0
	}
	c.stateAccess.Lock()
	if c.closed {
		c.stateAccess.Unlock()
		return 0
	}
	c.generation++
	generation := c.generation
	c.pendingMode = mode
	c.pendingGen = generation
	c.stateAccess.Unlock()
	c.signal()
	return generation
}

// SwitchMode applies a transition synchronously. It still participates in the
// generation ordering: a newer request wins if it arrives before this call
// acquires the transition seam.
func (c *Coordinator) SwitchMode(mode Mode) error {
	if !validMode(mode) {
		return fmt.Errorf("invalid capture mode: %d", mode)
	}
	c.stateAccess.Lock()
	if c.closed {
		c.stateAccess.Unlock()
		return ErrClosed
	}
	c.generation++
	generation := c.generation
	c.pendingMode = mode
	c.pendingGen = generation
	c.stateAccess.Unlock()
	return c.apply(mode, generation)
}

// WaitMode waits until mode becomes current or ctx is cancelled. It is useful
// to make callers and tests explicit about the asynchronous transition.
func (c *Coordinator) WaitMode(ctx context.Context, mode Mode) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if c.Current() == mode {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Close stops the request loop, deactivates the current owner, and finally
// closes both owners. It is idempotent.
func (c *Coordinator) Close() error {
	c.stateAccess.Lock()
	if c.closed {
		c.stateAccess.Unlock()
		return nil
	}
	c.closed = true
	c.stateAccess.Unlock()

	close(c.stop)
	<-c.done

	c.transitionAccess.Lock()
	defer c.transitionAccess.Unlock()

	c.stateAccess.Lock()
	current := c.current
	c.current = ModeNone
	c.stateAccess.Unlock()

	var closeErr error
	if owner := c.owner(current); owner != nil {
		closeErr = errors.Join(closeErr, owner.Deactivate())
	}
	for _, owner := range c.owners[1:] {
		if owner != nil {
			closeErr = errors.Join(closeErr, owner.Close())
		}
	}
	close(c.errors)
	return closeErr
}

func (c *Coordinator) run() {
	defer close(c.done)
	var timer *time.Timer
	var timerC <-chan time.Time
	resetTimer := func() {
		if timer == nil {
			timer = time.NewTimer(c.debounce)
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(c.debounce)
	}
	for {
		select {
		case <-c.stop:
			if timer != nil {
				timer.Stop()
			}
			return
		case <-c.wake:
			if c.debounce <= 0 {
				mode, generation, ok := c.pending()
				if ok {
					if err := c.apply(mode, generation); err != nil {
						c.publish(Failure{Generation: generation, From: c.Current(), To: mode, Result: c.Current(), Err: err})
					}
				}
				continue
			}
			resetTimer()
			timerC = timer.C
		case <-timerC:
			timerC = nil
			mode, generation, ok := c.pending()
			if !ok {
				continue
			}
			if err := c.apply(mode, generation); err != nil {
				c.publish(Failure{Generation: generation, From: c.Current(), To: mode, Result: c.Current(), Err: err})
			}
		}
	}
}

func (c *Coordinator) pending() (Mode, uint64, bool) {
	c.stateAccess.Lock()
	defer c.stateAccess.Unlock()
	if c.closed || c.pendingGen == 0 {
		return ModeNone, 0, false
	}
	return c.pendingMode, c.pendingGen, true
}

func (c *Coordinator) apply(mode Mode, generation uint64) error {
	c.transitionAccess.Lock()
	defer c.transitionAccess.Unlock()

	c.stateAccess.Lock()
	if c.closed {
		c.stateAccess.Unlock()
		return ErrClosed
	}
	if generation != c.generation || generation != c.pendingGen || generation <= c.appliedGen {
		c.stateAccess.Unlock()
		return nil
	}
	from := c.current
	c.appliedGen = generation
	c.stateAccess.Unlock()

	result, err := c.transition(from, mode)
	c.stateAccess.Lock()
	c.current = result
	c.stateAccess.Unlock()
	return err
}

func (c *Coordinator) transition(from, to Mode) (Mode, error) {
	if from == to {
		return from, nil
	}
	oldOwner := c.owner(from)
	if from != ModeNone && oldOwner == nil {
		return ModeNone, fmt.Errorf("current mode %s has no owner", from)
	}
	if oldOwner != nil {
		if err := oldOwner.Deactivate(); err != nil {
			return from, fmt.Errorf("deactivate %s owner: %w", from, err)
		}
	}
	if to == ModeNone {
		return ModeNone, nil
	}
	targetOwner := c.owner(to)
	if targetOwner == nil {
		return c.restore(from, oldOwner, fmt.Errorf("capture owner for %s is nil", to))
	}
	if err := targetOwner.Prepare(); err != nil {
		cleanupErr := targetOwner.Deactivate()
		return c.restore(from, oldOwner, errors.Join(fmt.Errorf("prepare %s owner: %w", to, err), cleanupErr))
	}
	if err := targetOwner.Activate(); err != nil {
		cleanupErr := targetOwner.Deactivate()
		return c.restore(from, oldOwner, errors.Join(fmt.Errorf("activate %s owner: %w", to, err), cleanupErr))
	}
	return to, nil
}

func (c *Coordinator) restore(from Mode, owner Owner, transitionErr error) (Mode, error) {
	if from == ModeNone || owner == nil {
		return ModeNone, transitionErr
	}
	if err := owner.Activate(); err != nil {
		return ModeNone, errors.Join(transitionErr, fmt.Errorf("restore %s owner: %w", from, err))
	}
	return from, transitionErr
}

func (c *Coordinator) owner(mode Mode) Owner {
	if !validMode(mode) {
		return nil
	}
	return c.owners[mode]
}

func (c *Coordinator) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *Coordinator) publish(failure Failure) {
	select {
	case c.errors <- failure:
	default:
	}
}

func validMode(mode Mode) bool { return mode <= ModeTUN }
