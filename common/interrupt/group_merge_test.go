package interrupt

import (
	"testing"
	"time"
)

type mergeTestCloser struct {
	closeFunc func()
	count     int
}

func (c *mergeTestCloser) Close() error {
	c.count++
	if c.closeFunc != nil {
		c.closeFunc()
	}
	return nil
}

func TestMergeInterruptClosesOutsideLock(t *testing.T) {
	g := NewGroup()
	c := &mergeTestCloser{}
	c.closeFunc = g.Add(c, true, false)
	done := make(chan struct{})
	go func() { g.Interrupt(true); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close callback deadlocked while removing itself")
	}
	if c.count != 1 {
		t.Fatalf("close count %d", c.count)
	}
}

func TestMergeInterruptPreservesProviderAndExternalPolicy(t *testing.T) {
	g := NewGroup()
	provider, external, internal := &mergeTestCloser{}, &mergeTestCloser{}, &mergeTestCloser{}
	g.Add(provider, false, true)
	g.Add(external, true, false)
	g.Add(internal, false, false)
	g.Interrupt(false)
	if provider.count != 0 || external.count != 0 || internal.count != 1 {
		t.Fatal("incorrect selective interruption")
	}
	g.Interrupt(true)
	g.Interrupt(true)
	if provider.count != 0 || external.count != 1 || internal.count != 1 {
		t.Fatal("provider protection or one-time removal failed")
	}
}
