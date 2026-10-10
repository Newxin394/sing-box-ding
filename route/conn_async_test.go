package route

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type testCountingCloser struct {
	once   sync.Once
	closed chan struct{}
}

func (c *testCountingCloser) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func TestConnectionManagerCloseAllAsyncDrainsTrackedConnections(t *testing.T) {
	manager := NewConnectionManager(nil)
	closer := &testCountingCloser{closed: make(chan struct{})}

	manager.access.Lock()
	manager.connections.PushBack(closer)
	manager.access.Unlock()

	manager.CloseAllAsync()
	require.Equal(t, 0, manager.Count())

	select {
	case <-closer.closed:
	case <-time.After(time.Second):
		t.Fatal("async close worker did not close the connection")
	}

	require.NoError(t, manager.Close())
}
