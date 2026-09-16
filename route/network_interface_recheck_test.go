package route

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// interfaceRecheckMonitor stands in for the default interface monitor. It
// records the Start/Close cycles the recheck loop performs and reports a
// default interface only once the test allows it, which is the state Android
// leaves the monitor in when it withdraws a network's default route and puts it
// back without touching the link.
type interfaceRecheckMonitor struct {
	tun.DefaultInterfaceMonitor
	access    sync.Mutex
	events    []string
	available bool
}

func (m *interfaceRecheckMonitor) Start() error {
	m.access.Lock()
	defer m.access.Unlock()
	m.events = append(m.events, "start")
	return nil
}

func (m *interfaceRecheckMonitor) Close() error {
	m.access.Lock()
	defer m.access.Unlock()
	m.events = append(m.events, "close")
	return nil
}

func (m *interfaceRecheckMonitor) DefaultInterface() *control.Interface {
	m.access.Lock()
	defer m.access.Unlock()
	if !m.available {
		return nil
	}
	return &control.Interface{Name: "test", Index: 1}
}

func (m *interfaceRecheckMonitor) setAvailable(available bool) {
	m.access.Lock()
	defer m.access.Unlock()
	m.available = available
}

func (m *interfaceRecheckMonitor) recorded() []string {
	m.access.Lock()
	defer m.access.Unlock()
	return append([]string(nil), m.events...)
}

func newInterfaceRecheckManager(t *testing.T, monitor tun.DefaultInterfaceMonitor) *NetworkManager {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctx = pause.WithDefaultManager(ctx)
	manager := &NetworkManager{
		ctx:              ctx,
		logger:           log.NewNOPFactory().NewLogger("network"),
		pauseManager:     service.FromContext[pause.Manager](ctx),
		interfaceMonitor: monitor,
	}
	t.Cleanup(manager.cancelInterfaceMonitorRecheck)
	return manager
}

func (r *NetworkManager) pendingInterfaceRecheck() *time.Timer {
	r.interfaceRecheckAccess.Lock()
	defer r.interfaceRecheckAccess.Unlock()
	return r.interfaceRecheckTimer
}

// A missing default interface must arm a retry, and repeated reports of the
// same state must not stack timers on top of each other.
func TestMissingDefaultInterfaceArmsSingleRecheck(t *testing.T) {
	monitor := new(interfaceRecheckMonitor)
	manager := newInterfaceRecheckManager(t, monitor)
	manager.notifyInterfaceUpdate(nil, 0)
	first := manager.pendingInterfaceRecheck()
	require.NotNil(t, first, "reported a missing interface without arming a retry")
	manager.notifyInterfaceUpdate(nil, 0)
	require.Same(t, first, manager.pendingInterfaceRecheck(), "armed a second retry for the same missing interface")
}

// The retry has to be cancelled once an interface is delivered again, so no
// polling is left behind.
func TestInterfaceRecheckCancelledOnRecovery(t *testing.T) {
	monitor := new(interfaceRecheckMonitor)
	manager := newInterfaceRecheckManager(t, monitor)
	manager.notifyInterfaceUpdate(nil, 0)
	require.NotNil(t, manager.pendingInterfaceRecheck())
	manager.cancelInterfaceMonitorRecheck()
	require.Nil(t, manager.pendingInterfaceRecheck())
	// Cancelling twice, and cancelling nothing, must stay harmless.
	manager.cancelInterfaceMonitorRecheck()
}

// The armed retry must actually fire, and it must re-arm itself while the
// monitor still reports nothing.
func TestInterfaceRecheckRetriesUntilAvailable(t *testing.T) {
	monitor := new(interfaceRecheckMonitor)
	manager := newInterfaceRecheckManager(t, monitor)
	manager.notifyInterfaceUpdate(nil, 0)
	require.Eventually(t, func() bool {
		return len(monitor.recorded()) >= 2
	}, 3*defaultInterfaceRecheckInterval, 25*time.Millisecond, "armed retry never ran")
	require.Equal(t, []string{"close", "start"}, monitor.recorded()[:2],
		"the retry must detach before re-attaching, otherwise callbacks stack on the update monitor")
	require.NotNil(t, manager.pendingInterfaceRecheck(), "stopped retrying while the monitor still reported nothing")
}

// Once the monitor reports an interface again the loop has to stop for good.
func TestInterfaceRecheckStopsOnceAvailable(t *testing.T) {
	monitor := new(interfaceRecheckMonitor)
	manager := newInterfaceRecheckManager(t, monitor)
	manager.notifyInterfaceUpdate(nil, 0)
	monitor.setAvailable(true)
	manager.recheckInterfaceMonitor()
	require.Equal(t, []string{"close", "start"}, monitor.recorded())
	require.Nil(t, manager.pendingInterfaceRecheck(), "kept polling after the interface came back")
	// A recovered monitor must not start a second cycle on its own.
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, []string{"close", "start"}, monitor.recorded())
}
