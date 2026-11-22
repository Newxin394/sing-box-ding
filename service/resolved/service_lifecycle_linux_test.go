//go:build linux && !android

package resolved_test

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/internal/dbustest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/resolved"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/require"
)

type serviceTestMonitor struct {
	callbacks list.List[tun.NetworkUpdateCallback]
}

func (m *serviceTestMonitor) Start() error { return nil }
func (m *serviceTestMonitor) Close() error { return nil }
func (m *serviceTestMonitor) RegisterCallback(callback tun.NetworkUpdateCallback) *list.Element[tun.NetworkUpdateCallback] {
	return m.callbacks.PushBack(callback)
}
func (m *serviceTestMonitor) UnregisterCallback(element *list.Element[tun.NetworkUpdateCallback]) {
	m.callbacks.Remove(element)
}

type serviceTestNetwork struct {
	adapter.NetworkManager
	monitor *serviceTestMonitor
}

func (n serviceTestNetwork) NetworkMonitor() tun.NetworkUpdateMonitor { return n.monitor }

func TestResolvedServiceCloseReleasesOnlyItsBusConnection(t *testing.T) {
	dbustest.Start(t)
	shared, err := dbus.SystemBus()
	require.NoError(t, err)
	t.Cleanup(func() { _ = shared.Close() })
	ctx := service.ContextWithDefaultRegistry(context.Background())
	factory := log.NewNOPFactory()
	service.MustRegister[adapter.NetworkManager](ctx, serviceTestNetwork{monitor: new(serviceTestMonitor)})
	service.MustRegister[adapter.ServiceManager](ctx, boxService.NewManager(factory.Logger(), nil))
	current, err := resolved.NewService(ctx, factory.NewLogger("resolved"), "resolved-test", option.ResolvedServiceOptions{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = current.Close() })
	require.NoError(t, current.Start(adapter.StartStateInitialize))
	var names []string
	require.NoError(t, shared.BusObject().Call("org.freedesktop.DBus.ListNames", 0).Store(&names))
	require.Contains(t, names, "org.freedesktop.resolve1")
	require.NoError(t, current.Close())
	require.NoError(t, shared.BusObject().Call("org.freedesktop.DBus.ListNames", 0).Store(&names))
	require.NotContains(t, names, "org.freedesktop.resolve1")
}
