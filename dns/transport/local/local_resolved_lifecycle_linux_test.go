//go:build linux && !android

package local_test

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/internal/dbustest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/require"
)

type resolvedTestMonitor struct {
	callbacks list.List[tun.DefaultInterfaceUpdateCallback]
}

func (m *resolvedTestMonitor) Start() error                         { return nil }
func (m *resolvedTestMonitor) Close() error                         { return nil }
func (m *resolvedTestMonitor) DefaultInterface() *control.Interface { return nil }
func (m *resolvedTestMonitor) OverrideAndroidVPN() bool             { return false }
func (m *resolvedTestMonitor) AndroidVPNEnabled() bool              { return false }
func (m *resolvedTestMonitor) RegisterCallback(callback tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	return m.callbacks.PushBack(callback)
}
func (m *resolvedTestMonitor) UnregisterCallback(element *list.Element[tun.DefaultInterfaceUpdateCallback]) {
	m.callbacks.Remove(element)
}
func (m *resolvedTestMonitor) RegisterMyInterface(string) {}
func (m *resolvedTestMonitor) MyInterfaces() []string     { return nil }

type resolvedTestNetwork struct {
	adapter.NetworkManager
	monitor *resolvedTestMonitor
}

func (n resolvedTestNetwork) InterfaceMonitor() tun.DefaultInterfaceMonitor { return n.monitor }

func TestResolvedResolverStartAndCloseKeepsOtherBusClients(t *testing.T) {
	dbustest.Start(t)
	shared, err := dbus.SystemBus()
	require.NoError(t, err)
	t.Cleanup(func() { _ = shared.Close() })
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), resolvedTestNetwork{monitor: new(resolvedTestMonitor)})
	resolver, err := local.NewResolvedResolver(ctx, log.NewNOPFactory().Logger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = resolver.Close() })
	require.NoError(t, resolver.Start())
	require.NoError(t, resolver.Close())
	var names []string
	require.NoError(t, shared.BusObject().Call("org.freedesktop.DBus.ListNames", 0).Store(&names))
	require.Contains(t, names, "org.freedesktop.DBus")
}
