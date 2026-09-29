package capture

import (
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/control"
)

func TestNetworkPolicyTypedInterfaceWins(t *testing.T) {
	policy := DefaultNetworkPolicy()
	defaultInterface := &adapter.NetworkInterface{Interface: control.Interface{Name: "wlan0", Index: 7}}
	interfaces := []adapter.NetworkInterface{{
		Interface: control.Interface{Name: "wlan0", Index: 7, Flags: net.FlagUp},
		Type:      C.InterfaceTypeCellular,
	}}
	mode, class, ok := policy.Select(defaultInterface, interfaces)
	if !ok || mode != ModeTUN || class != NetworkCellular {
		t.Fatalf("Select = mode %s, class %s, ok %v; want tun/cellular/true", mode, class, ok)
	}
}

func TestNetworkPolicyFallsBackToAndroidInterfaceNames(t *testing.T) {
	policy := DefaultNetworkPolicy()
	for _, test := range []struct {
		name  string
		mode  Mode
		class NetworkClass
	}{
		{"wlan0", ModeTC, NetworkWiFi},
		{"ccmni1", ModeTUN, NetworkCellular},
		{"rmnet_data0", ModeTUN, NetworkCellular},
		{"eth0", ModeNone, NetworkUnknown},
	} {
		mode, class, ok := policy.Select(&adapter.NetworkInterface{Interface: control.Interface{Name: test.name}}, nil)
		if test.class == NetworkUnknown {
			if ok {
				t.Fatalf("Select(%q) ok=true, want false", test.name)
			}
			continue
		}
		if !ok || mode != test.mode || class != test.class {
			t.Fatalf("Select(%q) = mode %s, class %s, ok %v", test.name, mode, class, ok)
		}
	}
}

func TestNetworkPolicyDoesNotGuessMissingDefault(t *testing.T) {
	mode, class, ok := DefaultNetworkPolicy().Select(nil, nil)
	if ok || mode != ModeNone || class != NetworkUnknown {
		t.Fatalf("missing default = mode %s, class %s, ok %v", mode, class, ok)
	}
}
