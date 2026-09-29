package capture

import (
	"path"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

// NetworkClass is the physical network class used to select a capture owner.
type NetworkClass uint8

const (
	NetworkUnknown NetworkClass = iota
	NetworkWiFi
	NetworkCellular
	NetworkOther
)

func (c NetworkClass) String() string {
	switch c {
	case NetworkWiFi:
		return "wifi"
	case NetworkCellular:
		return "cellular"
	case NetworkOther:
		return "other"
	default:
		return "unknown"
	}
}

// NetworkPolicy maps a physical network class to a capture mode. The default
// policy is the intended Android split: Wi-Fi uses TC and cellular uses TUN.
type NetworkPolicy struct {
	WiFiMode     Mode
	CellularMode Mode
	OtherMode    Mode

	// Interface patterns are only a fallback when NetworkManager does not
	// provide a typed NetworkInterface entry. They use path.Match syntax.
	WiFiInterfaces     []string
	CellularInterfaces []string
}

func DefaultNetworkPolicy() NetworkPolicy {
	return NetworkPolicy{
		WiFiMode:           ModeTC,
		CellularMode:       ModeTUN,
		OtherMode:          ModeNone,
		WiFiInterfaces:     []string{"wlan*", "wifi*"},
		CellularInterfaces: []string{"ccmni*", "rmnet*", "pdp*", "wwan*", "cellular*"},
	}
}

// Select classifies the current default interface and maps it to a mode.
//
// A typed entry from NetworkInterfaces wins over name heuristics. This is
// important because NetworkManager's fallback NetworkInterface has a zero
// Type value, and zero is a valid Wi-Fi enum value rather than "unknown".
// When no matching typed entry exists, interface-name patterns are used. An
// unrecognized interface returns ok=false so callers retain the current owner
// instead of guessing and potentially blackholing traffic.
func (p NetworkPolicy) Select(defaultInterface *adapter.NetworkInterface, interfaces []adapter.NetworkInterface) (mode Mode, class NetworkClass, ok bool) {
	if defaultInterface == nil || defaultInterface.Name == "" {
		return ModeNone, NetworkUnknown, false
	}
	if typed, found := matchingInterface(defaultInterface, interfaces); found {
		class = classFromType(typed.Type)
	} else {
		class = p.classFromName(defaultInterface.Name)
	}
	if class == NetworkUnknown {
		return ModeNone, class, false
	}
	switch class {
	case NetworkWiFi:
		return p.WiFiMode, class, true
	case NetworkCellular:
		return p.CellularMode, class, true
	default:
		return p.OtherMode, class, true
	}
}

func matchingInterface(defaultInterface *adapter.NetworkInterface, interfaces []adapter.NetworkInterface) (adapter.NetworkInterface, bool) {
	for _, current := range interfaces {
		if defaultInterface.Index != 0 && current.Index == defaultInterface.Index {
			return current, true
		}
		if current.Name != "" && current.Name == defaultInterface.Name {
			return current, true
		}
	}
	return adapter.NetworkInterface{}, false
}

func classFromType(interfaceType C.InterfaceType) NetworkClass {
	switch interfaceType {
	case C.InterfaceTypeWIFI:
		return NetworkWiFi
	case C.InterfaceTypeCellular:
		return NetworkCellular
	case C.InterfaceTypeEthernet, C.InterfaceTypeOther:
		return NetworkOther
	default:
		return NetworkUnknown
	}
}

func (p NetworkPolicy) classFromName(name string) NetworkClass {
	name = strings.TrimSpace(name)
	if name == "" {
		return NetworkUnknown
	}
	if matchesAny(name, p.WiFiInterfaces) {
		return NetworkWiFi
	}
	if matchesAny(name, p.CellularInterfaces) {
		return NetworkCellular
	}
	return NetworkUnknown
}

func matchesAny(name string, patterns []string) bool {
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		matched, err := path.Match(pattern, name)
		if err == nil && matched {
			return true
		}
	}
	return false
}
