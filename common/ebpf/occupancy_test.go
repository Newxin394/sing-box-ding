//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
)

func testMap(t *testing.T, mapType CiliumEBPF.MapType, name string, maxEntries uint32) *CiliumEBPF.Map {
	t.Helper()
	mapInstance, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Name:       name,
		Type:       mapType,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: maxEntries,
	})
	if err != nil {
		t.Skipf("kernel refuses test map creation: %v", err)
	}
	t.Cleanup(func() { _ = mapInstance.Close() })
	return mapInstance
}

func TestCountMapKeysCountsEntries(t *testing.T) {
	mapInstance := testMap(t, CiliumEBPF.Hash, "sb_occ_count", 16)
	value := uint32(1)
	for key := uint32(1); key <= 5; key++ {
		if err := mapInstance.Update(&key, &value, CiliumEBPF.UpdateAny); err != nil {
			t.Fatalf("update %d: %v", key, err)
		}
	}
	entries, err := countMapKeys(mapInstance, 4, 16)
	if err != nil {
		t.Fatalf("countMapKeys: %v", err)
	}
	if entries != 5 {
		t.Fatalf("entries = %d, want 5", entries)
	}
}

func TestCountMapKeysAbortsAtCapacityBudget(t *testing.T) {
	mapInstance := testMap(t, CiliumEBPF.Hash, "sb_occ_budget", 16)
	value := uint32(1)
	for key := uint32(1); key <= 8; key++ {
		if err := mapInstance.Update(&key, &value, CiliumEBPF.UpdateAny); err != nil {
			t.Fatalf("update %d: %v", key, err)
		}
	}
	_, err := countMapKeys(mapInstance, 4, 4)
	if !errors.Is(err, errMapKeyIterationAborted) {
		t.Fatalf("countMapKeys error = %v, want errMapKeyIterationAborted", err)
	}
}

func TestMapPressureThresholds(t *testing.T) {
	cases := []struct {
		entries uint32
		maximum uint32
		want    string
	}{
		{0, 100, MapPressureHealthy},
		{84, 100, MapPressureHealthy},
		{85, 100, MapPressureWarning},
		{94, 100, MapPressureWarning},
		{95, 100, MapPressureDegraded},
		{100, 100, MapPressureDegraded},
		{10, 0, MapPressureUnknown},
	}
	for _, testCase := range cases {
		got := mapPressure(testCase.entries, testCase.maximum, false)
		if got != testCase.want {
			t.Fatalf("mapPressure(%d,%d) = %q, want %q", testCase.entries, testCase.maximum, got, testCase.want)
		}
	}
	if got := mapPressure(0, 100, true); got != MapPressureFailed {
		t.Fatalf("failed iteration pressure = %q, want %q", got, MapPressureFailed)
	}
}

func TestMapPressureByTypeLPMTrieIsIterable(t *testing.T) {
	cases := []struct {
		mapType CiliumEBPF.MapType
		want    bool
	}{
		{CiliumEBPF.LRUHash, true},
		{CiliumEBPF.Hash, true},
		{CiliumEBPF.LPMTrie, true},
		{CiliumEBPF.Array, false},
		{CiliumEBPF.PerCPUArray, false},
		{CiliumEBPF.SockMap, false},
		{CiliumEBPF.ProgramArray, false},
	}
	for _, testCase := range cases {
		if got := mapOccupancySupported(testCase.mapType); got != testCase.want {
			t.Fatalf("mapOccupancySupported(%v) = %v, want %v", testCase.mapType, got, testCase.want)
		}
	}
}

func TestMapOccupancyStatusEscalates(t *testing.T) {
	if got := mapOccupancyStatus([]MapOccupancy{{Pressure: MapPressureHealthy}}); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
	if got := mapOccupancyStatus([]MapOccupancy{{Pressure: MapPressureHealthy}, {Pressure: MapPressureWarning}}); got != MapPressureWarning {
		t.Fatalf("status = %q, want warning", got)
	}
	if got := mapOccupancyStatus([]MapOccupancy{{Pressure: MapPressureWarning}, {Pressure: MapPressureDegraded}}); got != MapPressureDegraded {
		t.Fatalf("status = %q, want degraded", got)
	}
}
