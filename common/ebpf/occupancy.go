//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"os"
	"sort"
	"strings"

	CiliumEBPF "github.com/cilium/ebpf"
)

// Map pressure levels. Ratios are deliberately coarse: this answers "is a
// table about to reject inserts", not "how many entries are there exactly".
const (
	MapPressureHealthy       = "healthy"
	MapPressureWarning       = "warning"
	MapPressureDegraded      = "degraded"
	MapPressureNotApplicable = "not_applicable"
	MapPressureUnknown       = "unknown"
	MapPressureFailed        = "recovery_failed"
)

// mapPressureWarningRatio and mapPressureDegradedRatio mirror the thresholds
// the kernel-side tables were sized against: 85% is where LRU insertion starts
// evicting useful state, 95% is where new flows are effectively rejected.
const (
	mapPressureWarningRatio  = 0.85
	mapPressureDegradedRatio = 0.95
)

// MapOccupancy describes one of this backend's own maps at the moment an
// explicit diagnostic request asked for it.
type MapOccupancy struct {
	ID         CiliumEBPF.MapID `json:"id"`
	Name       string           `json:"name"`
	Type       string           `json:"type"`
	MaxEntries uint32           `json:"max_entries"`
	KeySize    uint32           `json:"key_size"`
	ValueSize  uint32           `json:"value_size"`
	Flags      uint32           `json:"flags"`
	Entries    uint32           `json:"entries"`
	Pressure   string           `json:"pressure"`
	Supported  bool             `json:"supported"`
	Error      string           `json:"error,omitempty"`
}

// MapOccupancyReport is the full answer to one occupancy request.
type MapOccupancyReport struct {
	Status string         `json:"status"`
	Maps   []MapOccupancy `json:"maps"`
	Error  string         `json:"error,omitempty"`
}

// MapPrefix filters enumeration to this backend's own objects. Every map this
// package creates is named with it.
const MapPrefix = "sb_"

// InspectMapOccupancy enumerates the maps this backend owns and reports their
// fill ratio. It is intentionally an on-demand operation: key iteration walks
// real entries, so callers must never invoke it from a watchdog, retry loop or
// data-plane path.
func InspectMapOccupancy() MapOccupancyReport {
	report := MapOccupancyReport{Status: "pass", Maps: make([]MapOccupancy, 0)}
	var id CiliumEBPF.MapID
	for {
		next, err := CiliumEBPF.MapGetNextID(id)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			report.Error = err.Error()
			report.Status = MapPressureUnknown
			break
		}
		id = next
		mapInstance, err := CiliumEBPF.NewMapFromID(id)
		if err != nil {
			continue
		}
		info, infoErr := mapInstance.Info()
		if infoErr != nil || info == nil || !strings.HasPrefix(info.Name, MapPrefix) {
			_ = mapInstance.Close()
			continue
		}
		item := MapOccupancy{
			ID:         id,
			Name:       info.Name,
			Type:       info.Type.String(),
			MaxEntries: info.MaxEntries,
			KeySize:    info.KeySize,
			ValueSize:  info.ValueSize,
			Flags:      info.Flags,
		}
		if !mapOccupancySupported(info.Type) {
			item.Error = "map type does not support safe key iteration"
			item.Pressure = MapPressureNotApplicable
			report.Maps = append(report.Maps, item)
			_ = mapInstance.Close()
			continue
		}
		item.Supported = true
		item.Entries, err = countMapKeys(mapInstance, info.KeySize, info.MaxEntries)
		if err != nil {
			item.Error = err.Error()
		}
		item.Pressure = mapPressure(item.Entries, item.MaxEntries, item.Error != "")
		report.Maps = append(report.Maps, item)
		_ = mapInstance.Close()
	}
	sort.Slice(report.Maps, func(a, b int) bool { return report.Maps[a].Name < report.Maps[b].Name })
	if report.Error == "" {
		report.Status = mapOccupancyStatus(report.Maps)
	}
	return report
}

// MapPressureLevel classifies a fill ratio with the same thresholds the
// occupancy report uses, so callers that already have entries/capacity (for
// example userspace flow accounting) report a consistent level.
func MapPressureLevel(entries, capacity uint32) string {
	return mapPressure(entries, capacity, false)
}

// CgroupUDPCleanupSocketRelease is the cgroup cleanup mode where the kernel
// sock_release hook owns map cleanup, so userspace must not also delete.
const CgroupUDPCleanupSocketRelease = cgroupUDPCleanupSocketRelease

// MapPressureInt64 is MapPressureLevel for counters read as int64 (pool
// snapshots, retained handles), clamped so a negative or oversized counter
// cannot wrap into a bogus ratio.
func MapPressureInt64(entries, capacity int64) string {
	if capacity <= 0 {
		return MapPressureUnknown
	}
	if entries <= 0 {
		return mapPressure(0, uint32(min(capacity, int64(^uint32(0)))), false)
	}
	return mapPressure(
		uint32(min(entries, int64(^uint32(0)))),
		uint32(min(capacity, int64(^uint32(0)))),
		false,
	)
}

// mapOccupancySupported excludes map types whose key layout makes generic
// byte iteration unsafe or meaningless (arrays are positional, sockmaps and
// prog/queue maps are not key/value tables in the same sense).
func mapOccupancySupported(mapType CiliumEBPF.MapType) bool {
	switch mapType {
	case CiliumEBPF.Hash,
		CiliumEBPF.LRUHash,
		CiliumEBPF.LRUCPUHash,
		CiliumEBPF.LPMTrie,
		CiliumEBPF.PerCPUHash:
		return true
	default:
		return false
	}
}

func mapOccupancyStatus(maps []MapOccupancy) string {
	status := "pass"
	for _, item := range maps {
		switch item.Pressure {
		case MapPressureDegraded:
			return MapPressureDegraded
		case MapPressureWarning:
			status = MapPressureWarning
		}
	}
	return status
}

func mapPressure(entries, maxEntries uint32, failed bool) string {
	if failed {
		return MapPressureFailed
	}
	if maxEntries == 0 {
		return MapPressureUnknown
	}
	ratio := float64(entries) / float64(maxEntries)
	switch {
	case ratio >= mapPressureDegradedRatio:
		return MapPressureDegraded
	case ratio >= mapPressureWarningRatio:
		return MapPressureWarning
	default:
		return MapPressureHealthy
	}
}

var errMapKeyIterationAborted = errors.New("map key iteration aborted")

func countMapKeys(mapInstance *CiliumEBPF.Map, keySize uint32, maxEntries uint32) (uint32, error) {
	if mapInstance == nil || keySize == 0 {
		return 0, errBackendClosed
	}
	key := make([]byte, keySize)
	next := make([]byte, keySize)
	err := mapInstance.NextKey(nil, &next)
	var entries uint32
	for err == nil {
		if maxEntries != 0 && entries >= maxEntries {
			return entries, errMapKeyIterationAborted
		}
		entries++
		copy(key, next)
		err = mapInstance.NextKey(key, &next)
	}
	if errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
		return entries, nil
	}
	return entries, err
}
