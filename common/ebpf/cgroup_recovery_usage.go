//go:build with_ebpf && (linux || android)

package ebpf

// UDPRecoveryUsage reports how full the UDP recovery table is.
//
// The table is sized once at load time, so the entry count is the only thing
// that changes. Counting entries costs one walk of the map, which is why only
// the maintenance loop and the occupancy report ask for it.
//
// A map that cannot be counted is reported as full: claiming headroom that
// cannot be verified would let the table fill up quietly, which is exactly the
// failure this path exists to prevent.
func (b *CgroupBackend) UDPRecoveryUsage() MapUsage {
	if b == nil {
		return MapUsage{}
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return MapUsage{}
	}
	recoveryMap := b.runtime.maps["cgroup_udp_recovery"]
	if recoveryMap == nil {
		return MapUsage{}
	}
	capacity := recoveryMap.MaxEntries()
	entries, err := countMapKeys(recoveryMap, uint32(len(listenerLookupKey{}.TokenAddr))+4, capacity)
	if err != nil && !isIterationAborted(err) {
		return MapUsage{Entries: capacity, Capacity: capacity}
	}
	return MapUsage{Entries: min(entries, capacity), Capacity: capacity}
}

func isIterationAborted(err error) bool {
	return err != nil && err == errMapKeyIterationAborted
}
