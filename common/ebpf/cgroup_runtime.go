//go:build with_ebpf && (linux || android)

package ebpf

// UDPCleanupModeLRUFallback is the cgroup cleanup mode where the kernel can not
// report socket releases, so userspace has to reclaim recovery state itself.
const UDPCleanupModeLRUFallback = cgroupUDPCleanupLRUFallback

// UDPCleanupModeSocketRelease is the cgroup cleanup mode where the kernel
// release hook reclaims connected UDP state exactly. The recovery table is
// still written and still needs age-based housekeeping in this mode.
const UDPCleanupModeSocketRelease = cgroupUDPCleanupSocketRelease

func (b *CgroupBackend) CgroupPath() string {
	if b == nil {
		return ""
	}
	return b.cgroupPath
}

func (b *CgroupBackend) UDPCleanupMode() string {
	if b == nil {
		return cgroupUDPCleanupDisabled
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return cgroupUDPCleanupModeLocked(b.runtime)
}

func (b *CgroupBackend) UDPTimeMode() string {
	if b == nil {
		return "disabled"
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || !b.runtime.enable_udp {
		return "disabled"
	}
	if b.runtime.coarse_time_supported {
		return "coarse"
	}
	return "precise"
}

func (b *CgroupBackend) UDPStorageMode() string {
	if b == nil {
		return "disabled"
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || !b.runtime.enable_udp {
		return "disabled"
	}
	if b.runtime.socket_storage_supported {
		return "socket_storage"
	}
	return "lru"
}

func cgroupUDPCleanupModeLocked(runtimeState *cgroupRuntime) string {
	if runtimeState == nil || !runtimeState.enable_udp {
		return cgroupUDPCleanupDisabled
	}
	if !runtimeState.socket_release_supported {
		return cgroupUDPCleanupLRUFallback
	}
	if len(runtimeState.programs) <= cgroupProgramSocketRelease ||
		runtimeState.programs[cgroupProgramSocketRelease] == nil {
		return cgroupUDPCleanupInvalid
	}
	return cgroupUDPCleanupSocketRelease
}
