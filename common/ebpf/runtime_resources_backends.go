package ebpf

import (
	"slices"

	CiliumEBPF "github.com/cilium/ebpf"
)

// loadedObjectSet is what every backend's runtime type has in common: the maps
// and programs it loaded from one object file. The three runtime types differ
// in the file descriptors and attachments they also keep, none of which a
// diagnostics report needs.
type loadedObjectSet interface {
	loadedMaps() map[string]*CiliumEBPF.Map
	loadedPrograms() []*CiliumEBPF.Program
}

func (r *tcRuntime) loadedMaps() map[string]*CiliumEBPF.Map            { return r.maps }
func (r *tcRuntime) loadedPrograms() []*CiliumEBPF.Program             { return r.programs }
func (r *sharedNetworkRuntime) loadedMaps() map[string]*CiliumEBPF.Map { return r.maps }
func (r *sharedNetworkRuntime) loadedPrograms() []*CiliumEBPF.Program  { return r.programs }
func (r *cgroupRuntime) loadedMaps() map[string]*CiliumEBPF.Map        { return r.maps }
func (r *cgroupRuntime) loadedPrograms() []*CiliumEBPF.Program         { return r.programs }

// runtimeResourcesOf turns one of this package's loaded object sets into the
// handle snapshot a deep diagnostic run enumerates.
//
// The maps are walked in name order so the same instance reports the same
// order twice; the program order is whatever the loader produced, which is
// already stable per object.
func runtimeResourcesOf(runtime loadedObjectSet) RuntimeResources {
	if runtime == nil {
		return RuntimeResources{}
	}
	loadedMaps := runtime.loadedMaps()
	names := make([]string, 0, len(loadedMaps))
	for name := range loadedMaps {
		names = append(names, name)
	}
	slices.Sort(names)
	maps := make([]CiliumEBPF.Map, 0, len(names))
	for _, name := range names {
		if mapInstance := loadedMaps[name]; mapInstance != nil {
			maps = append(maps, *mapInstance)
		}
	}
	loadedPrograms := runtime.loadedPrograms()
	programs := make([]CiliumEBPF.Program, 0, len(loadedPrograms))
	for _, program := range loadedPrograms {
		if program != nil {
			programs = append(programs, *program)
		}
	}
	return RuntimeResources{
		Programs: programs,
		Maps:     maps,
	}
}

// runtimeResourcesLocked is runtimeResourcesOf for callers that already hold
// the backend's access lock. The two are separate because a backend must not
// take its own non-reentrant lock to answer Diagnostics.
func (b *TCBackend) runtimeResourcesLocked() RuntimeResources {
	if b == nil {
		return RuntimeResources{}
	}
	return runtimeResourcesOf(b.runtime)
}

// runtimeResourcesLocked is the shared backend's own-access variant.
func (b *SharedNetworkBackend) runtimeResourcesLocked() RuntimeResources {
	if b == nil {
		return RuntimeResources{}
	}
	return runtimeResourcesOf(b.runtime)
}

// RuntimeResources reports the shared packet_rewrite backend's programs and maps.
func (b *SharedNetworkBackend) RuntimeResources() RuntimeResources {
	if b == nil {
		return RuntimeResources{}
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtimeResourcesLocked()
}

// runtimeResourcesLocked is the cgroup backend's own-access variant.
func (b *CgroupBackend) runtimeResourcesLocked() RuntimeResources {
	if b == nil {
		return RuntimeResources{}
	}
	return runtimeResourcesOf(b.runtime)
}

// RuntimeResources reports the cgroup backend's programs and maps.
func (b *CgroupBackend) RuntimeResources() RuntimeResources {
	if b == nil {
		return RuntimeResources{}
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtimeResourcesLocked()
}

// runtimeResourcesLocked is the fakeip_icmp backend's own-access variant.
func (b *FakeIPICMPBackend) runtimeResourcesLocked() RuntimeResources {
	if b == nil {
		return RuntimeResources{}
	}
	return runtimeResourcesOf(b.runtime)
}

// RuntimeResources reports the fakeip_icmp backend's programs and maps.
//
// It is separate from TCBackend's because the same native object is loaded
// twice in some configurations (local and shared filters each need their own
// reply program); reporting them in one place would hide the second copy.
func (b *FakeIPICMPBackend) RuntimeResources() RuntimeResources {
	if b == nil {
		return RuntimeResources{}
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtimeResourcesLocked()
}

// RuntimeResources reports the self-bypass table's map and, when the cgroup
// variant is in use, its programs.
//
// SelfBypass has no tcRuntime: it keeps one socket map and the programs it
// attached, so the handles are gathered directly.
func (b *SelfBypass) RuntimeResources() RuntimeResources {
	if b == nil {
		return RuntimeResources{}
	}
	b.access.RLock()
	defer b.access.RUnlock()
	resources := RuntimeResources{}
	if b.sockets != nil {
		resources.Maps = []CiliumEBPF.Map{*b.sockets}
	}
	for _, program := range b.programs {
		if program != nil {
			resources.Programs = append(resources.Programs, *program)
		}
	}
	return resources
}

// RuntimeResources reports the process tracker's three maps and its attached
// programs.
func (t *ProcessTracker) RuntimeResources() RuntimeResources {
	if t == nil {
		return RuntimeResources{}
	}
	resources := RuntimeResources{}
	for _, mapInstance := range []*CiliumEBPF.Map{t.owners, t.policyUID, t.metadata} {
		if mapInstance != nil {
			resources.Maps = append(resources.Maps, *mapInstance)
		}
	}
	for _, program := range t.programs {
		if program != nil {
			resources.Programs = append(resources.Programs, *program)
		}
	}
	return resources
}
