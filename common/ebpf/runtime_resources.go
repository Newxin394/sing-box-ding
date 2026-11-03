package ebpf

import (
	"errors"
	"os"
	"slices"
	"strings"

	CiliumEBPF "github.com/cilium/ebpf"
)

// RuntimeResources is one owner's kernel objects: the programs it loaded and
// the maps it created. Owners hand these out while their own lifecycle is
// stable, so the caller can enumerate IDs afterwards without holding a
// lifecycle lock over the (slow) kernel walk.
//
// Only IDs cross this boundary, never handles. Enumerating by ID is what makes
// the report tolerant of an object vanishing between the snapshot and the
// walk: a vanished ID is skipped rather than turning into an error, and the
// same code covers a PID that has to read back objects it can no longer reach
// through a handle.
type RuntimeResources struct {
	Programs []CiliumEBPF.Program
	Maps     []CiliumEBPF.Map
}

// RuntimeOwner is the interface a backend implements to hand out its kernel
// objects for diagnostics.
//
// It is deliberately not part of every backend's public surface: the report
// only needs it when someone asks for a deep diagnostic run, and a backend
// that has no objects to report simply does not implement it. Callers type
// assert.
type RuntimeOwner interface {
	RuntimeResources() RuntimeResources
}

// RuntimeState is one enumeration of the objects in RuntimeResources, already
// filtered to this project's own programs and maps and classified.
type RuntimeState struct {
	Programs      []RuntimeProgram
	ProgramsError error
	MapOccupancy  MapOccupancyReport
}

// RuntimeProgram is one loaded BPF program as the kernel reports it.
type RuntimeProgram struct {
	ID       CiliumEBPF.ProgramID
	Name     string
	Type     CiliumEBPF.ProgramType
	MapCount int
	MapIDs   []CiliumEBPF.MapID
}

// runtimeProgramPrefixes are the names this project's loaders give their
// programs (see the native sources under native/ and the *_bpfel.go wrappers).
// A prefix test is how a diagnostic run tells our programs apart from every
// other eBPF program on the host, which matters because the ID space is
// global.
var runtimeProgramPrefixes = []string{"sb_tc_", "sb_ebpf_", "sb_share_", "sb_self_", "sb_proc_"}

// IsProjectProgramName reports whether name belongs to this project.
func IsProjectProgramName(name string) bool {
	for _, prefix := range runtimeProgramPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// InspectRuntimeResources enumerates the programs and maps the given owners
// hold handles to.
//
// Owners are intersected rather than trusted: only objects whose IDs appear in
// some owner's handle list are reported, so a long-running instance sharing a
// host with another one does not claim that other instance's objects. Duplicate
// owners are de-duplicated by ID for the same reason a merged report would
// otherwise count each object once per inbound.
func InspectRuntimeResources(owners ...RuntimeOwner) RuntimeState {
	var state RuntimeState
	programIDs := make(map[CiliumEBPF.ProgramID]struct{})
	mapIDs := make(map[CiliumEBPF.MapID]struct{})
	addProgram := func(program *CiliumEBPF.Program) {
		if program == nil {
			return
		}
		info, err := program.Info()
		if err != nil || info == nil || !IsProjectProgramName(info.Name) {
			return
		}
		id, ok := info.ID()
		if !ok {
			return
		}
		programIDs[id] = struct{}{}
	}
	addMap := func(mapInstance *CiliumEBPF.Map) {
		if mapInstance == nil {
			return
		}
		info, err := mapInstance.Info()
		if err != nil || info == nil || !strings.HasPrefix(info.Name, MapPrefix) {
			return
		}
		id, ok := info.ID()
		if !ok {
			return
		}
		mapIDs[id] = struct{}{}
	}
	for _, owner := range owners {
		if owner == nil {
			continue
		}
		resources := owner.RuntimeResources()
		for _, program := range resources.Programs {
			addProgram(&program)
		}
		for _, mapInstance := range resources.Maps {
			addMap(&mapInstance)
		}
	}
	state.Programs, state.ProgramsError = inspectRuntimePrograms(programIDs)
	state.MapOccupancy = InspectOwnedMapOccupancy(mapIDs)
	return state
}

// inspectRuntimePrograms reads back every ID in owned and keeps the ones that
// still exist. A vanished ID is skipped: the point of reporting by ID is to
// survive the window where a close is in flight.
func inspectRuntimePrograms(owned map[CiliumEBPF.ProgramID]struct{}) ([]RuntimeProgram, error) {
	if len(owned) == 0 {
		return nil, nil
	}
	ids := make([]CiliumEBPF.ProgramID, 0, len(owned))
	for id := range owned {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	programs := make([]RuntimeProgram, 0, len(ids))
	for _, id := range ids {
		program, err := CiliumEBPF.NewProgramFromID(id)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return programs, err
		}
		info, infoErr := program.Info()
		program.Close()
		if infoErr != nil {
			if errors.Is(infoErr, os.ErrNotExist) {
				continue
			}
			return programs, infoErr
		}
		id, ok := info.ID()
		if info == nil || !ok {
			continue
		}
		mapIDs, _ := info.MapIDs()
		programs = append(programs, RuntimeProgram{
			ID:       id,
			Name:     info.Name,
			Type:     info.Type,
			MapCount: len(mapIDs),
			MapIDs:   mapIDs,
		})
	}
	return programs, nil
}
