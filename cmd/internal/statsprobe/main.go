//go:build linux || android

// Command statsprobe attributes eBPF runtime cost to individual programs by
// sampling each program's accumulated run time twice and reporting the delta.
// This is what bpftool prog show does; the device has no bpftool.
//
// Usage: statsprobe [seconds]   (default 5)
package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// progInfo is the leading part of struct bpf_prog_info, up to the runtime
// counters. Field order and padding follow the kernel's definition.
type progInfo struct {
	Type                 uint32   // 0
	ID                   uint32   // 4
	Tag                  [8]byte  // 8
	JitedProgLen         uint32   // 16
	XlatedProgLen        uint32   // 20
	JitedProgInsns       uint64   // 24
	XlatedProgInsns      uint64   // 32
	LoadTime             uint64   // 40
	CreatedByUID         uint32   // 48
	NrMapIDs             uint32   // 52
	MapIDs               uint64   // 56
	Name                 [16]byte // 64
	Ifindex              uint32   // 80
	_                    uint32   // 84
	NetnsDev             uint64   // 88
	NetnsIno             uint64   // 96
	NrJitedKsyms         uint32   // 104
	NrJitedFuncLens      uint32   // 108
	JitedKsyms           uint64   // 112
	JitedFuncLens        uint64   // 120
	BtfID                uint32   // 128
	FuncInfoRecSize      uint32   // 132
	FuncInfo             uint64   // 136
	NrFuncInfo           uint32   // 144
	NrLineInfo           uint32   // 148
	LineInfo             uint64   // 152
	JitedLineInfo        uint64   // 160
	NrJitedLineInfo      uint32   // 168
	LineInfoRecSize      uint32   // 172
	JitedLineInfoRecSize uint32   // 176
	NrProgTags           uint32   // 180
	ProgTags             uint64   // 184
	RunTimeNs            uint64   // 192
	RunCnt               uint64   // 200
	RecursionMisses      uint64   // 208
	VerifiedInsns        uint32   // 216
	AttachBtfObjID       uint32   // 220
	AttachBtfID          uint32   // 224
	_                    uint32   // 228
}

type progStat struct {
	id      uint32
	name    string
	typ     uint32
	runTime uint64
	runCnt  uint64
}

// progName returns the NUL-terminated name.
func (info *progInfo) progName() string {
	name := info.Name[:]
	if index := strings.IndexByte(string(name), 0); index >= 0 {
		name = name[:index]
	}
	return string(name)
}

func nextID(start uint32) (uint32, error) {
	attr := struct {
		startID uint32
		nextID  uint32
	}{startID: start}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_GET_NEXT_ID, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return 0, errno
	}
	return attr.nextID, nil
}

func fdByID(id uint32) (int, error) {
	attr := struct {
		progID    uint32
		nextID    uint32
		openFlags uint32
	}{progID: id}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_GET_FD_BY_ID, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

func infoByFD(fd int) (progInfo, error) {
	var info progInfo
	attr := struct {
		bpfFD   uint32
		infoLen uint32
		info    uint64
	}{
		bpfFD:   uint32(fd),
		infoLen: uint32(unsafe.Sizeof(info)),
		info:    uint64(uintptr(unsafe.Pointer(&info))),
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET_INFO_BY_FD, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return progInfo{}, errno
	}
	return info, nil
}

func snapshot() (map[uint32]progStat, error) {
	stats := make(map[uint32]progStat)
	id := uint32(0)
	for {
		next, err := nextID(id)
		if err != nil {
			if err == unix.ENOENT {
				break
			}
			return nil, err
		}
		id = next
		fd, fdErr := fdByID(id)
		if fdErr != nil {
			// The program went away between the two calls.
			continue
		}
		info, infoErr := infoByFD(fd)
		_ = unix.Close(fd)
		if infoErr != nil {
			continue
		}
		stats[id] = progStat{
			id:      id,
			name:    info.progName(),
			typ:     info.Type,
			runTime: info.RunTimeNs,
			runCnt:  info.RunCnt,
		}
	}
	return stats, nil
}

func main() {
	interval := 5
	if len(os.Args) > 1 {
		if parsed, err := strconv.Atoi(os.Args[1]); err == nil && parsed > 0 {
			interval = parsed
		}
	}
	before, err := snapshot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "first snapshot: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("sampled %d programs, waiting %ds...\n", len(before), interval)
	// time.Sleep keeps this portable: Timespec.Sec is int32 on 32-bit targets
	// and int64 on 64-bit ones, so spelling the field width by hand does not
	// build on every platform the lint matrix covers.
	time.Sleep(time.Duration(interval) * time.Second)
	after, err := snapshot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "second snapshot: %v\n", err)
		os.Exit(1)
	}

	type row struct {
		name       string
		id         uint32
		runs       uint64
		runTimeNs  uint64
		avgPerCall uint64
	}
	rows := make([]row, 0, len(after))
	var totalNs uint64
	for id, current := range after {
		previous, existed := before[id]
		if !existed {
			continue
		}
		runs := current.runCnt - previous.runCnt
		runTime := current.runTime - previous.runTime
		if runs == 0 && runTime == 0 {
			continue
		}
		row := row{
			name:      current.name,
			id:        id,
			runs:      runs,
			runTimeNs: runTime,
		}
		if runs > 0 {
			row.avgPerCall = runTime / runs
		}
		rows = append(rows, row)
		totalNs += runTime
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].runTimeNs > rows[j].runTimeNs })

	fmt.Printf("\n%-20s %6s %12s %14s %10s %8s\n", "NAME", "ID", "RUNS", "CPU_MS", "AVG_NS", "SHARE")
	for _, row := range rows {
		share := float64(0)
		if totalNs > 0 {
			share = float64(row.runTimeNs) * 100 / float64(totalNs)
		}
		fmt.Printf("%-20s %6d %12d %14.3f %10d %7.1f%%\n",
			row.name, row.id, row.runs, float64(row.runTimeNs)/1e6, row.avgPerCall, share)
	}
	fmt.Printf("\ntotal eBPF run time in %ds: %.3f ms\n", interval, float64(totalNs)/1e6)
}
