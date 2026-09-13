//go:build linux

package process

import (
	"os"
	"testing"
)

func TestFindProcessInfoByPID(t *testing.T) {
	processInfo, err := FindProcessInfoByPID(uint32(os.Getpid()), uint32(os.Getuid()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if processInfo.ProcessID != uint32(os.Getpid()) || processInfo.UserId != int32(os.Getuid()) {
		t.Fatalf("unexpected process identity: %+v", processInfo)
	}
	if len(processInfo.ProcessPaths) == 0 || processInfo.ProcessPaths[0] == "" {
		t.Fatal("missing process path")
	}
}

// TestProcessPathSnapshotIsThrottled verifies that an inode absent from a fresh
// snapshot does not cause that snapshot to be rebuilt. Rebuilding on every miss
// is what turned bursty short-lived sockets such as DNS queries into a
// continuous procfs walk, because every new socket carries a new inode.
func TestProcessPathSnapshotIsThrottled(t *testing.T) {
	searcher, err := NewSearcher(Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer searcher.Close()
	linuxSearcher, isLinux := searcher.(*linuxSearcher)
	if !isLinux {
		t.Fatalf("unexpected searcher type: %T", searcher)
	}
	selfUID := uint32(os.Getuid())
	// No socket owns this inode, so both lookups below miss the snapshot and
	// would previously have forced a rebuild each time.
	const absentInode = ^uint32(0)
	if _, err = linuxSearcher.findProcessPaths(absentInode, selfUID); err == nil {
		t.Fatal("expected an absent inode to be unresolved")
	}
	first, loaded := linuxSearcher.processPathCache.Get(selfUID)
	if !loaded {
		t.Fatal("snapshot was not cached after the first lookup")
	}
	if first.builtAt.IsZero() {
		t.Fatal("snapshot carries no build timestamp")
	}
	if _, err = linuxSearcher.findProcessPaths(absentInode, selfUID); err == nil {
		t.Fatal("expected an absent inode to be unresolved")
	}
	second, loaded := linuxSearcher.processPathCache.Get(selfUID)
	if !loaded {
		t.Fatal("snapshot disappeared")
	}
	if second != first {
		t.Fatal("snapshot was rebuilt within the rescan interval")
	}
}
