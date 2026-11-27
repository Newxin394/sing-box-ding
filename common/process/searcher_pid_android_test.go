//go:build android

package process

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestFindProcessInfoByPIDFiltersAndroidAppProcess(t *testing.T) {
	pidText := os.Getenv("SING_BOX_TEST_ANDROID_APP_PROCESS_PID")
	if pidText == "" {
		t.Skip("set SING_BOX_TEST_ANDROID_APP_PROCESS_PID to a readable Android zygote child")
	}
	pid, err := strconv.ParseUint(pidText, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	procDir := filepath.Join("/proc", strconv.FormatUint(pid, 10))
	info, err := os.Stat(procDir)
	if err != nil {
		t.Fatal(err)
	}
	uid := info.Sys().(*syscall.Stat_t).Uid
	path, err := os.Readlink(filepath.Join(procDir, "exe"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(path, "/system/bin/app_process") {
		t.Fatalf("fixture executable = %q, want Android app_process", path)
	}
	owner, err := FindProcessInfoByPID(uint32(pid), uid, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(owner.ProcessPaths) != 0 {
		t.Fatalf("Android app_process should not identify the application: %q", owner.ProcessPaths)
	}
	if owner.ProcessID != uint32(pid) || owner.UserId != int32(uid) {
		t.Fatalf("unexpected process identity: %+v", owner)
	}
}
