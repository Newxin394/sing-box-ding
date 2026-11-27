//go:build linux

package process

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestFindProcessInfoByPIDWithDeletedExecutable(t *testing.T) {
	const childEnv = "SING_BOX_TEST_DELETED_EXECUTABLE_CHILD"
	if os.Getenv(childEnv) == "1" {
		fmt.Fprintln(os.Stdout, "ready")
		_, _ = io.Copy(io.Discard, os.Stdin)
		return
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(t.TempDir(), "process-fixture")
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	copyFile, err := os.OpenFile(fixture, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(copyFile, source)
	closeErr := copyFile.Close()
	if copyErr != nil {
		t.Fatal(copyErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, fixture, "-test.run=^TestFindProcessInfoByPIDWithDeletedExecutable$")
	command.Env = append(os.Environ(), childEnv+"=1")
	command.Stderr = os.Stderr
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = input.Close()
		_ = command.Wait()
	}()
	ready, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || ready != "ready\n" {
		t.Fatalf("fixture failed to start: %q, %v", ready, err)
	}

	pid := command.Process.Pid
	procLink := filepath.Join("/proc", strconv.Itoa(pid), "exe")
	want, err := os.Readlink(procLink)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fixture); err != nil {
		t.Fatal(err)
	}
	deletedPath, err := os.Readlink(procLink)
	if err != nil {
		t.Fatal(err)
	}
	if deletedPath == want {
		t.Skipf("procfs wrapper omitted the deleted executable marker: %q", deletedPath)
	}
	if deletedPath != want+" (deleted)" {
		t.Fatalf("fixture should expose a deleted executable: before=%q, after=%q", want, deletedPath)
	}
	owner, err := FindProcessInfoByPID(uint32(pid), uint32(os.Getuid()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(owner.ProcessPaths) != 1 || owner.ProcessPaths[0] != want {
		t.Fatalf("process paths = %q, want [%q]", owner.ProcessPaths, want)
	}
	if owner.ProcessID != uint32(pid) || owner.UserId != int32(os.Getuid()) {
		t.Fatalf("unexpected process identity: %+v", owner)
	}
}
