package dbustest

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Start runs an isolated bus. It never connects to the host system bus.
func Start(t *testing.T) {
	t.Helper()
	binary, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon is not installed")
	}
	directory, err := os.MkdirTemp("", "sbd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	command := exec.Command(binary, "--session", "--nofork", "--nopidfile", "--address=unix:path="+filepath.Join(directory, "bus"), "--print-address=1")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() { _ = command.Process.Kill(); <-done })
	address := make(chan string, 1)
	go func() {
		reader := bufio.NewReader(stdout)
		line, _ := reader.ReadString('\n')
		address <- strings.TrimSpace(line)
		_, _ = io.Copy(io.Discard, reader)
	}()
	select {
	case value := <-address:
		if value == "" {
			t.Fatal("private D-Bus daemon did not return an address")
		}
		t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", value)
	case <-time.After(5 * time.Second):
		t.Fatal("private D-Bus startup timed out")
	}
}
