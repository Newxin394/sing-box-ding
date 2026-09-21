package fswatch_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/fswatch"

	"github.com/stretchr/testify/require"
)

func TestFileWatcher(t *testing.T) {
	t.Parallel()
	tempDir, err := os.MkdirTemp("", "sing-box-file-watcher-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	watchPath := filepath.Join(tempDir, "test")
	fileContent := "Hello world!"
	done := make(chan struct{})
	watcher, err := fswatch.NewWatcher(fswatch.Options{
		Path: []string{watchPath},
		Callback: func(path string) {
			newContent, err := os.ReadFile(watchPath)
			require.NoError(t, err)
			require.Equal(t, fileContent, string(newContent))
			close(done)
		},
	})
	require.NoError(t, err)
	defer watcher.Close()
	require.NoError(t, watcher.Start())
	file, err := os.Create(watchPath)
	require.NoError(t, err)
	_, err = file.WriteString(fileContent)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("watch timeout")
	}
	done = make(chan struct{})
	require.NoError(t, os.Remove(watchPath))
	tempPath := filepath.Join(tempDir, "temp")
	require.NoError(t, os.WriteFile(tempPath, []byte(fileContent), 0o644))
	require.NoError(t, os.Rename(tempPath, watchPath))
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("watch timeout")
	}
	done = make(chan struct{})
	require.NoError(t, os.Remove(watchPath))
	require.NoError(t, os.WriteFile(tempPath, []byte(fileContent), 0o644))
	select {
	case <-done:
		t.Fatal("invalid event")
	case <-time.After(1 * time.Second):
	}
}

// TestWatchDirectAtomicReplace covers the exact pattern Android uses for
// /data/system/packages.xml: a temp file is renamed over the watched file.
// The watcher must survive the rename and keep firing callbacks.
func TestWatchDirectAtomicReplace(t *testing.T) {
	t.Parallel()
	tempDir, err := os.MkdirTemp("", "sing-box-file-watcher-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	watchPath := filepath.Join(tempDir, "test")
	file, err := os.Create(watchPath)
	require.NoError(t, err)
	_, err = file.WriteString("")
	require.NoError(t, err)
	require.NoError(t, file.Close())
	fileContent := "Hello world!"
	done := make(chan struct{})
	watcher, err := fswatch.NewWatcher(fswatch.Options{
		Path:   []string{watchPath},
		Direct: true,
		Callback: func(path string) {
			newContent, err := os.ReadFile(watchPath)
			require.NoError(t, err)
			require.Equal(t, fileContent, string(newContent))
			close(done)
		},
	})
	require.NoError(t, err)
	defer watcher.Close()
	require.NoError(t, watcher.Start())
	file, err = os.Create(watchPath)
	require.NoError(t, err)
	_, err = file.WriteString(fileContent)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("watch timeout")
	}
	for i := 0; i < 3; i++ {
		done = make(chan struct{})
		tempPath := filepath.Join(tempDir, "temp")
		require.NoError(t, os.WriteFile(tempPath, []byte(fileContent), 0o644))
		require.NoError(t, os.Rename(tempPath, watchPath))
		select {
		case <-done:
		case <-time.After(1 * time.Second):
			t.Fatalf("watch lost after atomic replace round %d", i+1)
		}
	}
}
