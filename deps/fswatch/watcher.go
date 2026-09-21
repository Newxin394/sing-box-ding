package fswatch

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	"github.com/fsnotify/fsnotify"
)

const DefaultWaitTimeout = 100 * time.Millisecond

// readdMaxAttempts bounds the retry loop when a watched path is atomically
// replaced: the new file may not be visible for a few hundred milliseconds.
const readdMaxAttempts = 10

// Watcher is a simple fsnotify wrapper to watch updates correctly.
type Watcher struct {
	watchDirect bool
	watchTarget []string
	watchPath   []string
	callback    func(path string)
	waitTimeout time.Duration
	logger      logger.Logger
	watcher     *fsnotify.Watcher

	stateAccess sync.Mutex
	timerMap    map[string]pendingCallback
	readdMap    map[string]struct{}
	closed      bool
}

type pendingCallback struct {
	generation uint64
	timer      *time.Timer
}

type Options struct {
	// Path is the list of files or directories to watch
	// It is the caller's responsibility to ensure that paths are absolute.
	Path []string

	// Direct is the flag to watch the file directly if file will never be removed
	Direct bool

	// Callback is the function to call when a file is updated
	Callback func(path string)

	// WaitTimeout is the time to wait write events before calling the callback
	// DefaultWaitTimeout is used by default
	WaitTimeout time.Duration

	// Logger is the logger to log errors
	// optional
	Logger logger.Logger
}

func NewWatcher(options Options) (*Watcher, error) {
	if len(options.Path) == 0 || options.Callback == nil {
		return nil, os.ErrInvalid
	}
	waitTimeout := options.WaitTimeout
	if waitTimeout == 0 {
		waitTimeout = DefaultWaitTimeout
	}
	var watchTarget []string
	if options.Direct {
		watchTarget = options.Path
	} else {
		watchTarget = common.Uniq(common.Map(options.Path, filepath.Dir))
		// TODO: update sing to use common.Remove when it's stable
		watchTarget = common.Filter(watchTarget, func(it string) bool {
			return !common.Any(watchTarget, func(path string) bool {
				return len(path) > len(it) && strings.HasPrefix(path, it)
			})
		})
	}
	return &Watcher{
		watchDirect: options.Direct,
		watchTarget: watchTarget,
		watchPath:   options.Path,
		callback:    options.Callback,
		waitTimeout: waitTimeout,
		logger:      options.Logger,
		timerMap:    make(map[string]pendingCallback),
		readdMap:    make(map[string]struct{}),
	}, nil
}

func (w *Watcher) Start() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return E.Cause(err, "fswatch: create fsnotify watcher")
	}
	for _, target := range w.watchTarget {
		err = watcher.Add(target)
		if err != nil {
			return E.Cause(err, "fswatch: watch ", target)
		}
	}
	w.watcher = watcher
	go w.loopUpdate()
	return nil
}

func (w *Watcher) Close() error {
	w.stateAccess.Lock()
	if w.closed {
		watcher := w.watcher
		w.stateAccess.Unlock()
		return common.Close(common.PtrOrNil(watcher))
	}
	w.closed = true
	timers := make([]*time.Timer, 0, len(w.timerMap))
	for path, pending := range w.timerMap {
		timers = append(timers, pending.timer)
		delete(w.timerMap, path)
	}
	watcher := w.watcher
	w.stateAccess.Unlock()

	for _, timer := range timers {
		timer.Stop()
	}
	return common.Close(common.PtrOrNil(watcher))
}

func (w *Watcher) loopUpdate() {
	for {
		select {
		case event, loaded := <-w.watcher.Events:
			if !loaded {
				return
			}
			if common.Contains(w.watchTarget, event.Name) && (event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove)) {
				// A watched path was renamed away or removed. On Linux this also
				// drops the inotify watch, so a later atomic replace would go
				// unnoticed. Re-add the path (with retry) to keep watching it.
				if w.logger != nil {
					w.logger.Warn("fswatch: watcher removed, re-adding: ", event.Name)
				}
				w.readd(event.Name)
			} else if common.Contains(w.watchPath, event.Name) && (event.Has(fsnotify.Create) || event.Has(fsnotify.Write)) {
				w.scheduleCallback(event.Name)
			}
		case err, loaded := <-w.watcher.Errors:
			if !loaded {
				return
			}
			if w.logger != nil {
				w.logger.Error("fswatch: ", err)
			}
		}
	}
}

// readd re-registers a lost watch in the background. Multiple removals of the
// same path collapse into a single retry loop; the loop tolerates the gap
// between an atomic rename and the new file becoming visible.
func (w *Watcher) readd(path string) {
	w.stateAccess.Lock()
	if w.closed {
		w.stateAccess.Unlock()
		return
	}
	if _, exists := w.readdMap[path]; exists {
		w.stateAccess.Unlock()
		return
	}
	w.readdMap[path] = struct{}{}
	w.stateAccess.Unlock()

	go func() {
		defer func() {
			w.stateAccess.Lock()
			delete(w.readdMap, path)
			w.stateAccess.Unlock()
		}()
		for i := 0; i < readdMaxAttempts; i++ {
			w.stateAccess.Lock()
			closed := w.closed
			watcher := w.watcher
			w.stateAccess.Unlock()
			if closed || watcher == nil {
				return
			}
			if err := watcher.Add(path); err == nil {
				if w.logger != nil {
					w.logger.Info("fswatch: re-added: ", path)
				}
				if w.watchDirect {
					// The watch was on a file that was atomically replaced.
					// The replacement event was never delivered, so re-read it.
					w.scheduleCallback(path)
				}
				return
			}
			time.Sleep(DefaultWaitTimeout)
		}
		if w.logger != nil {
			w.logger.Error("fswatch: failed to re-add: ", path)
		}
	}()
}

func (w *Watcher) scheduleCallback(path string) {
	w.stateAccess.Lock()
	if w.closed {
		w.stateAccess.Unlock()
		return
	}

	pending := w.timerMap[path]
	generation := pending.generation + 1
	if pending.timer != nil {
		pending.timer.Stop()
	}
	w.timerMap[path] = pendingCallback{
		generation: generation,
		timer:      time.AfterFunc(w.waitTimeout, func() { w.fireCallback(path, generation) }),
	}
	w.stateAccess.Unlock()
}

func (w *Watcher) fireCallback(path string, generation uint64) {
	w.stateAccess.Lock()
	if w.closed {
		w.stateAccess.Unlock()
		return
	}

	pending, loaded := w.timerMap[path]
	if !loaded || pending.generation != generation {
		w.stateAccess.Unlock()
		return
	}
	delete(w.timerMap, path)
	callback := w.callback
	w.stateAccess.Unlock()

	callback(path)
}
