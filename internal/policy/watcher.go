package policy

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

const defaultDebounce = 250 * time.Millisecond

// Watcher watches a single policy file path and invokes onAccept whenever
// the file content changes AND parses cleanly, or onReject when the new
// content is malformed.
//
// We watch the file's parent directory rather than the file itself so
// that atomic-rename saves (vim, `mv tmp policy.yaml`) trigger events
// even after the original inode goes away.
type Watcher struct {
	path     string
	basename string
	logger   *slog.Logger
	onAccept func(*Policy)
	onReject func(error, []byte)
	debounce time.Duration

	fsw       *fsnotify.Watcher
	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

// NewWatcher creates a Watcher for the given absolute path. The
// callbacks are invoked synchronously from the watcher goroutine —
// keep them short; offload work to other goroutines if needed.
//
// logger may be nil (defaults to slog.Default()).
func NewWatcher(path string, logger *slog.Logger,
	onAccept func(*Policy),
	onReject func(error, []byte),
) (*Watcher, error) {
	if path == "" {
		return nil, fmt.Errorf("policy.Watcher: path is required")
	}
	if onAccept == nil || onReject == nil {
		return nil, fmt.Errorf("policy.Watcher: callbacks are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("policy.Watcher: abs path: %w", err)
	}
	return &Watcher{
		path:     abs,
		basename: filepath.Base(abs),
		logger:   logger,
		onAccept: onAccept,
		onReject: onReject,
		debounce: defaultDebounce,
		done:     make(chan struct{}),
	}, nil
}

// Start opens the fsnotify watcher on the parent directory and launches
// the event loop goroutine. Returns immediately; goroutine runs until
// ctx is cancelled OR Close is called.
func (w *Watcher) Start(ctx context.Context) error {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("policy.Watcher: fsnotify.NewWatcher: %w", err)
	}
	dir := filepath.Dir(w.path)
	if err := fsw.Add(dir); err != nil {
		_ = fsw.Close()
		return fmt.Errorf("policy.Watcher: add %s: %w", dir, err)
	}
	w.fsw = fsw
	w.wg.Add(1)
	go w.run(ctx)
	return nil
}

// Close stops the watcher. Idempotent. Joins the goroutine.
func (w *Watcher) Close() error {
	var err error
	w.closeOnce.Do(func() {
		close(w.done)
		if w.fsw != nil {
			err = w.fsw.Close()
		}
		w.wg.Wait()
	})
	return err
}

// run is the event loop. Filters events by basename, debounces bursts,
// reads the file, dispatches via callbacks.
func (w *Watcher) run(ctx context.Context) {
	defer w.wg.Done()

	var timer *time.Timer
	fireC := make(chan struct{}, 1)

	scheduleLoad := func() {
		if timer != nil {
			timer.Stop()
		}
		timer = time.AfterFunc(w.debounce, func() {
			select {
			case fireC <- struct{}{}:
			default:
			}
		})
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case ev, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			if filepath.Base(ev.Name) != w.basename {
				continue
			}
			if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename) != 0 {
				scheduleLoad()
			} else if ev.Op&fsnotify.Remove != 0 {
				w.logger.Warn("policy file removed; keeping current rules",
					"path", w.path)
			}
		case err, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			w.logger.Error("policy watcher fsnotify error",
				"err", err.Error())
		case <-fireC:
			w.loadAndDispatch()
		}
	}
}

func (w *Watcher) loadAndDispatch() {
	raw, err := os.ReadFile(w.path)
	if err != nil {
		w.logger.Warn("policy file read failed during reload",
			"path", w.path, "err", err.Error())
		return
	}
	p, err := LoadFromBytes(raw)
	if err != nil {
		w.onReject(err, raw)
		return
	}
	w.onAccept(p)
}
