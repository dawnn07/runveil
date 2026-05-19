package policy

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

const validYAML = `
version: 1
rules:
  - name: r1
    match: {all: true}
    action: warn
`

const validYAML2 = `
version: 1
rules:
  - name: r1
    match: {all: true}
    action: warn
  - name: r2
    match: {all: true}
    action: block
`

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func newTestWatcher(t *testing.T, path string,
	onAccept func(*Policy),
	onReject func(error, []byte),
) *Watcher {
	t.Helper()
	w, err := NewWatcher(path, discardLogger(), onAccept, onReject)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = w.Close()
	})
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return w
}

func waitForCh(t *testing.T, ch <-chan struct{}, timeout time.Duration) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for watcher callback")
	}
}

func TestWatcher_AcceptsValidReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	mustWriteFile(t, path, validYAML)

	accepted := make(chan struct{}, 1)
	var got *Policy
	newTestWatcher(t, path,
		func(np *Policy) { got = np; accepted <- struct{}{} },
		func(err error, _ []byte) { t.Errorf("unexpected reject: %v", err) },
	)

	mustWriteFile(t, path, validYAML2)
	waitForCh(t, accepted, 2*time.Second)

	if got == nil || got.RuleCount() != 2 {
		t.Errorf("got rule count = %d, want 2", got.RuleCount())
	}
}

func TestWatcher_RejectsMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	mustWriteFile(t, path, validYAML)

	rejected := make(chan struct{}, 1)
	var gotErr error
	newTestWatcher(t, path,
		func(_ *Policy) { t.Error("unexpected accept") },
		func(err error, _ []byte) { gotErr = err; rejected <- struct{}{} },
	)

	mustWriteFile(t, path, "not: valid: yaml: at: all")
	waitForCh(t, rejected, 2*time.Second)

	if gotErr == nil {
		t.Error("expected non-nil error")
	}
}

func TestWatcher_RejectsInvalidPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	mustWriteFile(t, path, validYAML)

	rejected := make(chan struct{}, 1)
	newTestWatcher(t, path,
		func(_ *Policy) { t.Error("unexpected accept") },
		func(_ error, _ []byte) { rejected <- struct{}{} },
	)

	mustWriteFile(t, path, `
version: 1
rules:
  - name: bad-glob
    match: {path: "**/[unclosed"}
    action: block
`)
	waitForCh(t, rejected, 2*time.Second)
}

func TestWatcher_DebouncesBurstEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	mustWriteFile(t, path, validYAML)

	accepted := make(chan struct{}, 8)
	newTestWatcher(t, path,
		func(_ *Policy) { accepted <- struct{}{} },
		func(err error, _ []byte) { t.Errorf("unexpected reject: %v", err) },
	)

	for i := 0; i < 5; i++ {
		mustWriteFile(t, path, validYAML2)
		time.Sleep(10 * time.Millisecond)
	}

	time.Sleep(500 * time.Millisecond)

	count := 0
loop:
	for {
		select {
		case <-accepted:
			count++
		default:
			break loop
		}
	}
	if count != 1 {
		t.Errorf("got %d accept callbacks, want 1 (debounce should coalesce)", count)
	}
}

func TestWatcher_HandlesAtomicRename(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "policy.yaml")
	mustWriteFile(t, target, validYAML)

	accepted := make(chan struct{}, 1)
	var got *Policy
	newTestWatcher(t, target,
		func(np *Policy) { got = np; accepted <- struct{}{} },
		func(err error, _ []byte) { t.Errorf("unexpected reject: %v", err) },
	)

	tmp := filepath.Join(dir, "policy.yaml.new")
	mustWriteFile(t, tmp, validYAML2)
	if err := os.Rename(tmp, target); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	waitForCh(t, accepted, 2*time.Second)

	if got.RuleCount() != 2 {
		t.Errorf("got rule count = %d, want 2", got.RuleCount())
	}
}

func TestWatcher_CloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	mustWriteFile(t, path, validYAML)

	w, err := NewWatcher(path, discardLogger(),
		func(_ *Policy) {},
		func(_ error, _ []byte) {})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
