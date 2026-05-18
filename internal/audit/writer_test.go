package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewWriter_HappyPath(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{
		Path:       filepath.Join(dir, "audit.log"),
		MaxSizeMB:  1,
		MaxBackups: 1,
		MaxAgeDays: 1,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestNewWriter_RejectsEmptyPath(t *testing.T) {
	_, err := NewWriter(Config{Path: ""}, discardLogger())
	if err == nil {
		t.Error("expected error for empty Path")
	}
}

func TestNewWriter_RejectsZeroSize(t *testing.T) {
	_, err := NewWriter(Config{
		Path:      filepath.Join(t.TempDir(), "audit.log"),
		MaxSizeMB: 0,
	}, discardLogger())
	if err == nil {
		t.Error("expected error for MaxSizeMB=0")
	}
}

func TestWriter_LogAndClose_WritesAllRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	w, err := NewWriter(Config{
		Path:       path,
		MaxSizeMB:  10,
		MaxBackups: 1,
		MaxAgeDays: 1,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	const n = 100
	for i := 0; i < n; i++ {
		w.Log(Record{
			Time:      time.Now(),
			RequestID: "r",
			Host:      "h",
			Method:    "POST",
			Path:      "/x",
			Status:    200,
			Decision:  "continue",
		})
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	count := 0
	for scanner.Scan() {
		var r Record
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			t.Errorf("line %d not JSON: %v", count, err)
		}
		count++
	}
	if count != n {
		t.Errorf("got %d lines, want %d", count, n)
	}
}

func TestWriter_CloseIsIdempotent(t *testing.T) {
	w, _ := NewWriter(Config{
		Path:       filepath.Join(t.TempDir(), "audit.log"),
		MaxSizeMB:  1,
		MaxBackups: 1,
		MaxAgeDays: 1,
	}, discardLogger())
	if err := w.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestWriter_LogAfterCloseIsSafe(t *testing.T) {
	w, _ := NewWriter(Config{
		Path:       filepath.Join(t.TempDir(), "audit.log"),
		MaxSizeMB:  1,
		MaxBackups: 1,
		MaxAgeDays: 1,
	}, discardLogger())
	_ = w.Close()
	// Must not panic.
	w.Log(Record{RequestID: "post-close"})
}

func TestWriter_LogDuringCloseDoesNotPanic(t *testing.T) {
	// Stress test: many Log goroutines racing a Close. Pre-fix this
	// reliably panicked with "send on closed channel" within a few
	// iterations. Post-fix it must complete cleanly.
	for trial := 0; trial < 50; trial++ {
		dir := t.TempDir()
		w, err := NewWriter(Config{
			Path:       filepath.Join(dir, "audit.log"),
			MaxSizeMB:  1,
			MaxBackups: 1,
			MaxAgeDays: 1,
			BufferSize: 16,
		}, discardLogger())
		if err != nil {
			t.Fatalf("NewWriter: %v", err)
		}

		var wg sync.WaitGroup
		const loggers = 16
		for g := 0; g < loggers; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 200; i++ {
					w.Log(Record{RequestID: "stress"})
				}
			}()
		}

		// Close shortly after spawning the loggers. This is the race
		// window pre-fix.
		time.Sleep(50 * time.Microsecond)
		if err := w.Close(); err != nil {
			t.Errorf("trial %d Close: %v", trial, err)
		}
		wg.Wait()
	}
}

// captureHandler captures slog records to a slice so tests can assert
// on warning/error messages.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}
func (h *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(_ string) slog.Handler      { return h }

func (h *captureHandler) hasMessage(msg string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if r.Message == msg {
			return true
		}
	}
	return false
}

func TestWriter_ChannelFullDropsRecord(t *testing.T) {
	// Tiny buffer (1) and spam records faster than the goroutine can
	// pull them, forcing at least one channel-full drop.
	ch := &captureHandler{}
	logger := slog.New(ch)

	dir := t.TempDir()
	w, err := NewWriter(Config{
		Path:       filepath.Join(dir, "audit.log"),
		MaxSizeMB:  1,
		MaxBackups: 1,
		MaxAgeDays: 1,
		BufferSize: 1,
	}, logger)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	for i := 0; i < 10000; i++ {
		w.Log(Record{RequestID: "spam"})
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	if !ch.hasMessage("audit channel full; dropping record") {
		t.Errorf("expected at least one channel-full warning")
	}
}

func TestWriter_ConcurrentLog(t *testing.T) {
	// All Logs happen before Close (concurrent integrity, not
	// concurrent shutdown). Verifies that every record makes it
	// through and the file is well-formed JSONL.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	w, err := NewWriter(Config{
		Path:       path,
		MaxSizeMB:  100,
		MaxBackups: 1,
		MaxAgeDays: 1,
		BufferSize: 4096,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	const goroutines = 32
	const perGoroutine = 100
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				w.Log(Record{
					Time:      time.Now(),
					RequestID: "concurrent",
					Host:      "x",
					Method:    "POST",
					Path:      "/",
					Status:    200,
					Decision:  "continue",
				})
			}
		}()
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	count := 0
	for scanner.Scan() {
		var r Record
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			t.Errorf("line not JSON: %v", err)
		}
		count++
	}
	if count != goroutines*perGoroutine {
		t.Errorf("got %d lines, want %d", count, goroutines*perGoroutine)
	}
}
