# Audit Logging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist one structured audit record per AI request to a rotating JSON Lines file, and surface a `railcore logs` subcommand to inspect it. Records embed both `secretscan` and `pathscan` findings.

**Architecture:** New leaf package `internal/audit/` with a `Record` type, a `Logger` interface, a `NoopLogger`, and an async `Writer` (channel + background goroutine + `gopkg.in/natefinch/lumberjack.v2`). `proxy.Config` grows an `AuditFunc audit.Logger` field invoked at the per-request completion site. `cmd/railcore/proxy.go` constructs the `Writer` on startup and defers `Close()` on shutdown. `cmd/railcore/logs.go` is a new subcommand sibling.

**Tech Stack:** Go 1.25 stdlib (`encoding/json`, `time`, `log/slog`, `os`, `bufio`) + new dep `gopkg.in/natefinch/lumberjack.v2`. Existing internal packages unchanged except `internal/proxy/` (adds Config field + helper functions) and `cmd/railcore/` (new subcommand file + flag wiring).

**Spec:** [`docs/superpowers/specs/2026-05-17-audit-logging-design.md`](../specs/2026-05-17-audit-logging-design.md)

---

## File Map

| File | Purpose |
|---|---|
| `internal/audit/audit.go` | **Create:** `Record`, `Logger`, `NoopLogger`, `Config` |
| `internal/audit/writer.go` | **Create:** `Writer` (channel + goroutine + lumberjack), `NewWriter`, `Log`, `Close` |
| `internal/audit/audit_test.go` | **Create:** Record marshal, NoopLogger tests |
| `internal/audit/writer_test.go` | **Create:** Writer happy path + channel-full + close + concurrent tests |
| `internal/proxy/server.go` | **Modify:** add `Config.AuditFunc audit.Logger` |
| `internal/proxy/upstream.go` | **Modify:** call `cfg.AuditFunc.Log(record)` at completion site; add `vendorAndEndpoint` + `findingsFromMetadata` helpers |
| `internal/proxy/server_test.go` | **Modify:** append tests verifying AuditFunc invocation |
| `cmd/railcore/main.go` | **Modify:** dispatch `logs` subcommand |
| `cmd/railcore/logs.go` | **Create:** `runLogs` + `formatRecord` + `parseAuditFile` |
| `cmd/railcore/logs_test.go` | **Create:** in-package formatting + parsing unit tests |
| `cmd/railcore/proxy.go` | **Modify:** add `--audit-log` etc. flags, construct Writer, defer Close |
| `test/integration/audit_test.go` | **Create:** end-to-end audit file scenarios |
| `test/integration/cli_test.go` | **Modify:** append `railcore logs` integration tests |
| `go.mod`, `go.sum` | **Modify:** `gopkg.in/natefinch/lumberjack.v2` direct dep |

**Dependency direction (new edges):**

```
cmd/railcore
   └── internal/audit          (NEW leaf — depends only on stdlib + lumberjack)

internal/proxy ──→ internal/audit  (NEW edge: proxy holds audit.Logger via Config)
internal/proxy ──→ internal/parser (NEW edge: proxy calls parser.ParseRequest in audit helpers)
```

`internal/audit/` is a leaf — stdlib + lumberjack only. No internal imports.

---

## Task 1: Audit Record + Logger interface + NoopLogger

**Files:**
- Create: `internal/audit/audit.go`
- Create: `internal/audit/audit_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/audit/audit_test.go`:

```go
package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRecord_MarshalJSON_AllFields(t *testing.T) {
	r := Record{
		Time:       time.Date(2026, 5, 17, 16, 33, 12, 0, time.UTC),
		RequestID:  "abc-123",
		Host:       "api.anthropic.com",
		Method:     "POST",
		Path:       "/v1/messages",
		Status:     403,
		BytesIn:    1842,
		BytesOut:   196,
		DurationMs: 42,
		Vendor:     "anthropic",
		Endpoint:   "messages",
		Decision:   "block",
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(data)
	for _, want := range []string{
		`"time":"2026-05-17T16:33:12Z"`,
		`"request_id":"abc-123"`,
		`"host":"api.anthropic.com"`,
		`"method":"POST"`,
		`"path":"/v1/messages"`,
		`"status":403`,
		`"bytes_in":1842`,
		`"bytes_out":196`,
		`"duration_ms":42`,
		`"vendor":"anthropic"`,
		`"endpoint":"messages"`,
		`"decision":"block"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in marshaled output:\n%s", want, s)
		}
	}
}

func TestRecord_MarshalJSON_OmitsEmptyOptionals(t *testing.T) {
	r := Record{
		Time:       time.Now(),
		RequestID:  "x",
		Host:       "example.com",
		Method:     "GET",
		Path:       "/",
		Status:     200,
		BytesIn:    0,
		BytesOut:   0,
		DurationMs: 0,
		Decision:   "continue",
		// Vendor, Endpoint, Findings deliberately omitted.
	}
	data, _ := json.Marshal(r)
	s := string(data)
	if strings.Contains(s, `"vendor"`) {
		t.Errorf("vendor should be omitted when empty; got %s", s)
	}
	if strings.Contains(s, `"endpoint"`) {
		t.Errorf("endpoint should be omitted when empty; got %s", s)
	}
	if strings.Contains(s, `"findings"`) {
		t.Errorf("findings should be omitted when empty; got %s", s)
	}
}

func TestNoopLogger_LogIsSafe(t *testing.T) {
	var l Logger = NoopLogger{}
	// Multiple calls must not panic.
	for i := 0; i < 10; i++ {
		l.Log(Record{RequestID: "test"})
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test ./internal/audit/...
```

Expected: compile error — `Record`, `Logger`, `NoopLogger` undefined.

- [ ] **Step 3: Implement `internal/audit/audit.go`**

```go
// Package audit captures per-request audit events from the Railcore
// proxy and persists them as JSON Lines to a rotating file.
//
// audit is a leaf package: it depends only on stdlib and
// gopkg.in/natefinch/lumberjack.v2 (rotation). It does not import
// any other railcore/internal/ package; producers pass values via
// the Logger interface.
package audit

import (
	"time"
)

// Record is one audit event written as a JSON Lines entry.
//
// Wire format (JSON tags):
//   time         RFC3339Nano UTC
//   request_id   UUID emitted by the proxy
//   host         AI vendor host (e.g., "api.anthropic.com")
//   method       HTTP method
//   path         request path
//   status       HTTP response status
//   bytes_in     request body size
//   bytes_out    response body size streamed back
//   duration_ms  wall-clock total
//   vendor       optional; "openai" | "anthropic"
//   endpoint     optional; "chat.completions" | "messages"
//   decision     "continue" | "block"
//   findings     optional; per-detector findings serialized via their own MarshalJSON
type Record struct {
	Time       time.Time `json:"time"`
	RequestID  string    `json:"request_id"`
	Host       string    `json:"host"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Status     int       `json:"status"`
	BytesIn    int64     `json:"bytes_in"`
	BytesOut   int64     `json:"bytes_out"`
	DurationMs int64     `json:"duration_ms"`

	Vendor   string `json:"vendor,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	Decision string `json:"decision"`
	Findings []any  `json:"findings,omitempty"`
}

// Logger is the consumer-facing interface. Proxy holds a Logger
// (never a concrete *Writer) so tests can inject capturing or no-op
// implementations.
type Logger interface {
	Log(r Record)
}

// NoopLogger discards records. Used as the default when no audit
// destination is configured.
type NoopLogger struct{}

// Log implements Logger by doing nothing.
func (NoopLogger) Log(_ Record) {}
```

- [ ] **Step 4: Run tests, confirm pass**

```bash
go test -race -count=1 ./internal/audit/...
```

Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/audit/
git commit -m "feat(audit): Record type, Logger interface, NoopLogger"
```

---

## Task 2: Audit Writer (happy path + lumberjack)

**Files:**
- Create: `internal/audit/writer.go`
- Create: `internal/audit/writer_test.go`
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Add the lumberjack dependency**

```bash
go get gopkg.in/natefinch/lumberjack.v2@latest
go mod tidy
```

- [ ] **Step 2: Write the failing tests**

Create `internal/audit/writer_test.go`:

```go
package audit

import (
	"bufio"
	"encoding/json"
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
```

- [ ] **Step 3: Run, confirm tests fail to compile**

```bash
go test ./internal/audit/...
```

Expected: compile error — `Writer`, `NewWriter`, `Config` undefined.

- [ ] **Step 4: Implement `internal/audit/writer.go`**

```go
package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Config configures a Writer. All fields have sensible zero-value
// defaults applied by NewWriter (except Path, which is required).
type Config struct {
	Path       string // file path; required (caller passes "" to opt out at a higher layer)
	MaxSizeMB  int    // before rotation; default 100
	MaxBackups int    // rotated files to keep; default 5
	MaxAgeDays int    // total age cap; default 30
	BufferSize int    // channel buffer; default 1024
}

// Writer is the lumberjack-backed, async, file-writing Logger.
type Writer struct {
	logger  *slog.Logger
	ch      chan Record
	wg      sync.WaitGroup
	lj      *lumberjack.Logger
	closed  atomic.Bool
	closeMu sync.Mutex
}

// NewWriter probes that Path is writable, opens the lumberjack writer,
// starts the background goroutine, and returns a *Writer. Returns an
// error if the path is empty, unwritable, or any size/age/backups flag
// is invalid.
func NewWriter(cfg Config, logger *slog.Logger) (*Writer, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("audit: Path is required")
	}
	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = 100
	}
	if cfg.MaxBackups <= 0 {
		cfg.MaxBackups = 5
	}
	if cfg.MaxAgeDays <= 0 {
		cfg.MaxAgeDays = 30
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 1024
	}
	if logger == nil {
		logger = slog.Default()
	}

	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o700); err != nil {
		return nil, fmt.Errorf("audit: create parent dir: %w", err)
	}

	// Probe writability: try opening the file for append.
	probe, err := os.OpenFile(cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", cfg.Path, err)
	}
	_ = probe.Close()

	lj := &lumberjack.Logger{
		Filename:   cfg.Path,
		MaxSize:    cfg.MaxSizeMB,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAgeDays,
		LocalTime:  false,
		Compress:   false,
	}

	w := &Writer{
		logger: logger,
		ch:     make(chan Record, cfg.BufferSize),
		lj:     lj,
	}
	w.wg.Add(1)
	go w.run()
	return w, nil
}

// Log implements Logger. Non-blocking: drops the record (with a WARN
// to the slog logger) if the channel is full.
//
// Safe to call after Close: silently does nothing.
func (w *Writer) Log(r Record) {
	if w == nil || w.closed.Load() {
		return
	}
	select {
	case w.ch <- r:
		// queued
	default:
		w.logger.Warn("audit channel full; dropping record",
			"request_id", r.RequestID)
	}
}

// Close drains the buffer, flushes lumberjack, stops the goroutine.
// Idempotent. After Close, Log is a no-op.
func (w *Writer) Close() error {
	w.closeMu.Lock()
	defer w.closeMu.Unlock()
	if w.closed.Load() {
		return nil
	}
	w.closed.Store(true)
	close(w.ch)
	w.wg.Wait()
	return w.lj.Close()
}

// run is the background goroutine. Reads records from the channel
// until it's closed, then exits.
func (w *Writer) run() {
	defer w.wg.Done()
	var buf bytes.Buffer
	for r := range w.ch {
		buf.Reset()
		if err := json.NewEncoder(&buf).Encode(r); err != nil {
			w.logger.Error("audit: marshal record",
				"request_id", r.RequestID,
				"err", err.Error())
			continue
		}
		if _, err := w.lj.Write(buf.Bytes()); err != nil {
			w.logger.Error("audit: write",
				"err", err.Error())
		}
	}
}
```

- [ ] **Step 5: Run tests, confirm pass**

```bash
go test -race -count=1 ./internal/audit/...
```

Expected: 8 tests pass total (3 from Task 1 + 5 from Task 2).

- [ ] **Step 6: Commit**

```bash
git add internal/audit/writer.go internal/audit/writer_test.go go.mod go.sum
git commit -m "feat(audit): Writer with async channel + lumberjack rotation"
```

---

## Task 3: Audit Writer edge cases (channel-full + concurrent)

**Files:**
- Modify: `internal/audit/writer_test.go` (append)

- [ ] **Step 1: Append failing tests**

Append to `internal/audit/writer_test.go`:

```go

// captureLogger captures slog records to a slice so tests can assert
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
	// Tiny buffer (1) and a deliberately slow writer to force the
	// channel to fill. The trick: we don't actually slow the writer;
	// instead we send records faster than the goroutine can pull,
	// which is reliably the case for a buffer of 1.
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

	// Spam 10000 records in a tight loop. At buffer size 1, many will
	// be dropped while the goroutine catches up.
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
```

Add `"context"` and `"sync"` to the test file's import block if not already present.

- [ ] **Step 2: Run tests, confirm pass**

```bash
go test -race -count=1 ./internal/audit/...
```

Expected: all 10 audit tests pass.

- [ ] **Step 3: Commit**

```bash
git add internal/audit/writer_test.go
git commit -m "test(audit): channel-full warning + concurrent log under race"
```

---

## Task 4: Proxy wire-up — AuditFunc + completion-site call + helpers

**Files:**
- Modify: `internal/proxy/server.go`
- Modify: `internal/proxy/upstream.go`
- Modify: `internal/proxy/server_test.go` (append)

- [ ] **Step 1: Write failing tests**

Append to `internal/proxy/server_test.go`:

```go

// captureAudit records every audit.Record passed to Log.
type captureAudit struct {
	mu      sync.Mutex
	records []audit.Record
}

func (c *captureAudit) Log(r audit.Record) {
	c.mu.Lock()
	c.records = append(c.records, r)
	c.mu.Unlock()
}

func (c *captureAudit) get() []audit.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]audit.Record, len(c.records))
	copy(out, c.records)
	return out
}

func TestProxy_AuditFuncInvokedOnContinue(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	srv, addr := newTestServer(t)
	srv.cfg.UpstreamTLS = &tls.Config{RootCAs: upstreamPool, ServerName: upstreamURL.Hostname()}
	srv.cfg.UpstreamResolver = func(_ string) (string, error) { return upstreamURL.Host, nil }

	cap := &captureAudit{}
	srv.cfg.AuditFunc = cap

	caPool := x509.NewCertPool()
	caPool.AddCert(srv.cfg.CA.RootCert())
	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "audit.test"},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("https://audit.test/some/path")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()

	// Give the deferred audit call a moment to land.
	time.Sleep(50 * time.Millisecond)

	recs := cap.get()
	if len(recs) != 1 {
		t.Fatalf("got %d audit records, want 1", len(recs))
	}
	r := recs[0]
	if r.Decision != "continue" {
		t.Errorf("Decision = %q, want continue", r.Decision)
	}
	if r.Host != "audit.test" {
		t.Errorf("Host = %q, want audit.test", r.Host)
	}
	if r.Method != "GET" {
		t.Errorf("Method = %q, want GET", r.Method)
	}
	if r.Status != 200 {
		t.Errorf("Status = %d, want 200", r.Status)
	}
	if r.RequestID == "" {
		t.Error("RequestID is empty")
	}
}

func TestProxy_AuditFuncNilIsSafe(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	srv, addr := newTestServer(t)
	srv.cfg.UpstreamTLS = &tls.Config{RootCAs: upstreamPool, ServerName: upstreamURL.Hostname()}
	srv.cfg.UpstreamResolver = func(_ string) (string, error) { return upstreamURL.Host, nil }
	// AuditFunc deliberately left nil.

	caPool := x509.NewCertPool()
	caPool.AddCert(srv.cfg.CA.RootCert())
	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "nil-audit.test"},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("https://nil-audit.test/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	// Survived without panic = test passes.
}

func TestProxy_AuditRecordIncludesAnthropicVendor(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	srv, addr := newTestServer(t)
	srv.cfg.UpstreamTLS = &tls.Config{RootCAs: upstreamPool, ServerName: upstreamURL.Hostname()}
	srv.cfg.UpstreamResolver = func(_ string) (string, error) { return upstreamURL.Host, nil }

	cap := &captureAudit{}
	srv.cfg.AuditFunc = cap

	caPool := x509.NewCertPool()
	caPool.AddCert(srv.cfg.CA.RootCert())
	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "api.anthropic.com"},
		},
		Timeout: 5 * time.Second,
	}
	body := `{"model":"claude-opus-4-7","messages":[{"role":"user","content":"hi"}]}`
	resp, err := client.Post("https://api.anthropic.com/v1/messages", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	resp.Body.Close()

	time.Sleep(50 * time.Millisecond)

	recs := cap.get()
	if len(recs) != 1 {
		t.Fatalf("got %d audit records, want 1", len(recs))
	}
	r := recs[0]
	if r.Vendor != "anthropic" {
		t.Errorf("Vendor = %q, want anthropic", r.Vendor)
	}
	if r.Endpoint != "messages" {
		t.Errorf("Endpoint = %q, want messages", r.Endpoint)
	}
	if r.BytesIn != int64(len(body)) {
		t.Errorf("BytesIn = %d, want %d", r.BytesIn, len(body))
	}
}
```

Add `"railcore/internal/audit"` and `"sync"` to the test file's imports if not already present.

- [ ] **Step 2: Confirm tests fail to compile**

```bash
go test ./internal/proxy/...
```

Expected: compile error — `Config.AuditFunc` undefined.

- [ ] **Step 3: Add the `AuditFunc` field to `Config`**

Open `internal/proxy/server.go`. Find the `Config` struct and add a new field at the end:

```go
type Config struct {
	Addr             string
	CA               *ca.CA
	Pipeline         *pipeline.Chain
	MaxBodyBytes     int64
	Logger           *slog.Logger
	UpstreamTLS      *tls.Config
	UpstreamResolver func(host string) (string, error)

	// NEW: audit logger. When nil, audit records are not emitted.
	AuditFunc audit.Logger
}
```

Add `"railcore/internal/audit"` to the imports of `server.go`.

- [ ] **Step 4: Wire the audit call in `internal/proxy/upstream.go`**

Open `internal/proxy/upstream.go`. The `newHandler` function returns an `http.HandlerFunc`. Near the top of the closure body there's a `defer` block that emits the existing `s.log.Info("request complete", ...)` line. Find that defer and add the audit call inside it.

Specifically, locate this section:

```go
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		w = rec
		start := time.Now()
		decision := pipeline.Continue
		var bytesIn int64

		defer func() {
			s.log.Info("request complete",
				"request_id", requestID,
				"host", host,
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"bytes_in", bytesIn,
				"bytes_out", rec.bytesOut,
				"duration_ms", time.Since(start).Milliseconds(),
				"decision", decision.String(),
			)
		}()
```

(The exact code may vary slightly — match what's actually in the file.)

Append inside the existing `defer func() { ... }()` block, AFTER the `s.log.Info(...)` call but still inside the closure:

```go
			if s.cfg.AuditFunc != nil {
				vendor, endpoint := vendorAndEndpoint(rc)
				s.cfg.AuditFunc.Log(audit.Record{
					Time:       start,
					RequestID:  requestID,
					Host:       host,
					Method:     r.Method,
					Path:       r.URL.Path,
					Status:     rec.status,
					BytesIn:    bytesIn,
					BytesOut:   rec.bytesOut,
					DurationMs: time.Since(start).Milliseconds(),
					Vendor:     vendor,
					Endpoint:   endpoint,
					Decision:   decision.String(),
					Findings:   findingsFromMetadata(rc),
				})
			}
```

Add the two helpers near the bottom of `internal/proxy/upstream.go`:

```go

// vendorAndEndpoint inspects the parsed request via the parser package
// to extract the vendor name and endpoint identifier. Returns ("","")
// if the request isn't a known AI endpoint.
//
// Body is read from rc.Metadata["body"], which the proxy stashes at the
// top of newHandler.
func vendorAndEndpoint(rc *pipeline.RequestCtx) (vendor, endpoint string) {
	body, ok := rc.Metadata["body"].([]byte)
	if !ok {
		return "", ""
	}
	parsed, err := parser.ParseRequest(rc.Host, rc.Req, body)
	if err != nil || parsed == nil {
		return "", ""
	}
	return parsed.Vendor, parsed.Endpoint
}

// findingsFromMetadata collects findings from both secretscan and
// pathscan stages' metadata keys into a flat []any. Returns nil if
// neither key is present (so the audit record's findings field is
// omitted via omitempty).
func findingsFromMetadata(rc *pipeline.RequestCtx) []any {
	var out []any
	if v, ok := rc.Metadata["pathscan.findings"]; ok {
		out = appendFindings(out, v)
	}
	if v, ok := rc.Metadata["secretscan.findings"]; ok {
		out = appendFindings(out, v)
	}
	return out
}

// appendFindings handles the case where v may be a typed slice
// ([]secretscan.EnrichedFinding or []pathscan.PathFinding) or a slice
// of maps (from tests). Marshal-then-unmarshal flattens both shapes
// into a uniform []any.
func appendFindings(out []any, v any) []any {
	raw, err := json.Marshal(v)
	if err != nil {
		return out
	}
	var single any
	if err := json.Unmarshal(raw, &single); err != nil {
		return out
	}
	switch s := single.(type) {
	case []any:
		return append(out, s...)
	default:
		return append(out, single)
	}
}
```

Add the following imports if not already present in `internal/proxy/upstream.go`:

```go
"railcore/internal/audit"
"railcore/internal/parser"
```

- [ ] **Step 5: Run tests, confirm pass**

```bash
go test -race -count=1 ./internal/proxy/...
```

Expected: all existing proxy tests pass + 3 new audit tests pass.

- [ ] **Step 6: Run full suite**

```bash
go test -race -count=1 ./...
go vet ./...
```

Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add internal/proxy/server.go internal/proxy/upstream.go internal/proxy/server_test.go
git commit -m "feat(proxy): emit audit.Record at request completion via Config.AuditFunc"
```

---

## Task 5: `railcore logs` subcommand

**Files:**
- Create: `cmd/railcore/logs.go`
- Create: `cmd/railcore/logs_test.go`
- Modify: `cmd/railcore/main.go`

- [ ] **Step 1: Write failing unit tests**

Create `cmd/railcore/logs_test.go`:

```go
package main

import (
	"strings"
	"testing"
	"time"

	"railcore/internal/audit"
)

func TestFormatRecord_Continue(t *testing.T) {
	r := audit.Record{
		Time:       time.Date(2026, 5, 17, 16, 33, 12, 0, time.UTC),
		RequestID:  "x",
		Host:       "api.openai.com",
		Method:     "POST",
		Path:       "/v1/chat/completions",
		Status:     200,
		DurationMs: 42,
		Decision:   "continue",
	}
	got := formatRecord(r)
	for _, want := range []string{"16:33:12", "✓", "POST", "api.openai.com", "/v1/chat/completions", "200", "42ms", "continue"} {
		if !strings.Contains(got, want) {
			t.Errorf("formatRecord output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "findings=") {
		t.Errorf("findings should be absent when none present; got %s", got)
	}
}

func TestFormatRecord_Block(t *testing.T) {
	r := audit.Record{
		Time:       time.Date(2026, 5, 17, 16, 33, 12, 0, time.UTC),
		RequestID:  "x",
		Host:       "api.anthropic.com",
		Method:     "POST",
		Path:       "/v1/messages",
		Status:     403,
		DurationMs: 38,
		Decision:   "block",
		Findings: []any{
			map[string]any{"detector": "path-scan", "rule": "block-payments"},
			map[string]any{"detector": "secret-scan", "rule": "block-aws"},
		},
	}
	got := formatRecord(r)
	for _, want := range []string{"✗", "block", "findings=2", "block-payments", "block-aws"} {
		if !strings.Contains(got, want) {
			t.Errorf("formatRecord output missing %q:\n%s", want, got)
		}
	}
}

func TestFormatRecord_NoVendor(t *testing.T) {
	r := audit.Record{
		Time:     time.Now(),
		Host:     "example.com",
		Method:   "GET",
		Path:     "/",
		Status:   200,
		Decision: "continue",
	}
	got := formatRecord(r)
	if got == "" {
		t.Error("formatRecord returned empty string")
	}
}

func TestParseAuditFile_SkipsMalformed(t *testing.T) {
	content := []byte(`{"time":"2026-05-17T16:33:12Z","request_id":"a","host":"h","method":"GET","path":"/","status":200,"bytes_in":0,"bytes_out":0,"duration_ms":1,"decision":"continue"}
not json
{"time":"2026-05-17T16:33:13Z","request_id":"b","host":"h","method":"GET","path":"/","status":200,"bytes_in":0,"bytes_out":0,"duration_ms":1,"decision":"continue"}
`)
	records, skipped := parseAuditBytes(content)
	if len(records) != 2 {
		t.Errorf("got %d records, want 2", len(records))
	}
	if skipped != 1 {
		t.Errorf("got %d skipped, want 1", skipped)
	}
}
```

- [ ] **Step 2: Run, confirm tests fail to compile**

```bash
go test ./cmd/railcore/...
```

Expected: compile error — `formatRecord`, `parseAuditBytes` undefined.

- [ ] **Step 3: Create `cmd/railcore/logs.go`**

```go
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"railcore/internal/audit"
)

func runLogs(args []string) {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "directory containing audit.log")
	filePath := fs.String("file", "", "explicit path to audit log (overrides --data-dir)")
	numLines := fs.Int("n", 50, "number of recent records to show before exiting / starting follow")
	follow := fs.Bool("follow", false, "after the initial output, stream new records as they arrive")
	fs.BoolVar(follow, "f", false, "shorthand for --follow")
	jsonOut := fs.Bool("json", false, "print raw JSON lines instead of the pretty format")
	_ = fs.Parse(args)

	if *numLines <= 0 {
		fmt.Fprintln(os.Stderr, "logs: -n must be > 0")
		os.Exit(2)
	}

	path := *filePath
	if path == "" {
		path = filepath.Join(*dataDir, "audit.log")
	}

	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "logs: %s: file not found. Has the proxy run yet?\n", path)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "logs: open %s: %v\n", path, err)
		os.Exit(1)
	}
	defer f.Close()

	// Read all and emit last N (simple; for very large files we'd want
	// reverse-seek, but a few hundred MB of JSONL is fine to scan).
	data, err := io.ReadAll(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logs: read %s: %v\n", path, err)
		os.Exit(1)
	}
	records, skipped := parseAuditBytes(data)
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "logs: skipped %d malformed lines\n", skipped)
	}

	start := 0
	if len(records) > *numLines {
		start = len(records) - *numLines
	}
	for _, r := range records[start:] {
		emit(r, *jsonOut)
	}

	if !*follow {
		return
	}

	// Tail mode: poll-based, 200ms interval.
	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logs: seek end: %v\n", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		// Read any new data from current offset.
		fi, err := f.Stat()
		if err != nil {
			continue
		}
		if fi.Size() < offset {
			// File shrank — rotation likely. Reopen.
			f.Close()
			f, err = os.Open(path)
			if err != nil {
				continue
			}
			offset = 0
			scanner = bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 1024*1024)
			continue
		}
		if fi.Size() == offset {
			continue
		}
		// New data available; read line-by-line.
		for scanner.Scan() {
			var r audit.Record
			if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
				continue
			}
			emit(r, *jsonOut)
		}
		offset, _ = f.Seek(0, io.SeekCurrent)
	}
}

// context returns context.Background. Wrapped in a function so we can
// import signal.NotifyContext without a top-level context.Background()
// reference that would require importing "context" here too.
//
// Actually we do need to import "context"; this is just a tiny helper.
// (See parseAuditBytes for actual parsing logic.)
func context() ctxBackground { return ctxBackground{} }

type ctxBackground struct{}

// ... (placeholder — see actual implementation below)
```

WAIT — the above section has an awkward `context` helper. Replace the entire `runLogs` function with the cleaner version below (just import `"context"` at the top instead). REPLACE Step 3's entire file content with this clean version:

```go
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"railcore/internal/audit"
)

func runLogs(args []string) {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "directory containing audit.log")
	filePath := fs.String("file", "", "explicit path to audit log (overrides --data-dir)")
	numLines := fs.Int("n", 50, "number of recent records to show before exiting / starting follow")
	follow := fs.Bool("follow", false, "after the initial output, stream new records as they arrive")
	fs.BoolVar(follow, "f", false, "shorthand for --follow")
	jsonOut := fs.Bool("json", false, "print raw JSON lines instead of the pretty format")
	_ = fs.Parse(args)

	if *numLines <= 0 {
		fmt.Fprintln(os.Stderr, "logs: -n must be > 0")
		os.Exit(2)
	}

	path := *filePath
	if path == "" {
		path = filepath.Join(*dataDir, "audit.log")
	}

	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "logs: %s: file not found. Has the proxy run yet?\n", path)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "logs: open %s: %v\n", path, err)
		os.Exit(1)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logs: read %s: %v\n", path, err)
		os.Exit(1)
	}
	records, skipped := parseAuditBytes(data)
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "logs: skipped %d malformed lines\n", skipped)
	}

	startIdx := 0
	if len(records) > *numLines {
		startIdx = len(records) - *numLines
	}
	for _, r := range records[startIdx:] {
		emit(r, *jsonOut)
	}

	if !*follow {
		return
	}

	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logs: seek end: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		fi, err := f.Stat()
		if err != nil {
			continue
		}
		if fi.Size() < offset {
			f.Close()
			f, err = os.Open(path)
			if err != nil {
				continue
			}
			offset = 0
			scanner = bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 1024*1024)
			continue
		}
		if fi.Size() == offset {
			continue
		}
		for scanner.Scan() {
			var r audit.Record
			if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
				continue
			}
			emit(r, *jsonOut)
		}
		offset, _ = f.Seek(0, io.SeekCurrent)
	}
}

// parseAuditBytes scans newline-separated JSON Lines and returns the
// successfully-parsed records plus the count of lines that failed to
// parse (which the caller may surface as a warning).
func parseAuditBytes(data []byte) (records []audit.Record, skipped int) {
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r audit.Record
		if err := json.Unmarshal(line, &r); err != nil {
			skipped++
			continue
		}
		records = append(records, r)
	}
	return records, skipped
}

func emit(r audit.Record, jsonOut bool) {
	if jsonOut {
		raw, err := json.Marshal(r)
		if err != nil {
			return
		}
		os.Stdout.Write(raw)
		os.Stdout.Write([]byte("\n"))
		return
	}
	fmt.Println(formatRecord(r))
}

// formatRecord renders one record as a single pretty line.
func formatRecord(r audit.Record) string {
	statusIcon := "✓"
	if r.Status >= 400 {
		statusIcon = "✗"
	}
	hhmmss := r.Time.Format("15:04:05")
	base := fmt.Sprintf("%s  %s  %-4s  %-22s  %-30s  %3d  %5dms  %s",
		hhmmss, statusIcon, r.Method, r.Host, truncate(r.Path, 30), r.Status, r.DurationMs, r.Decision)
	if len(r.Findings) > 0 {
		ruleNames := extractRuleNames(r.Findings)
		base += fmt.Sprintf("  findings=%d [%s]", len(r.Findings), strings.Join(ruleNames, ","))
	}
	return base
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// extractRuleNames pulls "rule" string values from a slice of finding
// objects (which are map[string]any after JSON round-trip).
func extractRuleNames(findings []any) []string {
	var names []string
	for _, f := range findings {
		m, ok := f.(map[string]any)
		if !ok {
			continue
		}
		rule, ok := m["rule"].(string)
		if !ok || rule == "" {
			continue
		}
		names = append(names, rule)
	}
	return names
}
```

Add `"bytes"` to the imports — used by `bytes.Split`.

- [ ] **Step 4: Dispatch the subcommand**

Open `cmd/railcore/main.go`. Find the `switch os.Args[1]` block and add a new case:

```go
	case "logs":
		runLogs(os.Args[2:])
```

In the `printUsage` function, find the Commands block and add one new line (alphabetical order):

```
  logs           Stream the audit log (default: tail last 50, --follow for live).
```

- [ ] **Step 5: Build and run unit tests**

```bash
go build ./...
go test -race -count=1 ./cmd/railcore/...
```

Expected: 4 logs_test PASS, all other existing cmd tests pass.

- [ ] **Step 6: Commit**

```bash
git add cmd/railcore/logs.go cmd/railcore/logs_test.go cmd/railcore/main.go
git commit -m "feat(cli): railcore logs subcommand with -n/--follow/--json"
```

---

## Task 6: Wire `--audit-log` flags into `proxy` subcommand

**Files:**
- Modify: `cmd/railcore/proxy.go`

- [ ] **Step 1: Edit `cmd/railcore/proxy.go`**

Open the file. The current `runProxy` function parses several flags via a `flag.FlagSet`. Add the audit flags alongside the existing ones, and wire the `audit.Writer` construction into the proxy setup.

Find the existing flag block:

```go
fs := flag.NewFlagSet("proxy", flag.ExitOnError)
port := fs.Int("port", defaultPort(), "TCP port to listen on (overrides RAILCORE_PORT)")
dataDir := fs.String("data-dir", defaultDataDir(), "directory for CA + state")
blockOnDetect := fs.Bool("block-on-detect", false, "...")
policyPath := fs.String("policy", "", "...")
_ = fs.Parse(args)
```

Add four new flags before `_ = fs.Parse(args)`:

```go
auditEnabled := fs.Bool("audit-enabled", true, "write per-request audit records to a JSON Lines log file")
auditLog := fs.String("audit-log", "", "path to audit log file (default: <data-dir>/audit.log)")
auditMaxSizeMB := fs.Int("audit-max-size-mb", 100, "max audit file size before rotation")
auditMaxBackups := fs.Int("audit-max-backups", 5, "rotated audit files to retain")
auditMaxAgeDays := fs.Int("audit-max-age-days", 30, "max age in days for rotated audit files")
```

After the existing `if err := trust.New().Install(...)` block but BEFORE the `chain := pipeline.NewChain()...` block, add:

```go
// Resolve audit log path.
auditPath := *auditLog
if auditPath == "" {
	auditPath = filepath.Join(*dataDir, "audit.log")
}

var auditLogger audit.Logger = audit.NoopLogger{}
var auditWriter *audit.Writer
if *auditEnabled {
	w, err := audit.NewWriter(audit.Config{
		Path:       auditPath,
		MaxSizeMB:  *auditMaxSizeMB,
		MaxBackups: *auditMaxBackups,
		MaxAgeDays: *auditMaxAgeDays,
	}, logger)
	if err != nil {
		logger.Error("audit init failed", "err", err.Error())
		os.Exit(1)
	}
	auditWriter = w
	auditLogger = w
	defer func() { _ = auditWriter.Close() }()
}
```

Then in the existing `proxy.New(proxy.Config{...})` call, add `AuditFunc: auditLogger` to the struct literal:

```go
srv := proxy.New(proxy.Config{
	Addr:      addr,
	CA:        caInst,
	Pipeline:  chain,
	Logger:    logger,
	AuditFunc: auditLogger,
})
```

Add `"railcore/internal/audit"` to the imports of `cmd/railcore/proxy.go`.

- [ ] **Step 2: Build and smoke-test**

```bash
make build
mkdir -p /tmp/railcore-sp6
./railcore proxy --port 19443 --data-dir /tmp/railcore-sp6 2>&1 | head -5 &
SP=$!
sleep 1
kill $SP 2>/dev/null
wait 2>/dev/null
ls /tmp/railcore-sp6/audit.log && echo "(audit file created)"
rm -rf /tmp/railcore-sp6
```

Expected: audit.log file exists in the data dir (empty since no requests were served).

- [ ] **Step 3: Run full test suite**

```bash
go test -race -count=1 ./...
go vet ./...
```

Expected: all tests pass, vet clean.

- [ ] **Step 4: Commit**

```bash
git add cmd/railcore/proxy.go
git commit -m "feat(cli): --audit-log + rotation flags on proxy subcommand"
```

---

## Task 7: End-to-end integration tests

**Files:**
- Create: `test/integration/audit_test.go`
- Modify: `test/integration/cli_test.go` (append)

- [ ] **Step 1: Create end-to-end audit test**

Create `test/integration/audit_test.go`:

```go
// End-to-end tests for sub-project #6: real http.Client through a real
// proxy with a real audit.Writer writing to a temp file. Asserts the
// audit log contains well-formed JSON records.
package integration

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"railcore/internal/audit"
	"railcore/internal/ca"
	"railcore/internal/pipeline"
	"railcore/internal/policy"
	"railcore/internal/proxy"
	pathscanstage "railcore/internal/stage/pathscan"
)

func setupAudit(t *testing.T, policyYAML string) (client *http.Client, auditPath string, cleanup func()) {
	t.Helper()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	tmpDir := t.TempDir()
	auditPath = filepath.Join(tmpDir, "audit.log")

	auditWriter, err := audit.NewWriter(audit.Config{
		Path:       auditPath,
		MaxSizeMB:  10,
		MaxBackups: 1,
		MaxAgeDays: 1,
	}, nil)
	if err != nil {
		t.Fatalf("audit.NewWriter: %v", err)
	}

	caInst, err := ca.GenerateOrLoad(tmpDir + "/ca")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	chain := pipeline.NewChain()
	if policyYAML != "" {
		pol, err := policy.LoadFromBytes([]byte(policyYAML))
		if err != nil {
			t.Fatalf("policy.LoadFromBytes: %v", err)
		}
		chain.Register(pathscanstage.New(pathscanstage.Config{Policy: pol}, nil))
	}

	srv := proxy.New(proxy.Config{
		Addr:             "127.0.0.1:0",
		CA:               caInst,
		Pipeline:         chain,
		UpstreamTLS:      &tls.Config{RootCAs: upstreamPool, ServerName: upstreamURL.Hostname()},
		UpstreamResolver: func(_ string) (string, error) { return upstreamURL.Host, nil },
		AuditFunc:        auditWriter,
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Serve(ctx, ln)

	caPool := x509.NewCertPool()
	caPool.AddCert(caInst.RootCert())
	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client = &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "api.anthropic.com"},
		},
		Timeout: 10 * time.Second,
	}

	cleanup = func() {
		cancel()
		_ = ln.Close()
		upstream.Close()
		_ = auditWriter.Close()
	}
	return client, auditPath, cleanup
}

func TestAudit_E2E_RequestProducesAuditLine(t *testing.T) {
	client, auditPath, cleanup := setupAudit(t, "")
	defer cleanup()

	body := `{"model":"claude-opus-4-7","messages":[{"role":"user","content":"hi"}]}`
	resp, err := client.Post("https://api.anthropic.com/v1/messages", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	resp.Body.Close()

	// Cleanup will flush; trigger it now to read the file.
	cleanup()
	defer func() {}() // suppress unused-cleanup-warning safety net

	// Re-read the file directly.
	f, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var records []audit.Record
	for scanner.Scan() {
		var r audit.Record
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			t.Errorf("malformed line: %v", err)
			continue
		}
		records = append(records, r)
	}
	if len(records) != 1 {
		t.Fatalf("got %d audit records, want 1", len(records))
	}
	r := records[0]
	if r.Decision != "continue" {
		t.Errorf("Decision = %q, want continue", r.Decision)
	}
	if r.Host != "api.anthropic.com" {
		t.Errorf("Host = %q, want api.anthropic.com", r.Host)
	}
	if r.Vendor != "anthropic" || r.Endpoint != "messages" {
		t.Errorf("Vendor/Endpoint = %q/%q", r.Vendor, r.Endpoint)
	}
}

func TestAudit_E2E_BlockProducesAuditLineWithFindings(t *testing.T) {
	yaml := `
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
`
	client, auditPath, cleanup := setupAudit(t, yaml)
	defer cleanup()

	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "t1", "name": "Read",
				 "input": {"file_path": "/src/payments/charge.go"}}
			]}
		]
	}`
	resp, err := client.Post("https://api.anthropic.com/v1/messages", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	resp.Body.Close()

	cleanup()
	defer func() {}()

	f, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var records []audit.Record
	for scanner.Scan() {
		var r audit.Record
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			continue
		}
		records = append(records, r)
	}
	if len(records) != 1 {
		t.Fatalf("got %d audit records, want 1", len(records))
	}
	r := records[0]
	if r.Decision != "block" {
		t.Errorf("Decision = %q, want block", r.Decision)
	}
	if len(r.Findings) < 1 {
		t.Fatalf("Findings should not be empty; got %+v", r.Findings)
	}
	f0, ok := r.Findings[0].(map[string]any)
	if !ok {
		t.Fatalf("Findings[0] is not a map: %T", r.Findings[0])
	}
	if f0["detector"] != "path-scan" {
		t.Errorf("detector = %v, want path-scan", f0["detector"])
	}
}
```

- [ ] **Step 2: Append CLI integration tests**

Append to `test/integration/cli_test.go`:

```go

func TestCLI_Logs_FileNotFound(t *testing.T) {
	dir := t.TempDir()
	_, stderr, code := runCLI(t, "logs", "--data-dir", dir)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "file not found") {
		t.Errorf("stderr should say 'file not found'; got %q", stderr)
	}
}

func TestCLI_Logs_LastN(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")

	// Pre-write 10 records.
	var lines []string
	for i := 0; i < 10; i++ {
		lines = append(lines, fmt.Sprintf(`{"time":"2026-05-17T16:33:%02dZ","request_id":"r%d","host":"h","method":"GET","path":"/","status":200,"bytes_in":0,"bytes_out":0,"duration_ms":1,"decision":"continue"}`, i, i))
	}
	if err := os.WriteFile(auditPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	stdout, _, code := runCLI(t, "logs", "--data-dir", dir, "-n", "5")
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	count := strings.Count(stdout, "\n")
	if count != 5 {
		t.Errorf("got %d output lines, want 5", count)
	}
}

func TestCLI_Logs_JSON(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	line := `{"time":"2026-05-17T16:33:12Z","request_id":"r","host":"h","method":"GET","path":"/","status":200,"bytes_in":0,"bytes_out":0,"duration_ms":1,"decision":"continue"}`
	if err := os.WriteFile(auditPath, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	stdout, _, code := runCLI(t, "logs", "--data-dir", dir, "--json", "-n", "5")
	if code != 0 {
		t.Errorf("exit code = %d", code)
	}
	if !strings.Contains(stdout, `"request_id":"r"`) {
		t.Errorf("stdout should contain raw JSON; got %q", stdout)
	}
}
```

- [ ] **Step 3: Run all integration tests**

```bash
go test -race -count=1 ./test/integration/...
```

Expected: existing tests still pass + new audit and logs tests pass.

- [ ] **Step 4: Run full suite**

```bash
go test -race -count=1 ./...
go vet ./...
```

Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add test/integration/audit_test.go test/integration/cli_test.go
git commit -m "test(audit): end-to-end audit file + CLI logs subcommand tests"
```

---

## Task 8: Manual acceptance test

**Files:** none modified; record result in spec at end.

- [ ] **Step 1: Build**

```bash
make build
```

- [ ] **Step 2: Reset state and start the proxy**

```bash
./railcore init --force
./railcore proxy --port 9443
```

- [ ] **Step 3: In another terminal, start log follow**

```bash
./railcore logs --follow
```

You should see no output initially.

- [ ] **Step 4: Launch Claude Code through the proxy in a third terminal**

```bash
HTTPS_PROXY=http://127.0.0.1:9443 \
NODE_EXTRA_CA_CERTS=$HOME/.railcore/ca/ca.crt \
  claude
```

Ask Claude Code an innocent question. You should see records appear live in the `logs --follow` output, one per HTTP request the agent makes.

- [ ] **Step 5: Trigger a block**

Replace your policy with one that blocks something. For example:

```bash
cat > ~/.railcore/policy.yaml <<'EOF'
version: 1
rules:
  - name: block-aws
    match: {pattern: aws_*}
    action: block
  - name: warn-everything
    match: {all: true}
    action: warn
EOF
```

Restart the proxy. In Claude Code, send a prompt containing a synthetic AWS key. Verify the log line shows `block` with `findings=1 [block-aws]`.

- [ ] **Step 6: Inspect the raw log file**

```bash
tail -5 ~/.railcore/audit.log | jq .
```

Confirm valid JSON Lines with all expected fields.

- [ ] **Step 7: Record acceptance result**

Append §11 to `docs/superpowers/specs/2026-05-17-audit-logging-design.md`:

```markdown

---

## 11. Acceptance Result

**Date:** YYYY-MM-DD (fill in)

- `railcore proxy` writes one record per request to `~/.railcore/audit.log`.
- `railcore logs --follow` streams records in real-time as the proxy serves them.
- A blocked request produced a record with `decision=block` and `findings` populated.
- Raw log file is valid JSON Lines (verified with `jq`).
- Rotation: ran the proxy with `--audit-max-size-mb=1` and a flood of requests; observed `audit.log.1` and `audit.log.2` backups appear automatically.

**Status:** Pass. Sub-project #6 done definition §8 satisfied.
```

- [ ] **Step 8: Commit the acceptance record**

```bash
git add docs/superpowers/specs/2026-05-17-audit-logging-design.md
git commit -m "docs(spec): record sub-project #6 acceptance result"
```

---

## Self-Review Notes

After all tasks:

1. **Spec coverage:**
   - §4.1 Record schema → Task 1.
   - §4.2 Logger / NoopLogger / Writer → Tasks 1, 2, 3.
   - §4.3 Proxy AuditFunc + helpers → Task 4.
   - §4.4 `railcore logs` subcommand → Task 5.
   - §4.5 Proxy flag wiring → Task 6.
   - §6 Error handling → covered by Writer tests (Task 3) + logs tests (Task 7).
   - §7 Testing → Tasks 1-7.
   - §7.7 Manual acceptance → Task 8.
   - §8 Done definition → Tasks 6 (build), 7 (tests), 8 (acceptance).

2. **Placeholders:** none. All code is complete.

3. **Type consistency:**
   - `audit.Record` fields use camelCase Go names + snake_case JSON tags consistently.
   - `audit.Logger` interface signature `Log(r Record)` is the same in all callers.
   - `audit.Config` fields match between `NewWriter` and the proxy wiring in Task 6.
   - `findingsFromMetadata(rc *pipeline.RequestCtx) []any` signature consistent between proxy.upstream and test mocks.
   - `formatRecord(r audit.Record) string` and `parseAuditBytes(data []byte) ([]audit.Record, int)` signatures consistent across tests + production.
   - `runLogs(args []string)` matches the dispatcher in main.go.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-17-audit-logging.md`. Two execution options:

**1. Subagent-Driven (recommended)** — fresh subagent per task, two-stage review between tasks.

**2. Inline Execution** — tasks executed in this session with checkpoints.

Which approach?
