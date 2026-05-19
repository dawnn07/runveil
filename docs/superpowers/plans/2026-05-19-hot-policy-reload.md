# Hot Policy Reload Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pick up policy file edits within ~250ms without restarting the proxy. Emit structured audit events on every reload attempt (accepted or rejected).

**Architecture:** New `policy.Provider` (atomic-pointer holder) replaces direct `*policy.Policy` in stage configs. New `policy.Watcher` (fsnotify-based, parent-dir watch, debounced) calls back into the proxy. Audit `Logger` interface grows an `Event(Event)` method for synthetic non-request records; `Writer` reuses its existing async-channel for events. Proxy startup constructs Provider + Watcher and wires the watcher's callbacks to atomically swap the policy and emit reload events.

**Tech Stack:** Go 1.25 stdlib (`sync/atomic.Pointer`, `log/slog`, `os`, `time`, `context`) + new dep `github.com/fsnotify/fsnotify`. Existing internal packages unchanged in shape; signatures change in `internal/stage/pathscan`, `internal/stage/secretscan`, `internal/audit`, `cmd/railcore`.

**Spec:** [`docs/superpowers/specs/2026-05-19-hot-policy-reload-design.md`](../specs/2026-05-19-hot-policy-reload-design.md)

---

## File Map

| File | Purpose |
|---|---|
| `internal/policy/provider.go` | **Create:** `Provider` (atomic-pointer wrapper) |
| `internal/policy/provider_test.go` | **Create:** 3 tests |
| `internal/policy/policy.go` | **Modify:** add `RuleCount()` method |
| `internal/policy/policy_test.go` | **Modify:** append RuleCount test |
| `internal/policy/watcher.go` | **Create:** fsnotify-based Watcher |
| `internal/policy/watcher_test.go` | **Create:** 6 tests |
| `internal/audit/audit.go` | **Modify:** add `Event` type + `Logger.Event(Event)` method; `NoopLogger.Event` |
| `internal/audit/audit_test.go` | **Modify:** append 3 tests |
| `internal/audit/writer.go` | **Modify:** implement `Writer.Event` |
| `internal/audit/writer_test.go` | **Modify:** append 1 test |
| `internal/stage/pathscan/stage.go` | **Modify:** `Config.Policy` → `Config.Policies *policy.Provider`; per-request snapshot |
| `internal/stage/pathscan/stage_test.go` | **Modify:** update 6 fixtures + 1 new live-swap test |
| `internal/stage/secretscan/stage.go` | **Modify:** same shape change |
| `internal/stage/secretscan/stage_test.go` | **Modify:** update 4 fixtures + 1 new live-swap test |
| `internal/proxy/server_test.go` | **Modify:** captureAudit fixture gains `Event` method |
| `cmd/railcore/proxy.go` | **Modify:** construct Provider + Watcher; pass Provider to stages |
| `cmd/railcore/logs.go` | **Modify:** dispatch raw JSON line on `kind` field; add `formatEvent` |
| `cmd/railcore/logs_test.go` | **Modify:** append 2 formatEvent tests |
| `test/integration/policy_test.go` | **Modify:** Config{Policy:} → Config{Policies:} (1 site) |
| `test/integration/pathscan_test.go` | **Modify:** same (1 site) |
| `test/integration/audit_test.go` | **Modify:** same (1 site) + captureAudit fixture |
| `test/integration/cursor_test.go` | **Modify:** same (1 site) |
| `test/integration/hot_reload_test.go` | **Create:** end-to-end |
| `go.mod`, `go.sum` | **Modify:** add `github.com/fsnotify/fsnotify` |
| `docs/superpowers/specs/2026-05-19-hot-policy-reload-design.md` | **Modify (Task 9 only):** append §11 Acceptance Result |

**No new cross-package internal edges except**:
- `internal/stage/{pathscan,secretscan} → internal/policy.Provider` (replaces `*policy.Policy` field).

`internal/policy/` remains a leaf — stdlib + `gopkg.in/yaml.v3` + new `github.com/fsnotify/fsnotify`. No internal imports.

---

## Task 1: `policy.Provider` + `Policy.RuleCount()`

**Files:**
- Create: `internal/policy/provider.go`
- Create: `internal/policy/provider_test.go`
- Modify: `internal/policy/policy.go` (add method)
- Modify: `internal/policy/policy_test.go` (append test)

- [ ] **Step 1: Write the failing tests — create `internal/policy/provider_test.go`**

```go
package policy

import (
	"sync"
	"testing"
)

func TestProvider_GetReturnsStoredPointer(t *testing.T) {
	p := &Policy{Version: 1}
	pr := NewProvider(p)
	got := pr.Get()
	if got != p {
		t.Errorf("Get() = %v, want %v", got, p)
	}
}

func TestProvider_NilSafe(t *testing.T) {
	pr := NewProvider(nil)
	if pr.Get() != nil {
		t.Errorf("Get() on nil Provider must return nil")
	}
}

func TestProvider_SetSwapsAtomically(t *testing.T) {
	// 100 reader goroutines doing Get(); one writer goroutine doing
	// Set() in a tight loop. With -race, this must not flag.
	pr := NewProvider(&Policy{Version: 1})

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = pr.Get()
				}
			}
		}()
	}

	for i := 0; i < 1000; i++ {
		pr.Set(&Policy{Version: i + 2})
	}
	close(stop)
	wg.Wait()
}
```

- [ ] **Step 2: Append the failing RuleCount test to `internal/policy/policy_test.go`**

```go

func TestPolicy_RuleCount(t *testing.T) {
	cases := []struct {
		name string
		p    *Policy
		want int
	}{
		{"nil", nil, 0},
		{"empty", &Policy{}, 0},
		{"three rules", &Policy{Rules: make([]Rule, 3)}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.RuleCount(); got != tc.want {
				t.Errorf("RuleCount = %d, want %d", got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 3: Confirm compile failure**

```bash
go test ./internal/policy/...
```

Expected: `undefined: NewProvider`, `undefined: (*Policy).RuleCount`.

- [ ] **Step 4: Create `internal/policy/provider.go`**

```go
package policy

import "sync/atomic"

// Provider holds the active *Policy and serves wait-free reads to
// every request handler. Updates from the Watcher are atomic.
//
// Safe for concurrent use. Reads via Get are wait-free
// (atomic.Pointer.Load); writes via Set are atomic.
type Provider struct {
	p atomic.Pointer[Policy]
}

// NewProvider returns a Provider holding the given initial policy.
// initial may be nil — Get on a nil-initialized Provider returns nil
// and stage code is expected to treat that as "no policy".
func NewProvider(initial *Policy) *Provider {
	pr := &Provider{}
	pr.p.Store(initial)
	return pr
}

// Get returns the currently-active policy. Wait-free.
func (pr *Provider) Get() *Policy { return pr.p.Load() }

// Set atomically swaps the active policy.
func (pr *Provider) Set(np *Policy) { pr.p.Store(np) }
```

- [ ] **Step 5: Add `RuleCount` to `internal/policy/policy.go`**

Find the existing `Policy` struct (around line 65). After its existing methods (after `Decide` and any other methods on Policy), add:

```go

// RuleCount returns the number of rules in this policy. Nil-safe.
func (p *Policy) RuleCount() int {
	if p == nil {
		return 0
	}
	return len(p.Rules)
}
```

- [ ] **Step 6: Run tests**

```bash
go test -race -count=1 ./internal/policy/...
go vet ./...
gofmt -l internal/policy/
```

All clean. Expected: 4 new test cases pass (3 Provider + 1 RuleCount table-driven with 3 sub-cases).

- [ ] **Step 7: Commit**

```bash
git add internal/policy/provider.go internal/policy/provider_test.go \
        internal/policy/policy.go internal/policy/policy_test.go
git -c user.email=haidangdavid123@gmail.com -c user.name=dawn commit -m "feat(policy): Provider atomic-pointer holder + Policy.RuleCount()"
```

No Co-Authored-By.

---

## Task 2: Audit `Event` type + `Logger.Event` interface method

**Files:**
- Modify: `internal/audit/audit.go`
- Modify: `internal/audit/audit_test.go`

- [ ] **Step 1: Append failing tests to `internal/audit/audit_test.go`**

```go

func TestEvent_MarshalJSON_AllFields(t *testing.T) {
	e := Event{
		Time:        time.Date(2026, 5, 19, 10, 1, 23, 0, time.UTC),
		Kind:        "policy_reload",
		PolicyPath:  "/home/dawn/.railcore/policy.yaml",
		Outcome:     "accepted",
		RulesBefore: 2,
		RulesAfter:  3,
	}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(data)
	for _, want := range []string{
		`"time":"2026-05-19T10:01:23Z"`,
		`"kind":"policy_reload"`,
		`"policy_path":"/home/dawn/.railcore/policy.yaml"`,
		`"outcome":"accepted"`,
		`"rules_before":2`,
		`"rules_after":3`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}

func TestEvent_MarshalJSON_OmitsEmptyOptionals(t *testing.T) {
	e := Event{
		Time: time.Now(),
		Kind: "policy_reload",
	}
	data, _ := json.Marshal(e)
	s := string(data)
	for _, absent := range []string{
		`"policy_path"`,
		`"outcome"`,
		`"rules_before"`,
		`"rules_after"`,
		`"error"`,
	} {
		if strings.Contains(s, absent) {
			t.Errorf("field %s should be omitted when empty; got %s", absent, s)
		}
	}
}

func TestNoopLogger_EventIsSafe(t *testing.T) {
	var l Logger = NoopLogger{}
	for i := 0; i < 5; i++ {
		l.Event(Event{Kind: "policy_reload"})
	}
}
```

- [ ] **Step 2: Confirm compile failure**

```bash
go test ./internal/audit/...
```

Expected: `undefined: Event`, `(Logger).Event` not satisfied by NoopLogger.

- [ ] **Step 3: Add the `Event` type and extend the `Logger` interface in `internal/audit/audit.go`**

Find the existing `Logger` interface and `NoopLogger` block. Replace with:

```go
// Logger is the consumer-facing interface. Proxy holds a Logger (never
// a concrete *Writer) so tests can inject capturing or no-op
// implementations.
//
// Log emits one per-request record. Event emits one synthetic record
// (e.g., a policy reload notification). Both are async — implementations
// are free to drop on backpressure.
type Logger interface {
	Log(r Record)
	Event(e Event)
}

// NoopLogger discards records. Used as the default when no audit
// destination is configured.
type NoopLogger struct{}

// Log implements Logger by doing nothing.
func (NoopLogger) Log(_ Record) {}

// Event implements Logger by doing nothing.
func (NoopLogger) Event(_ Event) {}
```

Add the `Event` type after `Record`:

```go

// Event is a synthetic (non-request) audit record. Currently used for
// policy reload notifications. Future synthetic event kinds reuse this
// shape with a different Kind value.
//
// Wire format (JSON tags):
//   time          RFC3339Nano UTC
//   kind          event discriminator (e.g., "policy_reload")
//   policy_path   absolute path that triggered the event (omitempty)
//   outcome       "accepted" | "rejected" (omitempty)
//   rules_before  rule count of the policy that was active before
//                 (omitempty when zero)
//   rules_after   rule count after a successful reload (omitempty when
//                 zero — also omitted on rejection)
//   error         the validation error string (omitempty — only set on
//                 rejection)
type Event struct {
	Time        time.Time `json:"time"`
	Kind        string    `json:"kind"`
	PolicyPath  string    `json:"policy_path,omitempty"`
	Outcome     string    `json:"outcome,omitempty"`
	RulesBefore int       `json:"rules_before,omitempty"`
	RulesAfter  int       `json:"rules_after,omitempty"`
	Error       string    `json:"error,omitempty"`
}
```

- [ ] **Step 4: Run tests**

```bash
go test -race -count=1 ./internal/audit/...
go vet ./...
gofmt -l internal/audit/
```

The audit package compiles + new tests pass. Other packages that implement Logger will FAIL to compile — that's Task 3's job.

Expected: audit tests green, but `go build ./...` likely fails downstream (e.g., `captureAudit` in `internal/proxy/server_test.go`, `test/integration/audit_test.go`). That's OK for this commit's scope; Task 3 will land the captureAudit `Event` method together with Writer.Event.

- [ ] **Step 5: Defer commit to end of Task 3** (Tasks 2+3 form one compile-unit)

---

## Task 3: `Writer.Event` + downstream Logger implementations

**Files:**
- Modify: `internal/audit/writer.go`
- Modify: `internal/audit/writer_test.go`
- Modify: `internal/proxy/server_test.go` (captureAudit fixture)
- Modify: `test/integration/audit_test.go` (captureAudit if used; verify first)

- [ ] **Step 1: Inspect current Writer + captureAudit shapes**

```bash
grep -n "captureAudit\|func.*Writer.*Log\|type Writer" internal/audit/writer.go internal/proxy/server_test.go test/integration/audit_test.go | head -20
```

Note where `captureAudit` is defined and what fields it has. `internal/proxy/server_test.go` defines `captureAudit` (Task 4 from sub-project #6). Look at the existing `Log` implementation to mirror it for `Event`.

- [ ] **Step 2: Append failing test to `internal/audit/writer_test.go`**

```go

func TestWriter_LogsEventToFile(t *testing.T) {
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
	w.Event(Event{
		Time:        time.Date(2026, 5, 19, 10, 1, 23, 0, time.UTC),
		Kind:        "policy_reload",
		PolicyPath:  "/x",
		Outcome:     "accepted",
		RulesBefore: 2,
		RulesAfter:  3,
	})
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	s := string(data)
	for _, want := range []string{
		`"kind":"policy_reload"`,
		`"policy_path":"/x"`,
		`"outcome":"accepted"`,
		`"rules_before":2`,
		`"rules_after":3`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in file:\n%s", want, s)
		}
	}
}
```

Add `"strings"` to the imports if not already present.

- [ ] **Step 3: Implement `Writer.Event` in `internal/audit/writer.go`**

The current Writer uses a single channel `ch chan Record`. We have two reasonable patterns:

**Pattern A (recommended):** Add a second channel `evCh chan Event` and select on both in the `run` goroutine.

**Pattern B:** Wrap both Record and Event in a `union` struct, keep one channel.

Going with **A** — keeps the wire-format-to-channel mapping simple and the existing Record path 100% unchanged.

Update the `Writer` struct:

```go
type Writer struct {
	logger    *slog.Logger
	ch        chan Record
	evCh      chan Event              // NEW
	wg        sync.WaitGroup
	lj        *lumberjack.Logger
	closed    atomic.Bool
	closeOnce sync.Once
	done      chan struct{}
}
```

In `NewWriter`, initialize `evCh: make(chan Event, cfg.BufferSize)` alongside the existing channel allocation.

Add the new `Event` method (right after `Log`):

```go
// Event implements Logger. Non-blocking: drops the event (with a WARN
// to the slog logger) if the channel is full. Safe to call after Close.
func (w *Writer) Event(e Event) {
	if w == nil || w.closed.Load() {
		return
	}
	select {
	case w.evCh <- e:
	default:
		w.logger.Warn("audit event channel full; dropping event",
			"kind", e.Kind)
	}
}
```

Update the `run` goroutine to select on BOTH channels and drain on done:

```go
func (w *Writer) run() {
	defer w.wg.Done()
	var buf bytes.Buffer
	for {
		select {
		case r := <-w.ch:
			w.writeRecord(&buf, r)
		case e := <-w.evCh:
			w.writeEvent(&buf, e)
		case <-w.done:
			// Drain both channels non-blocking.
			for {
				select {
				case r := <-w.ch:
					w.writeRecord(&buf, r)
				case e := <-w.evCh:
					w.writeEvent(&buf, e)
				default:
					return
				}
			}
		}
	}
}

// writeEvent marshals an Event and writes it via lumberjack. Same
// shape as writeRecord but using the Event type. Errors are logged
// and the event dropped — the writer survives.
func (w *Writer) writeEvent(buf *bytes.Buffer, e Event) {
	buf.Reset()
	if err := json.NewEncoder(buf).Encode(e); err != nil {
		w.logger.Error("audit: marshal event", "kind", e.Kind, "err", err.Error())
		return
	}
	if _, err := w.lj.Write(buf.Bytes()); err != nil {
		w.logger.Error("audit: write event", "err", err.Error())
	}
}
```

(`writeRecord` already exists from sub-project #6's race fix — keep it as-is.)

- [ ] **Step 4: Update `captureAudit` in `internal/proxy/server_test.go`**

Find the `captureAudit` type (sub-project #6, in proxy/server_test.go). Add an `Event` method:

```go
func (c *captureAudit) Event(_ audit.Event) {
	// Tests don't assert on events; no-op satisfies the Logger interface.
}
```

- [ ] **Step 5: Update any other Logger implementers**

```bash
grep -rn "func.*captureAudit.*Log\b\|type captureAudit\|captureAudit{}" --include="*.go" .
```

For each captureAudit (or similar test fixture) found in another file, add the same no-op `Event` method.

Likely sites: `test/integration/audit_test.go` may define its own captureAudit or use the writer directly. Verify.

- [ ] **Step 6: Run tests**

```bash
go test -race -count=1 ./...
go vet ./...
gofmt -l internal/audit/ internal/proxy/ test/integration/
```

All green.

- [ ] **Step 7: Commit Tasks 2 + 3 together**

```bash
git add internal/audit/audit.go internal/audit/audit_test.go \
        internal/audit/writer.go internal/audit/writer_test.go \
        internal/proxy/server_test.go
# Add other test files only if you modified them in Step 5.
git -c user.email=haidangdavid123@gmail.com -c user.name=dawn commit -m "feat(audit): Event type + Logger.Event method for synthetic events"
```

No Co-Authored-By.

---

## Task 4: `policy.Watcher` (fsnotify + debounce)

**Files:**
- Create: `internal/policy/watcher.go`
- Create: `internal/policy/watcher_test.go`
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Add fsnotify dependency**

```bash
go get github.com/fsnotify/fsnotify@latest
go mod tidy
```

- [ ] **Step 2: Create the failing tests at `internal/policy/watcher_test.go`**

```go
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

	// Trigger a write event.
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

	accepted := make(chan struct{}, 8) // generous buffer
	newTestWatcher(t, path,
		func(_ *Policy) { accepted <- struct{}{} },
		func(err error, _ []byte) { t.Errorf("unexpected reject: %v", err) },
	)

	// 5 rapid writes within ~50ms.
	for i := 0; i < 5; i++ {
		mustWriteFile(t, path, validYAML2)
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for the debounce window + slack.
	time.Sleep(500 * time.Millisecond)

	// Count callbacks: should be 1 (debounced).
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

	// Write to a tmp file then atomically rename — the vim/save pattern.
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
```

- [ ] **Step 3: Confirm compile failure**

```bash
go test ./internal/policy/...
```

Expected: `undefined: NewWatcher, Watcher`.

- [ ] **Step 4: Create `internal/policy/watcher.go`**

```go
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
		// Treat missing file as "no change" (file may have been deleted
		// before we got here; we'll see it again when re-created).
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
```

- [ ] **Step 5: Run tests**

```bash
go test -race -count=1 ./internal/policy/...
go vet ./...
gofmt -l internal/policy/
```

Expected: 6 new watcher tests + 4 Provider/RuleCount tests + existing policy tests all pass.

- [ ] **Step 6: Commit**

```bash
git add internal/policy/watcher.go internal/policy/watcher_test.go go.mod go.sum
git -c user.email=haidangdavid123@gmail.com -c user.name=dawn commit -m "feat(policy): Watcher (fsnotify-based, debounced, atomic-rename safe)"
```

No Co-Authored-By.

---

## Task 5: Stage Config switch — `*Policy` → `*Provider`

**Files:**
- Modify: `internal/stage/pathscan/stage.go`
- Modify: `internal/stage/pathscan/stage_test.go`
- Modify: `internal/stage/secretscan/stage.go`
- Modify: `internal/stage/secretscan/stage_test.go`
- Modify: `cmd/railcore/proxy.go` (one-line — wrap policy in NewProvider)
- Modify: `test/integration/policy_test.go`
- Modify: `test/integration/pathscan_test.go`
- Modify: `test/integration/audit_test.go`
- Modify: `test/integration/cursor_test.go`

This is a single atomic commit — the field rename breaks every call site simultaneously.

- [ ] **Step 1: Update `internal/stage/pathscan/stage.go`**

Find the `Config` struct (around line 18):

```go
type Config struct {
	// Policy drives all decisions. When nil, the stage is a silent no-op.
	Policy *policy.Policy
}
```

Replace with:

```go
type Config struct {
	// Policies serves the active policy via wait-free atomic reads.
	// When nil or Get() returns nil, the stage is a silent no-op.
	Policies *policy.Provider
}
```

Then find every read of `s.cfg.Policy` and replace with a per-request snapshot. The Run method currently has lines like:

```go
if s.cfg.Policy == nil {
	return pipeline.Continue, nil
}
// ...
action, rule := s.cfg.Policy.DecidePath(e.Path)
```

Replace with:

```go
pol := s.cfg.Policies.Get()
if pol == nil {
	return pipeline.Continue, nil
}
// ...
action, rule := pol.DecidePath(e.Path)
```

(Capture `pol` once at the top of Run, use it for the rest of the function.)

Also handle the nil `Policies` case: if `s.cfg.Policies == nil`, treat as silent no-op (same as `Get()==nil`):

```go
if s.cfg.Policies == nil {
	return pipeline.Continue, nil
}
pol := s.cfg.Policies.Get()
if pol == nil {
	return pipeline.Continue, nil
}
```

- [ ] **Step 2: Update `internal/stage/secretscan/stage.go` the same way**

Replace `Config.Policy *policy.Policy` with `Config.Policies *policy.Provider`. In the Run method, snapshot once:

```go
var pol *policy.Policy
if s.cfg.Policies != nil {
	pol = s.cfg.Policies.Get()
}
if pol != nil {
	return s.decideWithPolicy(rc, parsed, raw, pol)
}
// fall through to BlockOnDetect behavior
```

Update `decideWithPolicy` signature to take `*policy.Policy` as an explicit parameter (instead of reading `s.cfg.Policy` inside):

```go
func (s *Stage) decideWithPolicy(rc *pipeline.RequestCtx, parsed *parser.ParsedRequest, raw []byte, pol *policy.Policy) (pipeline.Decision, error) {
	// ...
	action, rule := pol.Decide(f.Finding)
	// (was: s.cfg.Policy.Decide(...))
}
```

- [ ] **Step 3: Update all 15 fixture call sites**

For each line in this list, change `Config{Policy: pol}` to `Config{Policies: policy.NewProvider(pol)}`:

- `internal/stage/pathscan/stage_test.go` — lines 51, 73, 93, 129, 154 (nil → `Policies: nil` is fine), 223, 262
- `internal/stage/secretscan/stage_test.go` — lines 183, 239, 269, 302
- `test/integration/policy_test.go:50`
- `test/integration/pathscan_test.go:50`
- `test/integration/audit_test.go:64`
- `test/integration/cursor_test.go:56`

Add `"railcore/internal/policy"` import to any test file that doesn't already have it (the integration tests already import policy; the stage tests may need it).

For `internal/stage/pathscan/stage_test.go:154` which has `New(Config{Policy: nil}, discardLogger())` — change to `New(Config{Policies: nil}, discardLogger())` (Policies field still nil).

- [ ] **Step 4: Update `cmd/railcore/proxy.go` line 86 and 87**

Find:

```go
chain.Register(pathscan.New(pathscan.Config{Policy: loadedPolicy}, logger))
chain.Register(secretscan.New(secretscan.Config{
	BlockOnDetect: effectiveBlock,
	Policy:        loadedPolicy,
}, logger))
```

Replace with:

```go
policies := policy.NewProvider(loadedPolicy)
chain.Register(pathscan.New(pathscan.Config{Policies: policies}, logger))
chain.Register(secretscan.New(secretscan.Config{
	BlockOnDetect: effectiveBlock,
	Policies:      policies,
}, logger))
```

Keep the variable name `policies` — Task 6 will reuse it for the watcher hookup.

- [ ] **Step 5: Run tests**

```bash
go test -race -count=1 ./...
go vet ./...
gofmt -l ./...
```

All clean. Expected: ~301 total tests pass (existing 277 + 4 Provider/RuleCount + 6 Watcher + 3 Event/NoopLogger + 1 Writer.Event + 7 watcher_test = ~298 actually; +1 fixture sweep is internal cleanup that may not add tests).

- [ ] **Step 6: Commit**

```bash
git add internal/stage/pathscan/stage.go internal/stage/pathscan/stage_test.go \
        internal/stage/secretscan/stage.go internal/stage/secretscan/stage_test.go \
        cmd/railcore/proxy.go \
        test/integration/policy_test.go test/integration/pathscan_test.go \
        test/integration/audit_test.go test/integration/cursor_test.go
git -c user.email=haidangdavid123@gmail.com -c user.name=dawn commit -m "refactor(stage): Config.Policy → Config.Policies *policy.Provider"
```

No Co-Authored-By.

---

## Task 6: Live-swap stage tests

**Files:**
- Modify: `internal/stage/pathscan/stage_test.go` (append one test)
- Modify: `internal/stage/secretscan/stage_test.go` (append one test)

- [ ] **Step 1: Append `TestStage_LiveSwapPicksUpNewPolicy` to `internal/stage/pathscan/stage_test.go`**

```go

func TestStage_LiveSwapPicksUpNewPolicy(t *testing.T) {
	allowPolicy := mustParsePolicy(t, `
version: 1
rules:
  - name: warn-all
    match: {all: true}
    action: warn
`)
	blockPolicy := mustParsePolicy(t, `
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
`)

	provider := policy.NewProvider(allowPolicy)
	s := New(Config{Policies: provider}, discardLogger())

	body := []byte(`{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "name": "Read", "id": "x",
				 "input": {"file_path": "/src/payments/charge.go"}}
			]}
		]
	}`)
	rc := newRCWithBody(t, "api.anthropic.com", "/v1/messages", body)

	dec, _ := s.Run(context.Background(), rc)
	if dec != pipeline.Continue {
		t.Errorf("first Run with allow policy: dec = %v, want Continue", dec)
	}

	// Live swap.
	provider.Set(blockPolicy)

	rc2 := newRCWithBody(t, "api.anthropic.com", "/v1/messages", body)
	dec2, _ := s.Run(context.Background(), rc2)
	if dec2 != pipeline.Block {
		t.Errorf("second Run with block policy: dec = %v, want Block", dec2)
	}
}
```

If `mustParsePolicy` or `newRCWithBody` aren't already defined as test helpers in the file, look for the equivalent existing test helper pattern and use that. Common helpers in this codebase: `mustParse`, `mkPolicy`. Check `stage_test.go` for the actual helper names and use them.

- [ ] **Step 2: Append the symmetric test to `internal/stage/secretscan/stage_test.go`**

```go

func TestStage_LiveSwapPicksUpNewPolicy(t *testing.T) {
	warnPolicy := mkPolicy(t, `
version: 1
rules:
  - name: warn-aws
    match: {pattern: aws_*}
    action: warn
`)
	blockPolicy := mkPolicy(t, `
version: 1
rules:
  - name: block-aws
    match: {pattern: aws_*}
    action: block
`)

	provider := policy.NewProvider(warnPolicy)
	s := New(Config{Policies: provider}, discardLogger())

	body := []byte(`{
		"messages": [
			{"role": "user", "content": "my key is aws_AKIAIOSFODNN7EXAMPLE"}
		]
	}`)
	rc := newRCAnthropic(t, body)

	dec, _ := s.Run(context.Background(), rc)
	if dec != pipeline.Continue {
		t.Errorf("warn policy: dec = %v, want Continue", dec)
	}

	provider.Set(blockPolicy)

	rc2 := newRCAnthropic(t, body)
	dec2, _ := s.Run(context.Background(), rc2)
	if dec2 != pipeline.Block {
		t.Errorf("block policy: dec = %v, want Block", dec2)
	}
}
```

Use the existing helper names from `secretscan/stage_test.go`. If `mkPolicy` is the existing helper, use it. If `newRCAnthropic` doesn't exist, find the equivalent in the file and use that.

- [ ] **Step 3: Run tests**

```bash
go test -race -count=1 ./internal/stage/...
go vet ./...
```

Both new tests pass.

- [ ] **Step 4: Commit**

```bash
git add internal/stage/pathscan/stage_test.go internal/stage/secretscan/stage_test.go
git -c user.email=haidangdavid123@gmail.com -c user.name=dawn commit -m "test(stage): live policy swap reflected on next request"
```

No Co-Authored-By.

---

## Task 7: Proxy startup wiring — Provider + Watcher + audit Event

**Files:**
- Modify: `cmd/railcore/proxy.go`

- [ ] **Step 1: Open `cmd/railcore/proxy.go` and review the current shape**

```bash
sed -n '1,130p' cmd/railcore/proxy.go
```

After Task 5, the file already has:
- `policies := policy.NewProvider(loadedPolicy)` (around line 86)
- Both stages receive `Policies: policies`

This task ADDS the watcher between the provider creation and the stage registration.

- [ ] **Step 2: Insert the watcher block in `cmd/railcore/proxy.go`**

Find the line `policies := policy.NewProvider(loadedPolicy)` (added in Task 5). Immediately after it, before `chain.Register(...)`, insert:

```go
	// Hot reload: watch the resolved policy file. If no policy was
	// loaded at startup (resolvedPath==""), skip — there's nothing to
	// watch and reload will need a restart anyway.
	if resolvedPath != "" {
		watcher, err := policy.NewWatcher(resolvedPath, logger,
			func(np *policy.Policy) {
				before := policies.Get().RuleCount()
				policies.Set(np)
				auditLogger.Event(audit.Event{
					Time:        time.Now(),
					Kind:        "policy_reload",
					PolicyPath:  resolvedPath,
					Outcome:     "accepted",
					RulesBefore: before,
					RulesAfter:  np.RuleCount(),
				})
				logger.Info("policy reloaded",
					"path", resolvedPath,
					"rules_before", before,
					"rules_after", np.RuleCount())
			},
			func(rerr error, _ []byte) {
				before := policies.Get().RuleCount()
				auditLogger.Event(audit.Event{
					Time:        time.Now(),
					Kind:        "policy_reload",
					PolicyPath:  resolvedPath,
					Outcome:     "rejected",
					RulesBefore: before,
					Error:       rerr.Error(),
				})
				logger.Warn("policy reload rejected",
					"path", resolvedPath,
					"err", rerr.Error())
			},
		)
		if err != nil {
			logger.Error("policy watcher init failed", "err", err.Error())
			os.Exit(1)
		}
		if err := watcher.Start(ctx); err != nil {
			logger.Error("policy watcher start failed", "err", err.Error())
			os.Exit(1)
		}
		defer func() { _ = watcher.Close() }()
	}
```

This block uses `ctx`. The current proxy.go creates `ctx` via `signal.NotifyContext(...)` AFTER the chain.Register lines. You'll need to MOVE that line up. Find:

```go
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer stop()
```

And move it to immediately AFTER `policies := policy.NewProvider(...)`. Then the watcher block above can use `ctx`.

- [ ] **Step 3: Confirm imports**

Verify `cmd/railcore/proxy.go` imports `"time"` and `"railcore/internal/audit"`. Both should already be present (time from existing code, audit from sub-project #6's Task 6 work). If either is missing, add it.

- [ ] **Step 4: Build and smoke-test**

```bash
go build -o /tmp/railcore-sp8 ./cmd/railcore
```

Then:

```bash
mkdir -p /tmp/railcore-sp8-data
/tmp/railcore-sp8 init --data-dir /tmp/railcore-sp8-data --force >/dev/null 2>&1
/tmp/railcore-sp8 proxy --port 19444 --data-dir /tmp/railcore-sp8-data > /tmp/railcore-sp8-data/proxy.log 2>&1 &
SP=$!
sleep 1

# Modify the policy file:
cat > /tmp/railcore-sp8-data/policy.yaml <<'EOF'
version: 1
rules:
  - name: block-aws
    match: {pattern: aws_*}
    action: block
  - name: default-warn
    match: {all: true}
    action: warn
EOF
sleep 1

kill $SP 2>/dev/null
wait 2>/dev/null

# Verify the audit log contains a policy_reload event:
grep '"kind":"policy_reload"' /tmp/railcore-sp8-data/audit.log && echo "(reload event recorded)"

rm -rf /tmp/railcore-sp8-data /tmp/railcore-sp8
```

Expected output: at least one `"kind":"policy_reload"` line, plus `(reload event recorded)`.

- [ ] **Step 5: Run full test suite**

```bash
go test -race -count=1 ./...
go vet ./...
gofmt -l cmd/railcore/
```

All clean.

- [ ] **Step 6: Commit**

```bash
git add cmd/railcore/proxy.go
git -c user.email=haidangdavid123@gmail.com -c user.name=dawn commit -m "feat(cli): wire policy.Watcher into proxy startup with audit events"
```

No Co-Authored-By.

---

## Task 8: `railcore logs` Event rendering

**Files:**
- Modify: `cmd/railcore/logs.go`
- Modify: `cmd/railcore/logs_test.go`

- [ ] **Step 1: Append failing tests to `cmd/railcore/logs_test.go`**

```go

func TestFormatEvent_PolicyReloadAccepted(t *testing.T) {
	line := []byte(`{"time":"2026-05-19T10:01:23Z","kind":"policy_reload","policy_path":"/x/policy.yaml","outcome":"accepted","rules_before":2,"rules_after":3}`)
	got := formatEvent(line)
	for _, want := range []string{"10:01:23", "⟳", "policy_reload", "/x/policy.yaml", "accepted", "2→3 rules"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestFormatEvent_PolicyReloadRejected(t *testing.T) {
	line := []byte(`{"time":"2026-05-19T10:01:45Z","kind":"policy_reload","policy_path":"/x/policy.yaml","outcome":"rejected","rules_before":3,"error":"bad glob"}`)
	got := formatEvent(line)
	for _, want := range []string{"⚠", "rejected", "rules_before=3", "err='bad glob'"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}
```

- [ ] **Step 2: Add an event-routing helper to `cmd/railcore/logs.go`**

Find the existing `emit(r audit.Record, jsonOut bool)` function. Refactor the caller (the part that reads from the audit file line-by-line) so it dispatches on the `kind` field.

Add a helper that peeks at the JSON line:

```go

// lineIsEvent returns true if the raw JSONL line carries a non-empty
// "kind" field (i.e., is an audit.Event, not an audit.Record).
func lineIsEvent(raw []byte) bool {
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	return probe.Kind != ""
}
```

Then in `parseAuditBytes` (or wherever lines get parsed for the initial tail), update emit to dispatch:

```go
func emitLine(raw []byte, jsonOut bool) {
	if jsonOut {
		os.Stdout.Write(raw)
		os.Stdout.Write([]byte("\n"))
		return
	}
	if lineIsEvent(raw) {
		fmt.Println(formatEvent(raw))
		return
	}
	var r audit.Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return
	}
	fmt.Println(formatRecord(r))
}

// formatEvent renders a synthetic audit.Event line. Currently only
// kind="policy_reload" is rendered specifically; other kinds get a
// generic fallback.
func formatEvent(raw []byte) string {
	var e audit.Event
	if err := json.Unmarshal(raw, &e); err != nil {
		return ""
	}
	if e.Kind != "policy_reload" {
		return fmt.Sprintf("%s  %s  %s", e.Time.Format("15:04:05"), e.Kind, e.PolicyPath)
	}
	hhmmss := e.Time.Format("15:04:05")
	if e.Outcome == "accepted" {
		return fmt.Sprintf("%s  ⟳  policy_reload  %s  accepted  %d→%d rules",
			hhmmss, e.PolicyPath, e.RulesBefore, e.RulesAfter)
	}
	return fmt.Sprintf("%s  ⚠  policy_reload  %s  rejected  rules_before=%d  err='%s'",
		hhmmss, e.PolicyPath, e.RulesBefore, e.Error)
}
```

The existing `parseAuditBytes` returns `[]audit.Record`. We need it to handle Event lines too. Two options:

**Pattern A (recommended):** Leave `parseAuditBytes` alone for the initial tail-and-render path and replace its callers to use the raw-line dispatcher. Add a new helper:

```go
// parseAuditLines splits the input into newline-separated raw JSON
// lines, skipping empties and tracking malformed counts. Each line is
// returned as-is; the caller dispatches.
func parseAuditLines(data []byte) (lines [][]byte, skipped int) {
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		// Cheap validity check: must be a JSON object starting with '{'.
		if line[0] != '{' {
			skipped++
			continue
		}
		lines = append(lines, line)
	}
	return lines, skipped
}
```

Update `runLogs` to use `parseAuditLines` + `emitLine` instead of `parseAuditBytes` + `emit` for the initial tail. The follow-mode scanner already iterates line-by-line; switch it to call `emitLine` directly.

`parseAuditBytes` stays in the file for backward-compat with the existing `TestParseAuditFile_SkipsMalformed` test — it can keep its current behavior since it's already there and tested. (Or move that test to assert on `parseAuditLines` and delete `parseAuditBytes`.)

For simplicity in this task, keep both helpers. Future cleanup can consolidate.

- [ ] **Step 3: Run tests**

```bash
go test -race -count=1 ./cmd/railcore/...
go vet ./...
gofmt -l cmd/railcore/
```

All clean. New formatEvent tests pass.

- [ ] **Step 4: Commit**

```bash
git add cmd/railcore/logs.go cmd/railcore/logs_test.go
git -c user.email=haidangdavid123@gmail.com -c user.name=dawn commit -m "feat(cli): logs subcommand renders policy_reload events"
```

No Co-Authored-By.

---

## Task 9: End-to-end integration test

**Files:**
- Create: `test/integration/hot_reload_test.go`

- [ ] **Step 1: Create `test/integration/hot_reload_test.go`**

```go
// End-to-end test for sub-project #8: spin up a real proxy with a
// real policy file, modify the policy mid-flight, assert the next
// request reflects the new rules.
package integration

import (
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

func TestHotReload_E2E_PolicyChangeBlocksOnNextRequest(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.log")
	policyPath := filepath.Join(tmpDir, "policy.yaml")

	// Initial policy: warn-all only, no block.
	if err := os.WriteFile(policyPath, []byte(`
version: 1
rules:
  - name: default-warn
    match: {all: true}
    action: warn
`), 0o600); err != nil {
		t.Fatalf("write initial policy: %v", err)
	}

	auditWriter, err := audit.NewWriter(audit.Config{
		Path:       auditPath,
		MaxSizeMB:  10,
		MaxBackups: 1,
		MaxAgeDays: 1,
	}, nil)
	if err != nil {
		t.Fatalf("audit.NewWriter: %v", err)
	}
	t.Cleanup(func() { _ = auditWriter.Close() })

	caInst, err := ca.GenerateOrLoad(tmpDir + "/ca")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}

	initialPol, err := policy.LoadFromFile(policyPath)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	policies := policy.NewProvider(initialPol)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	watcher, err := policy.NewWatcher(policyPath, nil,
		func(np *policy.Policy) {
			before := policies.Get().RuleCount()
			policies.Set(np)
			auditWriter.Event(audit.Event{
				Time:        time.Now(),
				Kind:        "policy_reload",
				PolicyPath:  policyPath,
				Outcome:     "accepted",
				RulesBefore: before,
				RulesAfter:  np.RuleCount(),
			})
		},
		func(rerr error, _ []byte) {
			auditWriter.Event(audit.Event{
				Time:    time.Now(),
				Kind:    "policy_reload",
				Outcome: "rejected",
				Error:   rerr.Error(),
			})
		},
	)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	t.Cleanup(func() { _ = watcher.Close() })
	if err := watcher.Start(ctx); err != nil {
		t.Fatalf("watcher.Start: %v", err)
	}

	chain := pipeline.NewChain()
	chain.Register(pathscanstage.New(pathscanstage.Config{Policies: policies}, nil))

	srv := proxy.New(proxy.Config{
		Addr:             "127.0.0.1:0",
		CA:               caInst,
		Pipeline:         chain,
		AuditFunc:        auditWriter,
		UpstreamTLS:      &tls.Config{RootCAs: upstreamPool, ServerName: upstreamURL.Hostname()},
		UpstreamResolver: func(_ string) (string, error) { return upstreamURL.Host, nil },
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go srv.Serve(ctx, ln)

	caPool := x509.NewCertPool()
	caPool.AddCert(caInst.RootCert())
	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "api.anthropic.com"},
		},
		Timeout: 10 * time.Second,
	}

	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "name": "Read", "id": "x",
				 "input": {"file_path": "/src/payments/charge.go"}}
			]}
		]
	}`

	// First request — should pass under warn-only policy.
	resp, err := client.Post("https://api.anthropic.com/v1/messages", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("first Post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first request: status = %d, want 200", resp.StatusCode)
	}

	// Update policy to block payments paths.
	if err := os.WriteFile(policyPath, []byte(`
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
  - name: default-warn
    match: {all: true}
    action: warn
`), 0o600); err != nil {
		t.Fatalf("write updated policy: %v", err)
	}

	// Wait for the watcher to pick up the reload by polling the audit
	// file for a kind=policy_reload outcome=accepted event.
	waitForReloadEvent(t, auditPath, "accepted", 3*time.Second)

	// Second request — should be blocked under the new policy.
	resp2, err := client.Post("https://api.anthropic.com/v1/messages", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("second Post: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("second request: status = %d, want 403 (policy should now block)", resp2.StatusCode)
	}
}

// waitForReloadEvent polls the audit file until a policy_reload event
// with the given outcome appears, or the timeout fires.
func waitForReloadEvent(t *testing.T, path, outcome string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if line == "" {
					continue
				}
				var e audit.Event
				if err := json.Unmarshal([]byte(line), &e); err != nil {
					continue
				}
				if e.Kind == "policy_reload" && e.Outcome == outcome {
					return
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for kind=policy_reload outcome=%s in %s", outcome, path)
}
```

- [ ] **Step 2: Run the test**

```bash
go test -race -count=1 -run TestHotReload ./test/integration/...
```

Expected: PASS.

- [ ] **Step 3: Run full suite**

```bash
go test -race -count=1 ./...
go vet ./...
gofmt -l test/integration/
```

All clean.

- [ ] **Step 4: Commit**

```bash
git add test/integration/hot_reload_test.go
git -c user.email=haidangdavid123@gmail.com -c user.name=dawn commit -m "test(integration): end-to-end hot policy reload"
```

No Co-Authored-By.

---

## Task 10: Manual acceptance test

**Files:** none modified during testing; spec gets §11 appended at the end.

- [ ] **Step 1: Build**

```bash
make build || go build -o railcore ./cmd/railcore
```

- [ ] **Step 2: Reset state**

```bash
./railcore init --force
```

- [ ] **Step 3: Start proxy + log follower in two terminals**

Terminal A:
```bash
./railcore proxy --port 9443
```

Terminal B:
```bash
./railcore logs --follow
```

- [ ] **Step 4: Edit `~/.railcore/policy.yaml`**

Add a new rule above any catch-all warn (e.g., `block-aws` matching `aws_*` patterns). Save.

Within ~250ms, terminal B should show:

```
HH:MM:SS  ⟳  policy_reload  /home/dawn/.railcore/policy.yaml  accepted  N→M rules
```

- [ ] **Step 5: Verify the new rule fires**

Make an AI request through Claude Code or Cursor that triggers the new rule. Audit shows `decision=block` with the expected `findings[].rule` matching the new rule name.

- [ ] **Step 6: Test the rejection path**

Edit `~/.railcore/policy.yaml` to be malformed (e.g., delete a closing `}` or paste invalid YAML). Save.

Terminal B shows:

```
HH:MM:SS  ⚠  policy_reload  /home/dawn/.railcore/policy.yaml  rejected  rules_before=N  err='...'
```

Restore the YAML to a valid state, save — observe an `accepted` event.

Test that the OLD policy was still active during the rejection window: make an AI request between the rejected save and the restore, verify the previous rules still fire (e.g., the `block-aws` rule still blocks).

- [ ] **Step 7: Record acceptance result**

Append §11 to `docs/superpowers/specs/2026-05-19-hot-policy-reload-design.md`:

```markdown

---

## 11. Acceptance Result

**Date:** YYYY-MM-DD (fill in)

- **Live reload accepted:** Edited policy.yaml; saw `⟳ policy_reload ... accepted N→M rules` within ~250ms.
- **New rule fires on next request:** Triggered the new block rule via Claude Code / Cursor; observed `decision=block findings[0].rule=<new-rule>`.
- **Reload rejected on malformed YAML:** Saved invalid YAML; saw `⚠ policy_reload ... rejected ... err='...'`. Previous policy stayed live (verified by triggering the original block rule).
- **Restore re-accepts:** Fixed the YAML; saw another `accepted` event.
- **No lost AI sessions:** Active Claude Code / Cursor connection survived all reload events.

**Status:** Pass. Sub-project #8 done definition §8 satisfied.

**Notes:** [any observations on debounce timing, audit log shape, UI labels]
```

- [ ] **Step 8: Commit the acceptance record**

```bash
git add docs/superpowers/specs/2026-05-19-hot-policy-reload-design.md
git -c user.email=haidangdavid123@gmail.com -c user.name=dawn commit -m "docs(spec): record sub-project #8 acceptance result"
```

No Co-Authored-By.

---

## Self-Review

1. **Spec coverage:**
   - §4.1 `Provider` → Task 1.
   - §4.2 `Watcher` → Task 4.
   - §4.3 Stage integration → Tasks 5, 6.
   - §4.4 Audit Event + Logger.Event → Tasks 2, 3.
   - §4.5 Wire format → covered by Tasks 2, 3 tests.
   - §4.6 `railcore logs` Event rendering → Task 8.
   - §4.7 Proxy startup wiring → Task 7.
   - §4.8 RuleCount helper → Task 1.
   - §6 Error handling → covered by Watcher tests (Task 4) + smoke test (Task 7).
   - §7 Testing → Tasks 1-9.
   - §7.7 Manual acceptance → Task 10.
   - §8 Done definition → Tasks 7 (build), 9 (E2E), 10 (acceptance).

2. **Placeholder scan:** Task 10 step 7 has `YYYY-MM-DD` and `[fill in]` — runtime values the user supplies. No "TBD"/"TODO" in code paths.

3. **Type consistency:**
   - `policy.Provider.Get() / Set()` consistent across Tasks 1, 5, 6, 7, 9.
   - `audit.Event{Time, Kind, PolicyPath, Outcome, RulesBefore, RulesAfter, Error}` consistent across Tasks 2, 3, 7, 8, 9.
   - `Logger.Event(Event)` consistent across Tasks 2, 3, 5 (captureAudit), 7 (proxy invocation).
   - `policy.NewWatcher(path, logger, onAccept, onReject)` consistent across Tasks 4, 7, 9.
   - `policy.Policy.RuleCount()` consistent across Tasks 1, 7, 9.

4. **Cross-task compile gates:**
   - Task 1 standalone (Provider + RuleCount).
   - Tasks 2 + 3 commit together (Logger interface change requires NoopLogger.Event + Writer.Event + captureAudit.Event together).
   - Task 4 standalone (Watcher).
   - Task 5 atomic (15-site field rename) — must commit all in one go.
   - Task 6 follows Task 5.
   - Task 7 depends on Tasks 1-5 (uses Provider + Watcher + Event + Set + RuleCount).
   - Task 8 depends on Task 2 (Event type for parsing).
   - Task 9 depends on everything above.
   - Task 10 (manual) is the final step.
