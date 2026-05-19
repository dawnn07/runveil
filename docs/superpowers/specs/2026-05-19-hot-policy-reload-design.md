# Sub-project #8 — Hot Policy Reload

**Status:** Design approved, pending spec review
**Date:** 2026-05-19
**Sub-project of:** Railcore post-MVP (operational ergonomics)

---

## 1. Goal

When the user edits the policy YAML and saves, the proxy picks up the change within a second — no restart, no lost AI sessions. Successful reloads AND rejected reloads (malformed YAML, invalid rules) both produce structured audit records so compliance teams can see rule changes in the audit trail.

This eliminates the day-1 friction observed during sub-project #6's acceptance test, where editing the policy required restarting the proxy and losing all in-flight AI conversations.

---

## 2. Non-goals

- Reloading CLI flags (`--port`, `--data-dir`, `--audit-*`, `--block-on-detect`) — these remain bootstrap-only.
- Reloading CA / TLS configuration.
- Remote policy distribution (Git/HTTP source-of-truth) — that's a control-plane feature for a future sub-project.
- `railcore reload` CLI command — fsnotify-based file watching covers the user need without adding a control socket.
- Watching multiple policy files simultaneously — single-file scope.
- Per-file diff/changelog in the audit record — record only before/after rule counts and the validation error string when rejected.
- Schema migration (`version: 2` policies) — existing `policy.LoadFromBytes` handles version validation; rejection event reports any version error.

---

## 3. Module layout

```
internal/policy/                         (leaf — stdlib + yaml.v3 + NEW fsnotify)
├── provider.go                          CREATE: atomic-pointer Provider
├── provider_test.go                     CREATE: 3 tests
├── watcher.go                           CREATE: fsnotify-based Watcher
├── watcher_test.go                      CREATE: 6 tests
├── load.go                              unchanged
└── policy.go                            unchanged (will add RuleCount() helper)

internal/audit/                          (leaf — stdlib + lumberjack only)
├── audit.go                             MODIFY: add Event type + Logger.Event method
├── audit_test.go                        MODIFY: append 3 tests
├── writer.go                            MODIFY: implement Writer.Event
└── writer_test.go                       MODIFY: append 1 test

internal/stage/pathscan/
├── stage.go                             MODIFY: Config.Policy → Config.Policies *Provider
└── stage_test.go                        MODIFY: update fixtures + 1 new live-swap test

internal/stage/secretscan/
├── stage.go                             MODIFY: same shape
└── stage_test.go                        MODIFY: same shape

cmd/railcore/
└── proxy.go                             MODIFY: construct Provider + Watcher; wire callbacks
├── logs.go                              MODIFY: dispatch on Kind field for pretty rendering
└── logs_test.go                         MODIFY: append 2 formatEvent tests

test/integration/
└── hot_reload_test.go                   CREATE: end-to-end test

docs/superpowers/specs/2026-05-19-hot-policy-reload-design.md   (this file)
docs/superpowers/plans/2026-05-19-hot-policy-reload.md          (next step)
```

**New direct dependency:** `github.com/fsnotify/fsnotify`. Used only by `internal/policy/watcher.go`. `internal/policy` remains a leaf — stdlib + yaml.v3 + fsnotify.

**Dependency direction (new edges):**

```
cmd/railcore              ──→ internal/policy.Provider, internal/policy.Watcher (NEW)
internal/stage/{pathscan,secretscan} ──→ internal/policy.Provider   (replaces *Policy)
```

No new cross-package internal edges. `internal/policy` does not import `internal/audit` — the watcher uses callbacks so audit emission stays in `cmd/railcore`.

---

## 4. Detailed design

### 4.1 `policy.Provider` (new — `internal/policy/provider.go`)

```go
// Provider holds the active *Policy and serves wait-free reads to
// every request handler. Updates from the Watcher are atomic.
type Provider struct {
    p atomic.Pointer[Policy]
}

// NewProvider returns a Provider holding the given initial policy.
// initial may be nil.
func NewProvider(initial *Policy) *Provider {
    pr := &Provider{}
    pr.p.Store(initial)
    return pr
}

// Get returns the currently-active policy. Safe under concurrent
// access. Returns nil when no policy is configured.
func (pr *Provider) Get() *Policy { return pr.p.Load() }

// Set atomically swaps the active policy.
func (pr *Provider) Set(np *Policy) { pr.p.Store(np) }
```

No other methods. Wait-free reads, atomic writes. Nil-safe.

### 4.2 `policy.Watcher` (new — `internal/policy/watcher.go`)

```go
type Watcher struct {
    path     string                       // absolute path to watch
    logger   *slog.Logger
    onAccept func(*Policy)                // success callback
    onReject func(err error, raw []byte)  // failure callback
    debounce time.Duration                 // default 250ms
    // ...internal: fsnotify watcher, goroutine sync
}

func NewWatcher(path string, logger *slog.Logger,
    onAccept func(*Policy),
    onReject func(error, []byte),
) (*Watcher, error)

// Start launches the watch goroutine. Returns immediately. Goroutine
// runs until ctx is cancelled or Close is called.
func (w *Watcher) Start(ctx context.Context) error

// Close stops the watcher. Idempotent. Joins the goroutine.
func (w *Watcher) Close() error
```

**Behavior:**

- Watches the **parent directory** (`filepath.Dir(path)`) so atomic-rename saves (vim, `mv tmp policy.yaml`) are caught. Filters incoming events by basename match.
- On any Create/Write/Rename targeting the basename, debounce 250ms then re-read the file.
- Run bytes through `policy.LoadFromBytes`. Success → `onAccept(newPolicy)`. Failure → `onReject(err, rawBytes)`.
- Remove events: log WARN, no callback fired.
- fsnotify-watcher-itself errors (kernel buffer overflow): log ERROR, watcher continues, operator must `touch policy.yaml` to retry.
- Tests force a synchronous load via an unexported helper to avoid `time.Sleep`.

**Why callbacks:** keeps `internal/policy` free of dependencies on `internal/audit`. The proxy wires Set + Event-emission together at the call site.

### 4.3 Stage integration

Both stages switch `Config.Policy *policy.Policy` to `Config.Policies *policy.Provider`. Each Run captures `pol := s.cfg.Policies.Get()` once at the start so the rest of the request sees a consistent snapshot even if a reload fires mid-pipeline.

`internal/stage/pathscan/stage.go`:

```go
type Config struct {
    Policies *policy.Provider
}

func (s *Stage) Run(ctx context.Context, rc *pipeline.RequestCtx) (pipeline.Decision, error) {
    pol := s.cfg.Policies.Get()
    if pol == nil { return pipeline.Continue, nil }
    // ...
    action, rule := pol.DecidePath(e.Path)
}
```

`internal/stage/secretscan/stage.go`: identical pattern. `decideWithPolicy` gains an explicit `*policy.Policy` parameter (instead of reading `s.cfg.Policy` inside).

### 4.4 Audit Event type (new in `internal/audit/audit.go`)

```go
// Event is a synthetic (non-request) audit record. Currently used for
// policy reload notifications; future synthetic event kinds will use
// the same shape with a different Kind value.
type Event struct {
    Time        time.Time `json:"time"`
    Kind        string    `json:"kind"`          // e.g., "policy_reload"
    PolicyPath  string    `json:"policy_path,omitempty"`
    Outcome     string    `json:"outcome,omitempty"`  // "accepted" | "rejected"
    RulesBefore int       `json:"rules_before,omitempty"`
    RulesAfter  int       `json:"rules_after,omitempty"`
    Error       string    `json:"error,omitempty"`     // when rejected
}

type Logger interface {
    Log(Record)
    Event(Event)        // NEW
}

func (NoopLogger) Event(_ Event) {}
```

`Writer.Event` follows the same async-channel + lumberjack path as `Log`. Channel-full warnings and post-close safety are inherited from the existing implementation.

### 4.5 Wire format

Request records (existing) and reload events live in the same JSONL file. Readers dispatch on the `kind` field. A request record has no `kind` field (or `kind:""`); a reload event has `kind:"policy_reload"`.

```json
{"time":"2026-05-19T10:01:23Z","kind":"policy_reload","policy_path":"/home/dawn/.railcore/policy.yaml","outcome":"accepted","rules_before":2,"rules_after":3}
{"time":"2026-05-19T10:01:45Z","kind":"policy_reload","policy_path":"/home/dawn/.railcore/policy.yaml","outcome":"rejected","rules_before":3,"error":"policy: rule 0: invalid glob '**/[unclosed'"}
```

### 4.6 `railcore logs` rendering

`cmd/railcore/logs.go` parses each line, detects `kind`, and routes:
- `kind == ""` → existing `formatRecord`
- `kind == "policy_reload"` → new `formatEvent`

```
10:01:23  ⟳  policy_reload  /home/dawn/.railcore/policy.yaml  accepted  2→3 rules
10:01:45  ⚠  policy_reload  /home/dawn/.railcore/policy.yaml  rejected  rules_before=3  err='policy: rule 0: invalid glob...'
```

`--json` mode emits the raw line as-is — no shape detection needed.

### 4.7 Proxy startup wiring (`cmd/railcore/proxy.go`)

Before pipeline construction, replace the existing single-shot `policy.LoadFromFile(...)` with provider + watcher wiring:

```go
loadedPolicy, _, resolvedPath := resolvePolicy(*policyPath, *dataDir, logger)
policies := policy.NewProvider(loadedPolicy)

var watcher *policy.Watcher
if resolvedPath != "" {
    w, err := policy.NewWatcher(resolvedPath, logger,
        // onAccept
        func(np *policy.Policy) {
            before := 0
            if cur := policies.Get(); cur != nil {
                before = cur.RuleCount()
            }
            policies.Set(np)
            auditLogger.Event(audit.Event{
                Time:        time.Now(),
                Kind:        "policy_reload",
                PolicyPath:  resolvedPath,
                Outcome:     "accepted",
                RulesBefore: before,
                RulesAfter:  np.RuleCount(),
            })
            logger.Info("policy reloaded", "path", resolvedPath,
                "rules_before", before, "rules_after", np.RuleCount())
        },
        // onReject
        func(err error, _ []byte) {
            before := 0
            if cur := policies.Get(); cur != nil {
                before = cur.RuleCount()
            }
            auditLogger.Event(audit.Event{
                Time:        time.Now(),
                Kind:        "policy_reload",
                PolicyPath:  resolvedPath,
                Outcome:     "rejected",
                RulesBefore: before,
                Error:       err.Error(),
            })
            logger.Warn("policy reload rejected", "path", resolvedPath, "err", err.Error())
        },
    )
    if err != nil {
        logger.Error("policy watcher failed to start", "err", err.Error())
        os.Exit(1)
    }
    watcher = w
    if err := watcher.Start(ctx); err != nil {
        logger.Error("policy watcher start", "err", err.Error())
        os.Exit(1)
    }
    defer func() { _ = watcher.Close() }()
}

// pass policies (not *Policy) to both stages
chain.Register(pathscan.New(pathscan.Config{Policies: policies}, logger))
chain.Register(secretscan.New(secretscan.Config{
    BlockOnDetect: effectiveBlock,
    Policies:      policies,
}, logger))
```

If `resolvedPath == ""` (no policy in effect), the watcher is not started; the provider still holds nil and stages behave as silent no-ops.

### 4.8 `policy.Policy.RuleCount()` helper (new)

```go
func (p *Policy) RuleCount() int {
    if p == nil { return 0 }
    return len(p.Rules)
}
```

Trivial — needed because the `onAccept` / `onReject` callbacks include `rules_before` / `rules_after` in the audit event.

---

## 5. Data flow

```
Editor saves ~/.railcore/policy.yaml
  └─ fsnotify event on parent dir (Write/Create/Rename)
     └─ Watcher debounces 250ms
        └─ ReadFile + policy.LoadFromBytes
            ├─ success → onAccept(newPolicy)
            │            ├─ before := provider.Get().RuleCount()
            │            ├─ provider.Set(newPolicy)
            │            ├─ audit.Event{kind:policy_reload, outcome:accepted, ...}
            │            └─ slog.Info "policy reloaded"
            └─ failure → onReject(err, raw)
                         ├─ audit.Event{kind:policy_reload, outcome:rejected, error:..., rules_before:N}
                         └─ slog.Warn "policy reload rejected"

Per-request path (unchanged in shape, just reads via Provider):
  HTTP request → proxy → pipeline → secretscan.Run
                                       └─ pol := cfg.Policies.Get()    ← wait-free
                                          pol.Decide(...) / fallback
                                    pathscan.Run
                                       └─ pol := cfg.Policies.Get()    ← wait-free
                                          pol.DecidePath(...)
```

---

## 6. Error handling

| Event | Behavior |
|---|---|
| Malformed YAML on reload | Keep active policy. Emit `Event{outcome:"rejected"}`. Log WARN. |
| Valid YAML but policy validation fails | Same as malformed YAML. |
| File removed (`rm policy.yaml`) | Keep active policy. Log WARN ("policy file removed, keeping current rules"). NO rejection event. Re-create triggers normal accept. |
| File replaced via atomic rename | Caught — we watch the parent directory and filter by basename. |
| Editor save burst (header, body, fsync) | Debounce 250ms — one reload per save batch. |
| Path doesn't exist at startup | Watcher started anyway; no events fire until file created. Provider stays at whatever startup loaded (nil if file was absent at startup). |
| fsnotify watcher itself errors (inotify limit, kernel buffer overflow) | Log ERROR. Watcher continues; some events may have been missed. Operator must `touch policy.yaml` to force re-read. |
| Proxy shutdown | `Watcher.Close()` is deferred. Idempotent. Goroutine joined via `wg.Wait()`. |
| Reload fires during shutdown after audit.Writer closed | `Writer.Event` is no-op after close (same pattern as `Log` from sub-project #6). No panic. |
| Reload event order vs Provider.Set | Watcher goroutine is single-writer: (1) snapshot old rule count, (2) Set new policy, (3) emit Event. Sequential. |

---

## 7. Testing

### 7.1 `internal/policy/provider_test.go` (new, 3 tests)

- `TestProvider_GetReturnsStoredPointer`
- `TestProvider_SetSwapsAtomically` — 100 reader goroutines + 1 writer; passes under `-race`.
- `TestProvider_NilSafe` — `NewProvider(nil).Get() == nil`.

### 7.2 `internal/policy/watcher_test.go` (new, 6 tests)

- `TestWatcher_AcceptsValidReload`
- `TestWatcher_RejectsMalformedYAML`
- `TestWatcher_RejectsInvalidPolicy`
- `TestWatcher_DebouncesBurstEvents` — 5 writes within 50ms → exactly one onAccept call
- `TestWatcher_HandlesAtomicRename` — write to tmp, `os.Rename` to target
- `TestWatcher_CloseIdempotent`

All use real fsnotify in `t.TempDir()`. Tests wait on a `chan struct{}` from the callback — no `time.Sleep` polling.

### 7.3 Stage tests

Mechanical fixture updates (~25 lines): every `Config{Policy: pol}` becomes `Config{Policies: policy.NewProvider(pol)}`.

One new test per stage to verify live swap:

- `TestStage_LiveSwapPicksUpNewPolicy` in each stage's `_test.go` — construct stage with policy A, run, assert continue; `Provider.Set(policyB)`; run again, assert block.

### 7.4 Audit Event

- `internal/audit/audit_test.go`: append `TestEvent_MarshalJSON_AllFields`, `TestEvent_MarshalJSON_OmitsEmptyOptionals`, `TestNoopLogger_EventIsSafe`.
- `internal/audit/writer_test.go`: append `TestWriter_LogsEventToFile`.

### 7.5 End-to-end (`test/integration/hot_reload_test.go`, new)

`TestHotReload_E2E_PolicyChangeBlocksOnNextRequest`:
1. Start proxy with policy A (allows `**/payments/**`).
2. Make a request → audit shows `decision=continue`.
3. Write policy B (blocks `**/payments/**`) to the same file.
4. Wait for `kind=policy_reload outcome=accepted` event in audit (poll, max 2s, no fixed sleep).
5. Make a second request → audit shows `decision=block`.

Pattern: same as `audit_test.go` waitFor helper from sub-project #6.

### 7.6 `railcore logs` rendering

`cmd/railcore/logs_test.go`: append
- `TestFormatEvent_PolicyReloadAccepted`
- `TestFormatEvent_PolicyReloadRejected`

### 7.7 Regression sweep

`go test -race -count=1 ./...` remains green. Expected: 277 → ~295.

### 7.8 Manual acceptance (§7.7 equivalent)

Single scenario, real Claude Code or Cursor:

1. Start proxy with default policy.
2. `railcore logs --follow` in another terminal.
3. Edit `~/.railcore/policy.yaml` in your IDE — add a new block rule above any catch-all warn.
4. Save. Within ~250ms, see `⟳ policy_reload ... accepted N→M rules` in the log follower.
5. Make an AI request that should hit the new rule. Verify `decision=block`.
6. Edit the YAML to be malformed (delete a closing `]`). Save. Observe `⚠ policy_reload ... rejected ...` and confirm the OLD policy is still live (existing rules still fire).

---

## 8. Done definition

Sub-project #8 is complete when:

1. All unit tests in §7.1–7.4 pass under `-race -count=1`.
2. The end-to-end test in §7.5 passes.
3. `go test -race -count=1 ./...` for the whole repo remains green (no regression in the existing 277 tests; new total ~295).
4. `go vet ./...` and `gofmt -l .` clean.
5. Manual acceptance in §7.8 passes.
6. Acceptance result recorded in §11 of this spec.

---

## 9. Open questions

None. Three deliberate punts documented as out-of-scope in §2:
- Multi-file policy watching
- Symlinked policy file behavior
- Remote policy source (Git/HTTP)
