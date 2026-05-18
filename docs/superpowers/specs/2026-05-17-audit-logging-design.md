# Sub-project #6 — Audit Logging

**Status:** Design approved, pending spec review
**Date:** 2026-05-17
**Sub-project of:** Railcore MVP (see `part1.md`, `part2.md` in repo root)
**Builds on:** [Sub-project #5](2026-05-17-cli-subcommands-design.md) (CLI), which builds on #1-4.

---

## 1. Purpose and Scope

Make Railcore's traffic auditable. Today the proxy emits operational logs to stderr — fine for live debugging, useless for compliance, security review, or the [`part1.md`](../../../part1.md) §1.3 demo-killer ("your team sent 4,300 requests to OpenAI last week"). This sub-project adds a structured, persistent, rotating audit log of every AI request the proxy handles, plus a `railcore logs` subcommand for inspecting it.

**In scope:**

- New leaf package `internal/audit/` with `Record` type, `Logger` interface, `NoopLogger`, and `Writer` (async channel + goroutine + lumberjack-backed file).
- New `proxy.Config.AuditFunc audit.Logger` field; invoked at request completion (the same site as the existing slog line).
- One audit record per AI request — whether or not findings fired. Records embed any `secretscan.findings` and `pathscan.findings` from `rc.Metadata`.
- New `railcore logs` subcommand with `-n N`, `--follow`/`-f`, `--json` flags.
- New CLI flags on `railcore proxy`: `--audit-log`, `--audit-max-size-mb`, `--audit-max-backups`, `--audit-max-age-days`.
- New third-party dependency: `github.com/natefinch/lumberjack/v2` (MIT, the de facto Go log-rotation library).

**Out of scope (deferred):**

- **SIEM forwarder.** Splunk / Datadog / Sentinel connectors are the enterprise tier (part2.md §5.2).
- **Encryption at rest.** Plaintext JSON Lines on disk; rely on OS file permissions (0600).
- **Centralized aggregation.** A separate daemon reading audit logs from multiple machines.
- **Log integrity / tamper-evidence.** No cryptographic chaining of records.
- **Per-host audit filters** ("don't log anthropic.com"). YAGNI; pipe through `jq` if needed.
- **Audit `audit.yaml` config file.** CLI flags suffice for this cycle.
- **Audit channel-full = exit 1** ("guaranteed-no-gaps") mode. YAGNI; raise buffer size instead.
- **Time-based rotation** (daily files). Size-based via lumberjack only.

---

## 2. Decisions Locked in During Brainstorming

| Decision | Choice | Rationale |
|---|---|---|
| Scope of records | **Every AI request** (continue or block, findings or not). | Compliance-grade audit; demo-killer requires per-request totals. |
| Rotation | **Size-based via `github.com/natefinch/lumberjack/v2`** (100 MB × 5 backups × 30 days default). | De facto Go log-rotation library; zero-config out of the box. |
| Write model | **Async via buffered channel + background goroutine.** | Keeps the per-request hot path zero-latency. Acceptable data loss on hard kill. |
| `railcore logs` scope | **Pretty print last N + `--follow` + `--json` raw mode.** | Filters deferred; pipe through `jq`/`grep` for ad-hoc queries. |
| Integration with proxy | **`proxy.Config.AuditFunc audit.Logger` callback** at the request-completion site. | Same pattern as existing `Config.Logger`. Loose coupling, tests can inject capturing implementations. |

---

## 3. Repo Layout

One new leaf package + targeted edits to `internal/proxy/` and `cmd/railcore/`.

```
railcore/
├── cmd/
│   └── railcore/
│       ├── main.go             # +1 dispatch case: "logs"
│       ├── logs.go             # NEW — runLogs subcommand
│       ├── logs_test.go        # NEW — formatting + parsing unit tests
│       ├── proxy.go            # MODIFY — wire audit.Writer + AuditFunc + Close on shutdown
│       └── ...                 # other subcommands unchanged
├── internal/
│   ├── audit/                  # NEW — leaf package
│   │   ├── audit.go            # Record, Logger interface, NoopLogger
│   │   ├── writer.go           # Writer (channel + goroutine + lumberjack)
│   │   ├── audit_test.go
│   │   └── writer_test.go
│   ├── proxy/                  # MODIFY
│   │   ├── server.go           # +Config.AuditFunc field
│   │   ├── upstream.go         # +call AuditFunc at request completion; helpers to read metadata
│   │   └── server_test.go      # +tests for AuditFunc invocation
│   └── ... (everything else unchanged)
└── test/
    └── integration/
        ├── audit_test.go       # NEW — end-to-end audit file scenarios
        └── cli_test.go         # MODIFY — append `railcore logs` tests
```

**Dependency direction (unchanged + new):**

```
cmd/railcore
   └── internal/audit          (NEW leaf — depends only on stdlib + lumberjack)
   └── internal/proxy          (existing; gains optional dep on internal/audit via Config)
```

`internal/audit/` imports stdlib + `gopkg.in/lumberjack.v2` only. No `internal/proxy` or stage imports — the proxy calls into audit, not the other way around.

**New dependency:** `gopkg.in/natefinch/lumberjack.v2` (MIT, ~5KB, well-tested rotation library).

---

## 4. Components

### 4.1 The audit record

One JSON object per line. Schema:

```go
// Record is one audit event written as a JSON Lines entry.
// Wire format documented inline; producers must respect the JSON tags.
type Record struct {
    Time       time.Time `json:"time"`            // RFC3339Nano UTC
    RequestID  string    `json:"request_id"`      // UUID from proxy
    Host       string    `json:"host"`            // e.g., "api.anthropic.com"
    Method     string    `json:"method"`          // HTTP method
    Path       string    `json:"path"`            // request path
    Status     int       `json:"status"`          // HTTP response status code
    BytesIn    int64     `json:"bytes_in"`        // request body size
    BytesOut   int64     `json:"bytes_out"`       // response body size streamed
    DurationMs int64     `json:"duration_ms"`     // wall-clock total

    Vendor   string `json:"vendor,omitempty"`   // "openai" | "anthropic" | ""
    Endpoint string `json:"endpoint,omitempty"` // "chat.completions" | "messages" | ""
    Decision string `json:"decision"`           // "continue" | "block"
    Findings []any  `json:"findings,omitempty"` // per-detector findings, each carries its own "detector" field via MarshalJSON
}
```

Example line (block with findings):

```json
{"time":"2026-05-17T16:33:12.481Z","request_id":"abc-123","host":"api.anthropic.com","method":"POST","path":"/v1/messages","status":403,"bytes_in":1842,"bytes_out":196,"duration_ms":42,"vendor":"anthropic","endpoint":"messages","decision":"block","findings":[{"detector":"path-scan","tool":"Read","path":"/src/payments/charge.go","message_index":0,"rule":"block-payments"}]}
```

**Note on `Findings []any`:** the proxy stashes `[]secretscan.EnrichedFinding` and `[]pathscan.PathFinding` (each implements `MarshalJSON`) in `rc.Metadata`. The audit layer copies those values into the record's `Findings` slice and lets `json.Marshal` handle per-type serialization. The audit package does NOT import either stage package — it trusts the existing `MarshalJSON` methods.

### 4.2 `internal/audit` — public API

```go
// Logger is the consumer-facing interface. Proxy holds a Logger
// (never a concrete *Writer) so tests can inject capturing or no-op
// implementations.
type Logger interface {
    Log(r Record)
}

// NoopLogger discards records. Used as the default when no audit
// destination is configured.
type NoopLogger struct{}
func (NoopLogger) Log(_ Record) {}

// Writer is the lumberjack-backed, async, file-writing Logger.
type Writer struct {
    /* unexported: channel, wg, lumberjack writer, slog logger */
}

// Config configures a Writer.
type Config struct {
    Path       string // file path; required (caller passes "" to opt out)
    MaxSizeMB  int    // default 100
    MaxBackups int    // default 5
    MaxAgeDays int    // default 30
    BufferSize int    // channel buffer; default 1024
}

// NewWriter probes that Path is writable, opens the lumberjack writer,
// starts the background goroutine, and returns a *Writer. Errors at
// construction surface here (don't lazy-fail).
func NewWriter(cfg Config, logger *slog.Logger) (*Writer, error)

// Log implements Logger. Non-blocking: drops the record (with a WARN
// to the slog logger) if the channel is full.
func (w *Writer) Log(r Record)

// Close drains the buffer, flushes lumberjack, stops the goroutine.
// Safe to call multiple times. After Close, Log is a no-op.
func (w *Writer) Close() error
```

### 4.3 Wire-up in `internal/proxy`

`Config` gains one optional field:

```go
type Config struct {
    /* existing fields */
    AuditFunc audit.Logger // optional; defaults to NoopLogger semantics
}
```

The existing per-request completion site in `internal/proxy/upstream.go`'s `newHandler` defer block gains one new call:

```go
defer func() {
    /* existing slog.Info("request complete", ...) call */
    if s.cfg.AuditFunc != nil {
        s.cfg.AuditFunc.Log(audit.Record{
            Time:       start,
            RequestID:  requestID,
            Host:       host,
            Method:     r.Method,
            Path:       r.URL.Path,
            Status:     rec.status,
            BytesIn:    int64(len(body)),
            BytesOut:   rec.bytesOut,
            DurationMs: time.Since(start).Milliseconds(),
            Vendor:     vendorFromMetadata(rc),
            Endpoint:   endpointFromMetadata(rc),
            Decision:   decision.String(),
            Findings:   findingsFromMetadata(rc),
        })
    }
}()
```

Three small helpers (defined in `internal/proxy/upstream.go`):

- `vendorAndEndpoint(rc, body)` — calls `parser.ParseRequest(rc.Host, rc.Req, body)` once at the completion site and returns `(vendor, endpoint)` strings. Both empty if not a known AI endpoint. Duplicates the parse work already done by pathscan/secretscan stages, but the body is already in memory and the parse cost is microseconds. Avoids cross-stage metadata coupling and keeps `internal/proxy/` ignorant of stage internals.
- `findingsFromMetadata(rc)` — reads both `rc.Metadata["secretscan.findings"]` and `rc.Metadata["pathscan.findings"]`, concatenates into `[]any`. If both are absent, returns nil (so the record's `findings` field is omitted via `omitempty`).

Adding `parser` to `internal/proxy/`'s import list creates a new edge: `internal/proxy → internal/parser`. This is acceptable — `parser` is a leaf (stdlib + nothing internal) and there's no cycle.

### 4.4 `cmd/railcore/logs.go`

```go
type logsConfig struct {
    DataDir  string
    File     string  // explicit override
    NumLines int     // default 50
    Follow   bool    // --follow / -f
    JSON     bool    // --json: raw JSON lines
}

func runLogs(args []string)

// formatRecord renders one record as a single pretty line.
func formatRecord(r audit.Record) string
```

**Reading strategy:**

- Default to `<data-dir>/audit.log`; override via `--file PATH`.
- Read backwards to find last N records: seek to end, work backwards in chunks, scan for newlines. For typical N=50, reading the last 50–100KB suffices.
- If `--follow`: after printing last N, poll-based tail (200ms `os.Stat`-then-read loop). Re-open on inode change (lumberjack rotation).
- If file is missing: error message + exit 1.
- If file contains malformed JSON lines: skip silently, print one summary warning at exit `skipped N malformed lines`.

**Pretty format:**

```
HH:MM:SS  ✓|✗  METHOD  HOST  PATH  STATUS  DURATION  DECISION  [findings=N [rules]]
```

Example:

```
16:33:12  ✓  POST  api.anthropic.com  /v1/messages           200   42ms  continue
16:33:14  ✗  POST  api.anthropic.com  /v1/messages           403   38ms  block      findings=1 [block-payments]
16:33:15  ✓  POST  api.openai.com     /v1/chat/completions   200  127ms  continue
```

`--json` prints raw lines verbatim (one per `audit.Record`, byte-for-byte from the file).

### 4.5 `cmd/railcore/proxy.go` wiring

After existing CA + policy setup:

```go
auditPath := *flagAuditLog
if auditPath == "" {
    // Default: <data-dir>/audit.log. Pass --audit-log="" to disable.
    auditPath = filepath.Join(*dataDir, "audit.log")
}

var auditLogger audit.Logger = audit.NoopLogger{}
var auditWriter *audit.Writer
if *flagAuditEnabled {
    w, err := audit.NewWriter(audit.Config{
        Path:       auditPath,
        MaxSizeMB:  *flagAuditMaxSize,
        MaxBackups: *flagAuditMaxBackups,
        MaxAgeDays: *flagAuditMaxAge,
    }, logger)
    if err != nil {
        logger.Error("audit init failed", "err", err.Error())
        os.Exit(1)
    }
    auditWriter = w
    auditLogger = w
    defer func() { _ = auditWriter.Close() }()
}

srv := proxy.New(proxy.Config{
    /* existing fields */
    AuditFunc: auditLogger,
})
```

The `--audit-enabled=false` flag (default true) is the way to fully disable. Setting `--audit-log=""` is also accepted as a shortcut. Either route uses `NoopLogger`.

### 4.6 What's NOT added in this design

- No `audit.yaml` config file; CLI flags only.
- No SIEM forwarder; that's enterprise tier.
- No log integrity (signed chains).
- No time-based rotation (lumberjack size + age is enough).

---

## 5. Request Data Flow

Walks one Claude Code → Anthropic request that triggers the path-block rule.

```
 1. Claude Code's agent sends POST /v1/messages with a Read tool_use.
 2. proxy.handler intercepts, reads body, runs pipeline.
 3. pathscan stage blocks, stashes []PathFinding in rc.Metadata.
 4. proxy.handler returns 403 to client. Deferred completion fires:
       a. Build the per-request slog line (existing).
       b. Build audit.Record (Vendor/Endpoint/Decision/Findings from
          rc.Metadata helpers).
       c. s.cfg.AuditFunc.Log(record)  — non-blocking channel send.
    ──────────────────────────────────────────────────────
 5. audit.Writer goroutine receives:
       a. json.Marshal(record).
       b. lumberjack.Logger.Write(jsonLine + "\n").
       c. Rotation triggers internally when file exceeds MaxSizeMB.
 6. audit.log now contains one new line.
 7. Operator running `railcore logs --follow` sees the new line in ~200ms.
```

**Key properties:**

- Audit is **fire-and-forget** from the proxy hot path: one channel send, microseconds.
- **No content** in the audit record — only metadata + pattern names + paths. The security invariant from sub-project #2 (matched secret bytes never echoed) carries through.
- **Rotation is invisible.** Lumberjack renames atomically; `railcore logs --follow` reopens on inode change.
- **Decision = "block"** only when the pipeline returned Block. Allowed-via-policy findings are absent from the array; warn findings are present.

### 5.1 Shutdown sequence

1. SIGTERM/SIGINT cancels the listener context (existing signal handler from sub-project #1).
2. `srv.Serve` returns.
3. `main.go`'s `defer` calls `auditWriter.Close()`.
4. `Close()` closes the channel; goroutine drains; lumberjack flushes; goroutine returns.
5. Process exits.

Records in flight at SIGKILL / OOM are lost. Acceptable for audit-grade logging per §2.

---

## 6. Error Handling

Same posture: loud at startup, fail-open per-request.

### 6.1 Startup errors (fatal)

| Failure | Behavior |
|---|---|
| `--audit-log` parent dir doesn't exist and can't be created | `audit init failed: cannot create <dir>: <err>`. Exit 1. |
| File path not writable | `audit init failed: open <path>: <err>`. Exit 1. |
| `--audit-max-size-mb` ≤ 0 (or other size/age/backups flags) | `audit init failed: <flag> must be > 0`. Exit 1. |

`audit.NewWriter` does a startup probe (open + write zero bytes + close) so these errors surface loudly before the proxy accepts traffic.

### 6.2 Per-request errors (all fail-open)

| Failure | Behavior |
|---|---|
| Channel full (1024-record default buffer) | `Log` drops the record. Slog WARN: `audit channel full; dropping record`. Hot path unaffected. |
| `json.Marshal(record)` fails | Writer goroutine logs ERROR with `request_id` (never content). Skips that record. |
| `lumberjack.Logger.Write` fails (disk full, file deleted) | Writer logs ERROR. Continues trying on next record. Proxy keeps serving. |
| Audit file missing on next write | Lumberjack reopens transparently; log INFO `audit log reopened`. |

The crucial invariant: **a failure in the audit subsystem never blocks or delays an AI request.** The proxy keeps serving. Audit is observability, not gating.

### 6.3 `railcore logs` errors

| Failure | Behavior |
|---|---|
| Audit file doesn't exist | `logs: <path>: file not found. Has the proxy run yet?`. Exit 1. |
| Malformed JSON lines in file | Skip silently per line; print one summary warning at end. Exit 0. |
| `--follow` and file is renamed (rotation) | Detect inode change; reopen new file at offset 0. |
| `--follow` and file is deleted | Print warning; wait 1s; retry. Loop until SIGINT. |
| Ctrl-C in follow mode | Clean exit. No stack trace. |
| `-n N` ≤ 0 | `logs: -n must be > 0`. Exit 2. |

### 6.4 Hard invariants

- **No request/response body content in records.** Audit schema deliberately excludes prompt text, tool inputs, response chunks — only sizes.
- **No matched secret bytes in findings.** Carried through from sub-project #2 via `EnrichedFinding.MarshalJSON` which omits offset/length-derived substrings.
- **Audit file 0600 perms.** Lumberjack default; user-only.

---

## 7. Testing Strategy

TDD throughout.

### 7.1 Unit tests — `internal/audit/`

- `TestRecord_MarshalJSON` — full record marshals with all fields; optional fields with zero values are omitted.
- `TestNoopLogger_Log` — no panic.
- `TestNewWriter_HappyPath` — valid config + temp dir → no error, file created.
- `TestNewWriter_RejectsBadConfig` — `MaxSizeMB=0` errors. `Path=""` errors.
- `TestNewWriter_UnwritablePath` — `Path="/proc/something"` errors via startup probe.
- `TestWriter_LogAndClose` — log 100 records, close, read file: 100 valid JSON lines.
- `TestWriter_ChannelFull` — buffer=2, slow writer mock, log 100 rapidly: no panic, no blocking, WARN logged.
- `TestWriter_CloseIsIdempotent` — double-Close returns nil, no panic.
- `TestWriter_LogAfterClose` — no panic, record silently dropped.
- `TestWriter_ConcurrentLog` — 32 goroutines × 100 records each = 3200 lines in file. `-race` clean.

### 7.2 Unit tests — `internal/proxy/` (new)

- `TestProxy_AuditFuncInvokedOnContinue` — register capturing Logger, drive request, assert one record with `decision="continue"`.
- `TestProxy_AuditFuncInvokedOnBlock` — Block-emitting stage, assert record has `decision="block"` and non-empty `findings`.
- `TestProxy_AuditRecordVendorEndpoint` — Anthropic request → `vendor="anthropic"`, `endpoint="messages"`.
- `TestProxy_AuditRecordBytes` — request with N bytes body, response with M bytes → `bytes_in ≈ N`, `bytes_out > 0`.
- `TestProxy_AuditFuncNilIsSafe` — `AuditFunc=nil` → no panic.

### 7.3 Unit tests — `cmd/railcore/logs_test.go`

- `TestFormatRecord_Continue` — 200/continue record renders with `✓` and no findings.
- `TestFormatRecord_Block` — 403/block record renders with `✗`, `findings=N [rule1,rule2]`.
- `TestFormatRecord_NoVendor` — missing vendor/endpoint formats cleanly.
- `TestParseAuditFile_SkipsMalformed` — feed valid+malformed+valid lines, parser returns 2 records + skip count.

### 7.4 In-process integration — `internal/proxy/server_test.go`

- `TestProxy_AuditWrittenToFile` — real `audit.Writer` with temp-file path. Drive one request. Close writer. Read file. Assert one well-formed JSON record with expected fields.

### 7.5 End-to-end integration — `test/integration/audit_test.go`

- `TestAudit_E2E_RequestProducesAuditLine` — real Anthropic-shape request through full proxy → temp audit file → assert one JSON record.
- `TestAudit_E2E_BlockProducesAuditLineWithFindings` — same setup with path-block policy. Assert `decision=block` and `findings[0].detector=path-scan`.

### 7.6 CLI integration — `test/integration/cli_test.go` (append)

- `TestCLI_Logs_FileNotFound` — no audit file → "file not found", exit 1.
- `TestCLI_Logs_LastN` — write 10 records, `railcore logs -n 5` returns last 5.
- `TestCLI_Logs_JSON` — `--json` output is byte-for-byte the file content.
- `TestCLI_Logs_Follow` — start `railcore logs --follow` as subprocess, append records via parallel goroutine, assert they appear in subprocess stdout within timeout.

### 7.7 Manual acceptance test

1. `railcore init` to reset data dir.
2. `railcore proxy` with default audit log path.
3. In another terminal: `railcore logs --follow`.
4. Launch Claude Code through the proxy; ask it to do something innocuous.
5. Watch records appear live in the `logs --follow` output.
6. Trigger a block (paste an AWS key with a `block-aws` policy active).
7. Confirm block record appears with `decision=block` and `findings`.
8. Open the audit file in an editor; verify valid JSON Lines.
9. Record results in §11.

### 7.8 What's NOT tested

- **Lumberjack rotation under real load.** Trust the library's own test suite.
- **Crash-during-write semantics.** Spec'd as acceptable loss; no fuzz testing.
- **Windows-specific terminal rendering of `✓`/`✗`.** CI verifies build + tests pass; visual check is manual.

---

## 8. Done Definition

Sub-project #6 is complete when:

1. All unit and in-process integration tests in §7.1–7.4 pass on all three platforms in CI.
2. CI matrix stays green on `ubuntu-latest`, `macos-latest`, `windows-latest`.
3. The manual acceptance test in §7.7 passes against real Claude Code traffic.
4. The design doc and implementation are committed to the repo.

When these four hold, sub-project #7 (multi-tool support + protocol quirks) can begin without any audit-layer changes. Future enterprise work (SIEM forwarder, encrypted audit, signed chains) builds on this foundation.
