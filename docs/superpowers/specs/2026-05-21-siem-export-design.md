# Sub-project #9 — SIEM Export

**Status:** Design approved, pending spec review
**Date:** 2026-05-21
**Sub-project of:** Railcore post-MVP (enterprise audit delivery)

---

## 1. Goal

Ship every audit record and event to an HTTP SIEM collector in near-real-time, as batched NDJSON, with bounded in-memory retry so transient SIEM outages don't lose data. The local `audit.log` file stays the durable source of truth; the SIEM sink is best-effort live delivery layered alongside it.

This unblocks pilot deployments where a security team requires the audit trail in their SIEM (Splunk, Datadog, Sumo, Elastic) rather than on a developer laptop.

---

## 2. Non-goals

- **Syslog transport** (RFC5424/RFC3164). HTTP only.
- **Disk-spool + replay** — guaranteed delivery across proxy restart. The retry buffer is in-memory and bounded; a restart loses undelivered batches (but never loses the file copy).
- **Vendor-specific envelopes** — Splunk `{"event":...}` wrapping, Datadog JSON array. Plain NDJSON only; collectors do field extraction.
- **mTLS client certs to the SIEM.** Header-based auth only; the SIEM's server cert is verified against the system trust store.
- **Multiple simultaneous SIEM destinations.** One URL.
- **gzip compression** of the POST body.
- **Backfill** of records written to the file before the proxy started.

---

## 3. Module layout

```
internal/audit/                (leaf — stdlib + lumberjack only; no new dependency)
├── audit.go                   unchanged (Record, Event, Logger, NoopLogger)
├── writer.go                  unchanged (file Writer)
├── multi.go                   CREATE: MultiLogger fan-out
├── multi_test.go              CREATE: 4 tests
├── httpsink.go                CREATE: HTTPSink (batching + retry buffer + backoff)
├── httpsink_test.go           CREATE: 11 tests
├── audit_test.go              unchanged
└── writer_test.go             unchanged

cmd/railcore/
└── proxy.go                   MODIFY: --siem-* flags; construct HTTPSink + MultiLogger

docs/superpowers/specs/2026-05-21-siem-export-design.md   (this file)
docs/superpowers/plans/2026-05-21-siem-export.md          (next step)
```

**No new dependency.** `net/http`, `net/url`, `bytes`, `context`, `sync`, `sync/atomic`, `time`, `encoding/json`, `strings` are all stdlib. The retry buffer is a plain slice owned by one goroutine.

**Dependency direction (new edges):**

```
cmd/railcore ──→ audit.MultiLogger, audit.HTTPSink   (NEW — both constructed at startup)
```

No new cross-package internal edges. `internal/audit` remains a leaf. `internal/proxy` is unchanged — it already holds an `audit.Logger` via `proxy.Config.AuditFunc`, and `*MultiLogger` satisfies that interface.

---

## 4. Detailed design

### 4.1 `audit.MultiLogger` (`internal/audit/multi.go`)

A synchronous fan-out forwarding each call to every wrapped `Logger`.

```go
// MultiLogger forwards every Log and Event call to each wrapped Logger,
// in order. Used to tee audit output to the file Writer and the HTTP
// SIEM sink.
type MultiLogger struct {
    loggers []Logger
}

// NewMultiLogger returns a MultiLogger fanning out to the given loggers.
// nil entries are skipped. With zero non-nil loggers it behaves as a
// no-op.
func NewMultiLogger(loggers ...Logger) *MultiLogger

func (m *MultiLogger) Log(r Record)   // forward to each wrapped logger, in order
func (m *MultiLogger) Event(e Event)  // forward to each wrapped logger, in order
```

- **Synchronous fan-out, async sinks.** Both `Writer` and `HTTPSink` have non-blocking `Log`/`Event` (channel send, drop-on-full). So `MultiLogger.Log` is effectively non-blocking — N cheap channel sends. No goroutine, no buffering at the Multi layer.
- **No `Close` method.** `MultiLogger` does not own lifecycle. The proxy holds direct references to each concrete sink and defers `Close()` on them individually.
- **nil-skipping** is defense-in-depth; the proxy additionally never passes typed-nil pointers (see §4.4).

### 4.2 `audit.HTTPSink` config (`internal/audit/httpsink.go`)

```go
type HTTPConfig struct {
    URL              string        // required; the SIEM collector endpoint
    AuthHeader       string        // optional; e.g. "Authorization", "DD-API-KEY"
    AuthValue        string        // optional; the token/key (from env, not a flag)
    BatchSize        int           // lines per batch before flush; default 100
    FlushInterval    time.Duration // max age of a partial batch; default 5s
    MaxBufferBatches int           // retry-buffer cap in batches; default 64
    Timeout          time.Duration // per-POST HTTP timeout; default 10s
    BufferSize       int           // ingest channel capacity; default 1024
    BaseBackoff      time.Duration // first retry interval; default 1s
}
```

`NewHTTPSink` applies all defaults, validates `URL` (non-empty, parses, scheme is `http`/`https`), starts the background goroutine, and returns `(*HTTPSink, error)`.

### 4.3 `HTTPSink` type + lifecycle

```go
type HTTPSink struct {
    cfg       HTTPConfig
    client    *http.Client     // Timeout = cfg.Timeout
    logger    *slog.Logger
    ch        chan []byte      // each element = one marshaled JSON line
    closed    atomic.Bool
    closeOnce sync.Once
    done      chan struct{}
    wg        sync.WaitGroup
}

func NewHTTPSink(cfg HTTPConfig, logger *slog.Logger) (*HTTPSink, error)
func (s *HTTPSink) Log(r Record)    // marshal → non-blocking send; drop+WARN if full; no-op after Close
func (s *HTTPSink) Event(e Event)   // marshal → non-blocking send; drop+WARN if full; no-op after Close
func (s *HTTPSink) Close() error    // signal done, final best-effort flush, join goroutine; idempotent
```

`Log`/`Event` `json.Marshal` the record (in the caller's goroutine — microseconds) then `select { case s.ch <- line: default: WARN "siem ingest channel full; dropping record" }`. Identical non-blocking discipline to `Writer`. Both `Record` and `Event` are exported to the SIEM — policy reloads matter for compliance.

### 4.4 The batching goroutine

One goroutine owns all mutable state — no locks beyond the channel:

- `current [][]byte` — lines accumulating toward the next batch.
- `retryBuffer [][]byte` — finalized batch bodies awaiting (re)delivery, oldest first.
- `backoff time.Duration` — current retry interval, starts at `BaseBackoff`.

```
select:
  line := <-ch         → current = append(current, line)
                         if len(current) >= BatchSize: finalize(); tryDrain()
  <-flushTicker.C      → if len(current) > 0: finalize(); tryDrain()
  <-retryTimer.C       → tryDrain()
  <-done               → if len(current) > 0: finalize(); finalDrain(); return
```

- **`finalize()`** — join `current` with `\n` into one NDJSON body (trailing `\n`), append the body to `retryBuffer`, reset `current = nil`. If `len(retryBuffer) > MaxBufferBatches`: drop `retryBuffer[0]`, `WARN "siem retry buffer full; dropping oldest batch"`, increment a dropped counter.
- **`tryDrain()`** — while `retryBuffer` non-empty: POST `retryBuffer[0]`; on 2xx pop it and reset `backoff = BaseBackoff`; on non-2xx/transport-error stop, `retryTimer.Reset(backoff)`, then `backoff = min(backoff*2, 60s)`.
- **`finalDrain()`** on Close — one pass over `retryBuffer` bounded by a total `Timeout` budget (a shared context deadline); once the budget is spent the remaining batches are dropped with a logged count. `Close` blocks at most ~`Timeout`, not `len(retryBuffer) × Timeout`.

### 4.5 The POST

`POST <URL>` with:
- `Content-Type: application/x-ndjson`
- the configured auth header, when both `AuthHeader` and `AuthValue` are non-empty
- body = the NDJSON batch
- `http.Client.Timeout = cfg.Timeout`

Success = HTTP 2xx. Non-2xx or any transport error (DNS, refused, TLS, timeout) = failure. The SIEM's TLS server cert is verified against the system trust store — no custom CA (the SIEM is a real internet endpoint, not a MITM target).

### 4.6 Backoff

Exponential: `BaseBackoff` (default 1s) → 2s → 4s → … capped at 60s. Resets to `BaseBackoff` on the first successful POST. While the SIEM is down, batches accumulate in `retryBuffer` up to `MaxBufferBatches`, then steady-state drop-oldest. The local `audit.log` file is unaffected throughout.

### 4.7 Configuration — CLI flags

Five new flags on the `proxy` subcommand, in the `--audit-*` style of sub-project #6:

| Flag | Default | Purpose |
|---|---|---|
| `--siem-url` | `""` | SIEM collector endpoint. Empty = SIEM export disabled. |
| `--siem-auth-header` | `""` | Header name for auth, e.g. `Authorization`, `DD-API-KEY`. Empty = no auth header. |
| `--siem-batch-size` | `100` | Records per batch before flush. |
| `--siem-flush-interval` | `5s` | Max age of a partial batch. |
| `--siem-max-buffer-batches` | `64` | Retry-buffer cap (batches) before drop-oldest. |

### 4.8 Auth value from the environment

The auth **value** (token/API key) is read from the `RAILCORE_SIEM_AUTH` environment variable — never a CLI flag. Flag values appear in `ps`, shell history, and process listings; a secret must not. The flag carries only the header *name*; the env var carries the *value*.

```
RAILCORE_SIEM_AUTH="Splunk 8e8f4f...token..." \
  railcore proxy \
    --siem-url https://hec.example:8088/services/collector/raw \
    --siem-auth-header Authorization
```

If `--siem-auth-header` is set but `RAILCORE_SIEM_AUTH` is empty: WARN at startup ("siem auth header configured but RAILCORE_SIEM_AUTH is empty"), proceed unauthenticated (some collectors accept unauthenticated POSTs on a trusted network).

### 4.9 Proxy wiring (`cmd/railcore/proxy.go`)

After the existing audit Writer construction:

```go
var siemSink *audit.HTTPSink
if *siemURL != "" {
    sink, err := audit.NewHTTPSink(audit.HTTPConfig{
        URL:              *siemURL,
        AuthHeader:       *siemAuthHeader,
        AuthValue:        os.Getenv("RAILCORE_SIEM_AUTH"),
        BatchSize:        *siemBatchSize,
        FlushInterval:    *siemFlushInterval,
        MaxBufferBatches: *siemMaxBufferBatches,
    }, logger)
    if err != nil {
        logger.Error("siem sink init failed", "err", err.Error())
        os.Exit(1)
    }
    siemSink = sink
    defer func() { _ = siemSink.Close() }()
}

// Assemble the effective audit logger from the live sinks.
var sinks []audit.Logger
if auditWriter != nil {
    sinks = append(sinks, auditWriter)
}
if siemSink != nil {
    sinks = append(sinks, siemSink)
}
var auditLogger audit.Logger = audit.NoopLogger{}
switch len(sinks) {
case 1:
    auditLogger = sinks[0]
case 2:
    auditLogger = audit.NewMultiLogger(sinks...)
}
```

`auditWriter` and `siemSink` are concrete pointer types — the `!= nil` checks are on the concrete pointers, avoiding the typed-nil-interface trap. Only real sinks land in `sinks`.

**`defer` ordering:** `auditWriter.Close()` is deferred first (existing, sub-project #6), `siemSink.Close()` second. LIFO → on shutdown the SIEM sink closes first (final best-effort flush of its retry buffer), then the file Writer drains. Both Closes are idempotent.

---

## 5. Data flow

```
HTTP request → proxy → pipeline → (defer) auditLogger.Log(record)
                                    └─ MultiLogger.Log
                                        ├─ Writer.Log    → file channel → lumberjack file  (durable)
                                        └─ HTTPSink.Log  → ingest channel
                                                            └─ batching goroutine
                                                                ├─ accumulate into `current`
                                                                ├─ finalize() at BatchSize or FlushInterval
                                                                ├─ POST NDJSON batch to SIEM
                                                                └─ on failure: retryBuffer + backoff

Policy reload (sub-project #8) → auditLogger.Event(event)
                                  └─ MultiLogger.Event → same fan-out (file + SIEM)
```

When `--siem-url` is unset, `auditLogger` is the file `Writer` alone — identical to pre-#9 behavior.

---

## 6. Error handling

| Condition | Behavior |
|---|---|
| `--siem-url` empty | SIEM export disabled. No sink constructed. |
| `--siem-url` unparseable / non-http(s) scheme | `NewHTTPSink` errors. Proxy logs ERROR, `os.Exit(1)` at startup — fail fast on a config bug. |
| `--siem-auth-header` set, `RAILCORE_SIEM_AUTH` empty | WARN at startup; proceed with no auth header. |
| SIEM POST non-2xx | Batch failed. Stays in `retryBuffer`. `retryTimer` armed at current backoff; backoff doubles (cap 60s). |
| SIEM POST transport error (DNS, refused, TLS, timeout) | Same as non-2xx. |
| `retryBuffer` exceeds `MaxBufferBatches` | Oldest batch dropped, `WARN "siem retry buffer full; dropping oldest batch"`, dropped counter incremented. Newest data kept. |
| Ingest channel full | Record dropped at ingest, `WARN "siem ingest channel full; dropping record"`. Same discipline as `Writer`. |
| `json.Marshal` of a Record/Event fails | Skip that line, ERROR logged, continue. (Effectively impossible for these structs.) |
| `Log`/`Event` after `Close` | No-op (`closed.Load()` guard). No panic. |
| `Close()` called twice | Idempotent via `closeOnce`. |
| Shutdown with batches buffered | `Close()` runs `finalDrain()` — one best-effort pass bounded by a total budget of `Timeout`. Once the budget is exhausted the remaining batches are dropped with a logged count. `Close` blocks at most ~`Timeout` (plus one in-flight POST), not `len(retryBuffer) × Timeout`. |
| SIEM down for the whole proxy lifetime | `retryBuffer` saturates at `MaxBufferBatches`, steady-state drop-oldest. Proxy serves traffic normally. The local `audit.log` has every record — no audit data lost to disk. |

**Invariant:** the SIEM sink can never block request handling or crash the proxy. Every failure path degrades to "log a WARN, keep serving, the file is still complete."

---

## 7. Testing

### 7.1 `internal/audit/multi_test.go` (4 tests)

- `TestMultiLogger_ForwardsLogToAll`
- `TestMultiLogger_ForwardsEventToAll`
- `TestMultiLogger_SkipsNilLoggers`
- `TestMultiLogger_ZeroLoggersIsNoop`

A fake logger struct with a mutex-guarded slice of received records/events.

### 7.2 `internal/audit/httpsink_test.go` (11 tests)

All use `httptest.NewServer` as the fake SIEM. The handler records request bodies + headers; failure variants return non-2xx.

- `TestHTTPSink_NewRejectsEmptyURL`
- `TestHTTPSink_NewRejectsBadURL`
- `TestHTTPSink_DeliversBatch` — log `BatchSize` records → one POST with that many NDJSON lines.
- `TestHTTPSink_FlushIntervalDeliversPartialBatch` — log 3 records (< batch size), wait past `FlushInterval` → POST with 3 lines.
- `TestHTTPSink_SetsAuthHeader` — header+value configured → fake SIEM saw the auth header.
- `TestHTTPSink_NoAuthHeaderWhenUnconfigured`
- `TestHTTPSink_RetriesOnServerError` — fake SIEM returns 503 twice then 200 → batch eventually delivered.
- `TestHTTPSink_DropsOldestWhenBufferFull` — fake SIEM always 503, tiny `MaxBufferBatches`, flood records → `WARN "dropping oldest batch"` captured; sink does not block or grow unbounded.
- `TestHTTPSink_LogAfterCloseIsSafe`
- `TestHTTPSink_CloseFlushesPending` — log a partial batch, `Close()` immediately → fake SIEM still received it.
- `TestHTTPSink_CloseIdempotent`

Tests construct `HTTPConfig` with small intervals (`BaseBackoff`, `FlushInterval`) so they run in well under a second. Success assertions poll the fake SIEM's received-count via a deadline loop — no fixed sleeps. Body assertions: each NDJSON line `json.Unmarshal`s back to a `Record`/`Event`; line count matches.

### 7.3 Proxy smoke test

The plan's build step starts the proxy with `--siem-url` pointed at a throwaway local HTTP listener, makes one request, and confirms an NDJSON POST arrived.

### 7.4 Regression sweep

`go test -race -count=1 ./...` stays green. Expected total climbs from 304 → ~319.

### 7.5 Manual acceptance (recorded in §11)

1. Run a local collector stand-in (a small Go HTTP listener that prints request bodies + headers).
2. `RAILCORE_SIEM_AUTH=test-token railcore proxy --siem-url http://127.0.0.1:8088/collector --siem-auth-header Authorization --siem-flush-interval 2s`
3. Run an AI request through Claude Code / Cursor.
4. Within ~2s the collector prints an NDJSON POST containing the request's audit record, with `Authorization: test-token`.
5. Edit the policy file → confirm the `policy_reload` event also reaches the collector (Events exported, not just Records).
6. Kill the collector, make more requests, observe WARN backoff lines; restart the collector, confirm buffered batches drain.
7. Confirm `~/.railcore/audit.log` has every record throughout — the file is unaffected by SIEM availability.

---

## 8. Done definition

Sub-project #9 is complete when:

1. All unit tests in §7.1–7.2 pass under `-race -count=1`.
2. `go test -race -count=1 ./...` for the whole repo remains green (no regression in the existing 304 tests; new total ~319).
3. `go vet ./...` and `gofmt -l .` clean.
4. The proxy smoke test in §7.3 passes.
5. Manual acceptance in §7.5 passes.
6. Acceptance result recorded in §11 of this spec.

---

## 9. Open questions

None. Items deliberately deferred are documented as out-of-scope in §2: syslog transport, disk-spool replay, vendor envelopes, mTLS, multiple destinations, gzip, backfill.
