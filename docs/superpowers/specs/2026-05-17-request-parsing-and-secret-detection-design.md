# Sub-project #2 — Request Parsing + Secret Detection

**Status:** Design approved, pending spec review
**Date:** 2026-05-17
**Sub-project of:** Railcore MVP (see `part1.md`, `part2.md` in repo root)
**Builds on:** [Sub-project #1](2026-05-15-core-forward-proxy-design.md) (core forward proxy + TLS interception)

---

## 1. Purpose and Scope

Turn Railcore from a transparent passthrough proxy into an actual AI firewall. Parse outgoing AI requests, scan extracted prompt content for high-confidence secrets, and either log (default) or block (opt-in) before the request reaches the upstream API. This is the wedge demo from [`part1.md`](../../../part1.md) §1.3: *"Your engineers are accidentally sending AWS keys to Claude. We stop that."*

**In scope:**

- Vendor-specific parsers for two endpoints:
  - `POST /v1/chat/completions` on `api.openai.com`
  - `POST /v1/messages` on `api.anthropic.com`
- A curated catalog of 30 secret patterns (AWS, GitHub, Stripe, OpenAI, Anthropic, Google, Slack, Discord, npm/pypi, private keys, JWT, DB URLs, generic high-entropy).
- A `pipeline.Stage` (`secretscan`) that wires parser + detector into the existing chain from sub-project #1.
- Opt-in BLOCK via `--block-on-detect` CLI flag (or `RAILCORE_BLOCK_ON_DETECT=1` env var). High-severity findings only.
- JSON 403 response body that surfaces pattern name + role + message index — but never the matched bytes.
- Per-request scan logging via `log/slog`. Audit-log persistence is sub-project #6's problem.

**Out of scope (handled by later sub-projects):**

- PII detection (email, phone, SSN, credit card). Deferred entirely. The detector framework here is generic enough that PII slots in as another `Pattern` set later.
- Custom user patterns from a config file — sub-project #3 (policy engine).
- Per-pattern allowlists / suppress-once UX — sub-project #3.
- Per-host or per-tool routing (e.g. "only scan Anthropic, not OpenAI") — sub-project #3.
- The `redact` action (replace match with `[REDACTED]` and forward) — sub-project #4.
- Response-body inspection — explicitly deferred; the request-only wedge is the focus.
- OpenAI embeddings, Anthropic tool-use, Gemini, or any vendor beyond the two listed endpoints — sub-project #7.

---

## 2. Decisions Locked in During Brainstorming

| Decision | Choice | Rationale |
|---|---|---|
| Default action when a detector fires | **WARN** by default; `--block-on-detect` flag flips to BLOCK | Matches part1.md §9.3 ("false positives are the #1 product risk") while keeping the "oh shit" demo a single flag away. |
| Pattern coverage | **Curated ~30 high-value patterns**, not the full `trufflehog` catalog (~800) | Low FP rate is more valuable than coverage for a wedge. Patterns extracted from `secretlint`, `trufflehog`, `gitleaks`. |
| Vendor + endpoint scope | **OpenAI `chat.completions` + Anthropic `messages` only** | The two endpoints exercised by Cursor and Claude Code — the tools already verified end-to-end. Gemini blocked by cert pinning, deferred. |
| PII detection | **Defer entirely** to a future sub-project | PII has materially different UX (allowlists for test data, per-field policies). Rushing those decisions for marginal demo value is a trap. |
| Request vs response | **Request-only** | Part1.md wedge is exclusively request-side. Response scanning through streaming SSE is a hard problem deserving its own design. |
| Architecture | **Per-vendor typed parsers + flat detector function** | Simplest shape that ships. Detector pluggability comes free from Go function values; over-engineering an interface now risks getting the extension points wrong. |

---

## 3. Repo Layout

Three new packages under `internal/`. Existing packages unchanged except for a small body-caching change in `internal/proxy/upstream.go` (3 lines) and a stage registration in `cmd/railcore/main.go`.

```
railcore/
├── cmd/
│   └── railcore/
│       └── main.go                       # +1 stage registration, +1 CLI flag, remove no-op forwardStage
├── internal/
│   ├── ca/                               # unchanged
│   ├── pipeline/                         # unchanged (stage contract is stable)
│   ├── proxy/                            # 3-line change: stash body in rc.Metadata before Chain.Run
│   ├── trust/                            # unchanged
│   │
│   ├── parser/                           # NEW — vendor request parsing
│   │   ├── parser.go                     # ParsedRequest, TextSegment, ParseRequest dispatch
│   │   ├── openai.go                     # POST /v1/chat/completions
│   │   ├── anthropic.go                  # POST /v1/messages
│   │   └── parser_test.go
│   │
│   ├── detector/                         # NEW — scan text for secrets
│   │   ├── detector.go                   # Finding type, Severity enum, Scan, AddPattern
│   │   ├── patterns.go                   # the 30 curated patterns
│   │   ├── entropy.go                    # Shannon entropy helper
│   │   ├── corpus_test.go                # FP-rate sanity check vs a fixed corpus
│   │   └── detector_test.go
│   │
│   └── stage/                            # NEW — concrete pipeline.Stage implementations
│       └── secretscan/
│           ├── stage.go                  # Config + Stage + Process wiring
│           └── stage_test.go
└── test/
    └── integration/
        └── secretscan_test.go            # end-to-end block + warn scenarios
```

Package dependency graph (all dependencies point downward):

```
cmd/railcore
   └── internal/stage/secretscan
          ├── internal/parser     (leaf — depends only on stdlib)
          ├── internal/detector   (leaf — depends only on stdlib + regexp)
          └── internal/pipeline   (existing leaf, unchanged)

internal/proxy   ──→  internal/pipeline   (existing edge, unchanged)
```

`parser` and `detector` must remain leaf packages: no imports from `railcore/internal/*`. `secretscan` is the only package that imports both, and it implements `pipeline.Stage`.

---

## 4. Components

### 4.1 `internal/parser` — vendor request parsing

Knows JSON shapes; knows nothing about HTTP, detection, or pipelines.

**API (public surface within the module):**

```go
// ParsedRequest is the normalized view of an AI-vendor request.
type ParsedRequest struct {
    Vendor   string         // "openai" | "anthropic"
    Endpoint string         // "chat.completions" | "messages"
    Texts    []TextSegment  // all scannable prose extracted from the body
    Raw      []byte         // original request body (kept for redact action in #4)
}

// TextSegment is one piece of prose pulled from the request — a user
// message, system prompt, assistant turn, or tool result.
type TextSegment struct {
    Role    string  // "user" | "assistant" | "system" | "tool"
    Index   int     // position in the original messages array
    Content string  // raw text
}

// ParseRequest dispatches by host + method + path. Returns (nil, nil)
// when the request is not a known AI endpoint — the stage should treat
// that as "nothing to scan" and pass through. Returns (nil, err) only
// when a known endpoint has a malformed body.
func ParseRequest(host string, req *http.Request, body []byte) (*ParsedRequest, error)
```

**Vendor implementations:**

- `openai.go` — matches `host == "api.openai.com"`, `req.Method == POST`, `req.URL.Path == "/v1/chat/completions"`. Unmarshals into a typed `openAIChatRequest` struct, flattens the `messages` array into segments. Tool definitions are NOT scanned (only tool inputs/outputs would be, if present, but tool-use is out of scope here).
- `anthropic.go` — matches `host == "api.anthropic.com"`, path `/v1/messages`. Top-level `system` field becomes a segment with `Role="system"`. `messages[].content` can be either a string or an array of content blocks (`{type: "text", text: "..."}`) — both shapes are flattened.

**What's scanned within a request:** all role types (`user`, `assistant`, `system`, `tool`). Tool *definitions* (function schemas) are not scanned — they're usually fixed JSON schema text without user content.

### 4.2 `internal/detector` — secret detection

Pure text-in, findings-out. No HTTP, no JSON, no logging.

**API:**

```go
type Severity int
const (
    SeverityLow Severity = iota
    SeverityMedium
    SeverityHigh
)

type Finding struct {
    Pattern  string    // pattern name, e.g. "aws_access_key_id"
    Severity Severity
    Offset   int       // byte offset within the input
    Length   int
}

// Scan runs all registered patterns over text and returns findings
// sorted by offset. Always pure: no I/O, no logging, no side effects.
func Scan(text string) []Finding

// AddPattern registers an additional pattern. Intended for sub-project #3's
// YAML policy loader. Not part of a stable API; behaviour may change.
func AddPattern(p Pattern)
```

`Finding` deliberately does NOT include the matched substring. The pattern name + offset is enough for the audit record without echoing secrets through Railcore's own internals.

**Pattern shape:**

```go
type Pattern struct {
    Name              string
    Severity          Severity
    Regex             *regexp.Regexp
    EntropyThreshold  float64   // 0 = no entropy filter
    EntropySpan       func(match []int) (start, end int)  // optional, defaults to whole match
}
```

The entropy span lets a pattern check entropy on only the random portion — e.g. AWS access keys check entropy on the 16-char suffix after the `AKIA` prefix, not the prefix itself.

**`Scan` semantics:**

- Compiles patterns once at package init.
- Iterates patterns in registration order. For each pattern: `regex.FindAllStringIndex(text, -1)`. For each match: if `EntropyThreshold > 0`, compute Shannon entropy on `EntropySpan(match)`; skip if below threshold.
- Returns all surviving findings, sorted by offset.
- Overlap is allowed: two patterns may flag the same bytes. The 30 curated patterns are designed not to overlap; if they ever do, both fire.

### 4.3 `internal/stage/secretscan` — pipeline integration

The only package that touches HTTP, JSON, AND detection. Implements `pipeline.Stage`.

```go
type Config struct {
    BlockOnDetect bool   // false = WARN only; true = Block on any High finding
}

type Stage struct {
    cfg Config
    log *slog.Logger
}

func New(cfg Config, log *slog.Logger) *Stage

func (s *Stage) Name() string { return "secret-scan" }
func (s *Stage) Process(ctx context.Context, rc *pipeline.RequestCtx) (pipeline.Decision, error)
```

`Process` does:

1. Read the request body from `rc.Metadata["body"]` (cached by the proxy before pipeline runs — see §4.4 below).
2. `parser.ParseRequest(rc.Host, rc.Req, body)` — if `(nil, nil)`, return `Continue` (not an AI endpoint we know).
3. If `(nil, err)`, log at DEBUG and return `Continue` (fail-open on malformed AI bodies).
4. For each `TextSegment`: skip if `!utf8.ValidString(seg.Content)`. Otherwise run `detector.Scan(seg.Content)`.
5. Annotate `rc.Metadata["secretscan.findings"] = []EnrichedFinding{...}` where each enriched finding carries the original `Finding` plus the segment role + index. Used by future audit-log sub-project.
6. If any High-severity finding AND `cfg.BlockOnDetect`: log at WARN with pattern names + counts (but not matched bytes), return `Block`.
7. Else if any findings (any severity): log at INFO with counts per severity. Return `Continue`.
8. Else (no findings on a parsed AI request): return `Continue` silently.

### 4.4 `internal/proxy` change — body caching

The proxy's handler in `internal/proxy/upstream.go` already reads the full request body into memory (the 32 MiB cap enforcement). It then replays it via `byteReader`. The 3-line change: before calling `s.cfg.Pipeline.Run(...)`, stash the bytes in `rc.Metadata["body"] = body`. Stages read from there instead of trying to re-read `rc.Req.Body`. This is a minor refactor with no behaviour change for non-scanning paths.

---

## 5. Request Data Flow

Walks an actual Claude Code → Anthropic request containing an AWS key, with `--block-on-detect` enabled.

```
 1. Claude Code sends:
       POST https://api.anthropic.com/v1/messages
       {
         "model": "claude-opus-4-7",
         "messages": [
           {"role": "user", "content": "review:\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE..."}
         ]
       }
 2. proxy.handler intercepts (existing sub-project #1 code).
 3. proxy.handler reads body fully (32 MiB cap, existing).
 4. proxy.handler stashes body in rc.Metadata["body"] = []byte{...}     ← NEW
 5. proxy.handler runs pipeline.Chain.Run(ctx, rc).
    ──────────────────────────────────────────────────────
 6. secretscan.Stage.Process(ctx, rc):
       a. body := rc.Metadata["body"].([]byte)
       b. parsed := parser.ParseRequest("api.anthropic.com", rc.Req, body)
          → ParsedRequest{
              Vendor: "anthropic",
              Endpoint: "messages",
              Texts: [TextSegment{Role:"user", Index:0, Content:"review:\n..."}]
            }
       c. for seg in parsed.Texts:
            findings := detector.Scan(seg.Content)
            → [Finding{Pattern:"aws_access_key_id", Severity:High, Offset:14, Length:20}]
       d. rc.Metadata["secretscan.findings"] = [...]
       e. cfg.BlockOnDetect==true AND ≥1 High finding → return Block
    ──────────────────────────────────────────────────────
 7. pipeline.Chain returns Block.
 8. proxy.handler returns 403 with JSON body:
       {
         "error": "blocked by railcore policy",
         "request_id": "<uuid>",
         "detector": "secret-scan",
         "findings": [
           {"pattern":"aws_access_key_id", "severity":"high",
            "role":"user", "message_index":0}
         ]
       }
 9. Claude Code receives 403, surfaces the JSON body to the user.
10. proxy.log emits the per-request completion line (existing #1):
       host=api.anthropic.com status=403 decision=block bytes_out=421
```

**Key invariants:**

- The pipeline runs after the request body is fully read but **before any bytes leave the proxy headed upstream**. The Block path never dials upstream — same security guarantee as sub-project #1.
- **Matched bytes are never echoed.** Not in the 403 body, not in logs, not in `Finding`. Pattern names and locations are enough for the audit record.
- **WARN mode** (default): step 6e returns `Continue` regardless. Findings get logged at INFO; upstream forwarding proceeds normally.
- **Non-AI traffic**: step 6b returns `(nil, nil)`. Stage returns `Continue` immediately. Per-request cost: one map lookup + one host string comparison.

---

## 6. Error Handling

Inherits sub-project #1's posture; adds these specifics for the new stage.

**Two posture rules:**

1. **Fail-open on detection errors.** Parser crash, regex panic, malformed JSON — request still goes upstream. The detector failing is a Railcore bug, not a user policy violation.
2. **Fail-closed only for confirmed High findings with `BlockOnDetect=true`.** Everything else is logged but allowed.

| Failure | Response |
|---|---|
| Request body is not JSON | Parser returns `(nil, nil)`. Stage returns Continue. Logged at DEBUG. |
| Body is JSON but matches no known vendor schema | Parser returns `(nil, nil)`. Stage returns Continue. No log. |
| JSON matches schema but a required field is missing | Parser returns `(nil, err)`. Stage logs at DEBUG, returns Continue. |
| Regex compile failure at startup | Crash the process with a clear error. Bad patterns must not ship to runtime — compile once in `init()`. |
| Regex match panic at runtime | Caught by existing `Chain.runStage` recover from sub-project #1. Stage decision degrades to Continue. Logged at ERROR with stack. |
| Pattern matches but match span is invalid | Skip that finding, log at WARN, continue scanning other patterns. |
| Body exceeds 32 MiB | Proxy returns 413 before the stage ever runs. |
| Body contains non-UTF-8 bytes within a segment | `utf8.ValidString(seg.Content)` check skips that segment. Log at DEBUG. |
| `BlockOnDetect=true` but only Medium/Low findings | Continue. Findings logged at INFO. |

**Log lines emitted by the stage:**

- No findings on a parsed AI request: nothing extra.
- Any findings, WARN mode: `INFO secretscan findings vendor=anthropic endpoint=messages high=2 medium=0 low=0 patterns=[aws_access_key_id,aws_secret_access_key] request_id=...`
- Block fires: `WARN secretscan blocked` with the same fields.

Pattern names appear in logs; matched bytes do not.

**Explicitly NOT handled in this cycle:**

- Allowlists / suppress-once UX — sub-project #3.
- Detector FP-rate CI gate — measurement happens (§7.4 below), enforcement does not.

---

## 7. Testing Strategy

TDD throughout. Three layers, same shape as sub-project #1.

### 7.1 Unit tests (per package)

| Package | Critical tests |
|---|---|
| `internal/parser` | OpenAI parser extracts user/system/assistant segments from a minimal `chat.completions` request. Anthropic parser handles `system` field plus both string and content-block-array forms of `messages[].content`. Unknown host → `(nil, nil)`. Wrong path on known host → `(nil, nil)`. Malformed JSON → `(nil, err)`. Empty messages array → empty segments. |
| `internal/detector` | Each of the 30 patterns has a positive test (sample real-world key matches) and a negative test (known false-positive does not). AWS access-key pattern: `AKIA` + low-entropy suffix does NOT match; `AKIA` + real-entropy suffix DOES match. Shannon entropy returns 0 for empty string and matches reference values. `Scan` returns findings sorted by offset. Overlap: two patterns on identical bytes both fire. |
| `internal/stage/secretscan` | Non-AI host → Continue, no scanning, no logs. AI host with no findings → Continue, no log. Findings + `BlockOnDetect=false` → Continue, INFO log. High findings + `BlockOnDetect=true` → Block, WARN log. Only Medium/Low + `BlockOnDetect=true` → Continue (Medium/Low never block). Logs include pattern names but never matched bytes. Concurrent invocations are race-clean. |

### 7.2 In-process integration tests (extend `internal/proxy/server_test.go`)

Reuse the existing test helpers (fake `httptest.NewTLSServer` upstream, proxy on `localhost:0`):

1. **OpenAI request with AWS key, WARN mode**: synthetic `chat.completions` POST containing a fake AWS key in the user message. Client gets 200 from the fake upstream. Railcore log shows `decision=continue` plus a separate INFO line `secretscan high=1`.
2. **OpenAI request with AWS key, BLOCK mode**: same request, stage configured with `BlockOnDetect=true`. Client gets 403. Upstream's request counter stays at 0. Response body parses as JSON with the expected `findings` array. **Matched bytes do not appear anywhere in the 403 body.**
3. **Anthropic request with GitHub token in `system` field**: exercises the Anthropic parser path including the top-level `system` field.
4. **Non-AI request unaffected**: `curl https://example.test/` — stage returns Continue immediately. No scanning logs. Upstream is dialed normally.
5. **Base64-encoded secret**: known limitation, documented via test. The pattern does not match base64-wrapped keys.
6. **Detector panics on pathological input** (test-only detector via `AddPattern`): proves `Chain.runStage` recovery still works. Client gets 200 (fail-open).

### 7.3 End-to-end integration tests (extend `test/integration/`)

A new file `test/integration/secretscan_test.go`:

1. **Real-world AWS key gets blocked**: build the proxy with secretscan + `BlockOnDetect=true`. Send a `chat.completions` request with `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` in the user content. Assert 403. Assert no upstream hit.
2. **Test-fixture-like key passes**: send a request containing `AKIA0000000000000000` (all zeros — fails entropy check). Assert 200, no finding logged.

### 7.4 Detector corpus benchmark (measurement only, no CI gate)

`internal/detector/corpus_test.go` runs `Scan` over a small bundled corpus of known-clean text (~50 KB extracted from `cmd/railcore/main.go` plus standard library snippets). Asserts FP count ≤ 1. Catches regressions when patterns are added later. Runs under `go test ./...` but is not a hard CI gate yet — measurement is what matters at MVP.

### 7.5 Manual acceptance test

With `--block-on-detect`, run Claude Code through the proxy. Paste a synthetic AWS key into a prompt:

```
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

Verify:
- Claude Code receives 403 with a JSON body listing the findings.
- Proxy log shows `decision=block` and the pattern names but not the matched bytes.
- Without `--block-on-detect`, the same prompt goes through but logs `secretscan high=2`.

Record the result in this spec's §10 Acceptance Result section (added on completion).

---

## 8. The Pattern Catalog

30 patterns shipping in this sub-project. Each gets one entry in `internal/detector/patterns.go` (name, severity, regex, optional entropy threshold) and a unit test pair (one positive, one negative).

| # | Name | Severity | What it matches |
|---|---|---|---|
| 1 | `aws_access_key_id` | High | `AKIA[0-9A-Z]{16}` + entropy ≥ 3.5 on suffix |
| 2 | `aws_secret_access_key` | High | `[A-Za-z0-9/+=]{40}` near "aws"/"secret" hint + entropy ≥ 4.5 |
| 3 | `aws_session_token` | High | Long base64 strings beginning with `FwoG` or `IQoJ` |
| 4 | `github_pat_classic` | High | `ghp_[A-Za-z0-9]{36}` |
| 5 | `github_pat_fine_grained` | High | `github_pat_[A-Za-z0-9_]{82}` |
| 6 | `github_oauth_token` | High | `gho_[A-Za-z0-9]{36}` |
| 7 | `github_app_token` | High | `(ghu\|ghs)_[A-Za-z0-9]{36}` |
| 8 | `gitlab_pat` | High | `glpat-[A-Za-z0-9_-]{20}` |
| 9 | `stripe_secret_live` | High | `sk_live_[A-Za-z0-9]{24,}` |
| 10 | `stripe_restricted_live` | High | `rk_live_[A-Za-z0-9]{24,}` |
| 11 | `openai_api_key` | High | Legacy `sk-[A-Za-z0-9]{20}T3BlbkFJ...` + new `sk-proj-...` form |
| 12 | `anthropic_api_key` | High | `sk-ant-[A-Za-z0-9_-]{86,}` |
| 13 | `google_api_key` | High | `AIza[0-9A-Za-z_-]{35}` |
| 14 | `google_oauth_client_secret` | High | `GOCSPX-[A-Za-z0-9_-]{28}` |
| 15 | `google_service_account_json` | High | JSON containing `"type": "service_account"` AND `"private_key": "-----BEGIN PRIVATE KEY-----"` |
| 16 | `slack_bot_token` | High | `xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+` |
| 17 | `slack_user_token` | High | `xoxp-[0-9]+-[0-9]+-[0-9]+-[A-Fa-f0-9]+` |
| 18 | `slack_app_token` | High | `xapp-[0-9]+-[A-Z0-9]+-[0-9]+-[A-Fa-f0-9]+` |
| 19 | `slack_webhook_url` | Medium | `https://hooks.slack.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[A-Za-z0-9]+` |
| 20 | `discord_bot_token` | High | `[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}` |
| 21 | `discord_webhook_url` | Medium | `https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+` |
| 22 | `npm_token` | High | `npm_[A-Za-z0-9]{36}` |
| 23 | `pypi_token` | High | `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}` |
| 24 | `private_key_rsa` | High | `-----BEGIN RSA PRIVATE KEY-----` |
| 25 | `private_key_openssh` | High | `-----BEGIN OPENSSH PRIVATE KEY-----` |
| 26 | `private_key_ec` | High | `-----BEGIN EC PRIVATE KEY-----` |
| 27 | `private_key_pkcs8` | High | `-----BEGIN PRIVATE KEY-----` |
| 28 | `jwt` | Medium | `ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}` — Medium because of FP rate |
| 29 | `db_url_with_password` | Medium | `(postgres\|mysql\|mongodb)(\+srv)?://[^:]+:[^@/]+@[^/]+` |
| 30 | `generic_high_entropy_assignment` | Low | `(?i)(password\|secret\|api[_-]?key\|token)\s*[:=]\s*['"]?([A-Za-z0-9/+=_-]{20,})['"]?` + entropy ≥ 4.0 on the value |

**Catalog properties:**

- 25 High, 4 Medium, 1 Low. Only High is eligible for Block when `--block-on-detect` is set.
- Patterns with historically high FP rates (#11, #28, #29, #30) are Medium or Low so they never block.
- **Provenance:** patterns derived from open-source `secretlint` (MIT), `trufflehog` (AGPL for some pattern files; the regex *strings themselves* are facts, not copyrightable expression — we cite the source in the patterns.go header for hygiene), and `gitleaks` (MIT). Documented in the file's package comment.

---

## 9. Configuration

Configuration surface is intentionally minimal for this cycle.

### 9.1 CLI flag

```bash
./railcore proxy [--port N] [--data-dir PATH] [--block-on-detect]
```

`--block-on-detect` is a bool, default `false`. When set, the secretscan stage returns Block on any High-severity finding.

### 9.2 Env var fallback

`RAILCORE_BLOCK_ON_DETECT=1` flips the same switch. Standard precedence: CLI flag wins over env var.

### 9.3 Runtime wiring (cmd/railcore/main.go)

```go
blockOnDetect := *blockFlag || envFlag("RAILCORE_BLOCK_ON_DETECT")
chain.Register(secretscan.New(secretscan.Config{
    BlockOnDetect: blockOnDetect,
}, logger))
// forwardStage is removed in this sub-project — it was a no-op.
```

### 9.4 Not configurable in this cycle

Deferred to sub-project #3 (policy engine) or later:

- Custom regex patterns from a config file.
- Per-pattern allowlists.
- Per-host policies.
- Severity-level routing (e.g., "block on High, redact on Medium").
- Redact action.
- PII detector.

---

## 10. Done Definition

Sub-project #2 is complete when:

1. All unit and in-process integration tests in §7.1 and §7.2 pass on all three platforms in CI.
2. CI matrix stays green on `ubuntu-latest`, `macos-latest`, `windows-latest`.
3. The manual acceptance test in §7.5 passes: Claude Code with `--block-on-detect` receives a 403 when a synthetic AWS key is included in a prompt; without the flag, the same request proceeds with a WARN-level log entry.
4. The design doc and implementation are committed to the repo.

When these four hold, sub-project #3 (policy engine) can begin building on the `AddPattern` hook and the `pipeline.Stage` framework that this sub-project extends.
