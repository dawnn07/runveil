# Sub-project #4 — Path-Based Rules

**Status:** Design approved, pending spec review
**Date:** 2026-05-17
**Sub-project of:** Railcore MVP (see `part1.md`, `part2.md` in repo root)
**Builds on:** [Sub-project #3](2026-05-17-policy-engine-design.md) (policy engine), which builds on #2 (parser + detector) and #1 (proxy).

---

## 1. Purpose and Scope

Govern AI agent access to sensitive file paths. When Claude Code's agent invokes `Read`/`Write`/`Edit`/`MultiEdit` against a path matching a configured glob, Railcore blocks the request before it reaches Anthropic. This is the agentic-control surface from [`part1.md`](../../../part1.md) §1.4 point #3 — *"AI agents now have shell access, file system access, API access. The attack surface just 10x'd."* — applied as a policy gate.

**In scope:**

- Extract file paths from Anthropic `tool_use` blocks where the tool is `Read`, `Write`, `Edit`, or `MultiEdit` and the input contains a `file_path` field.
- Add `match.path:` doublestar glob condition to the policy YAML schema.
- New `policy.DecidePath(path string) (Action, *Rule)` method that mirrors the existing `Decide`.
- New `internal/pathscan/` leaf package that produces `[]PathEvent` from a parsed request.
- New `internal/stage/pathscan/` pipeline.Stage that runs path events through the policy and decides allow/block/warn.
- Proxy 403 body aggregates findings from BOTH `secretscan.findings` and `pathscan.findings` keys in `rc.Metadata`.
- Wire pathscan as the first registered stage (before secretscan) in `cmd/railcore/main.go`.

**Out of scope (deferred):**

- **Bash command path extraction** (`cat /secrets/foo`) — shell argument parsing is its own design problem.
- **`Glob`/`Grep` tool path matching** — glob-vs-glob overlap detection is more subtle than path-vs-glob.
- **Combining `path` with `pattern`/`severity` in one rule** — "block AWS keys found in payments code" requires cross-cutting type plumbing; deferred to a future cycle.
- **Path-shaped strings in free-form prompt text** — high FP rate; deferred (sub-project #7 or beyond).
- **OpenAI tool/function-call path extraction** — OpenAI uses a different schema; Anthropic-only for this cycle.
- **Path normalization / canonicalization** — operators write explicit globs; we match the literal string the AI sent.
- **Repo classifier** (public vs private repo via git remote) — separate sub-project #4b.
- **Content classifier** (sensitive code patterns beyond secrets) — dropped; users add patterns via `detector.AddPattern` if needed.

---

## 2. Decisions Locked in During Brainstorming

| Decision | Choice | Rationale |
|---|---|---|
| Path source | **Anthropic `tool_use` blocks only** | Where the *dangerous* thing happens — agent file access. Vendor-agnostic prompt-text extraction has high FP rate. |
| Tool input fields | **Just `file_path` on Read/Write/Edit/MultiEdit** | Covers the agentic-file-access wedge. Bash/Glob/Grep deferred. |
| Glob syntax | **`github.com/bmatcuk/doublestar/v4`** | Matches `**` syntax users expect from `.gitignore`. Battle-tested, MIT, small. |
| Architecture | **Parallel `pathscan` stage with new `policy.DecidePath`** | Type narrowness, future-proof for sub-project #4b. Cleaner than overloading `detector.Finding`. |
| Path + secret combined rules | **Deferred** | `match.path` is mutually exclusive with `match.pattern`/`severity` in this cycle. Cross-cutting later. |

---

## 3. Repo Layout

Two new packages + targeted edits to `internal/policy/`, `internal/proxy/`, and `cmd/railcore/`.

```
railcore/
├── cmd/
│   └── railcore/
│       └── main.go                       # register pathscan stage before secretscan
├── internal/
│   ├── ca/                               # unchanged
│   ├── pipeline/                         # unchanged
│   ├── proxy/                            # writeBlockResp aggregates findings from both metadata keys
│   ├── trust/                            # unchanged
│   ├── parser/                           # MODIFY — add ExtractToolUses helper for typed tool_use access
│   ├── detector/                         # unchanged
│   │
│   ├── pathscan/                         # NEW — pure path extraction
│   │   ├── pathscan.go                   # PathEvent type, ExtractPathEvents
│   │   ├── pathscan_test.go
│   │
│   ├── policy/                           # MODIFY — add Path match condition + DecidePath
│   │   ├── policy.go                     # +Match.Path field, +DecidePath method
│   │   ├── load.go                       # +path YAML field + doublestar compile + exclusivity validation
│   │   ├── match.go                      # +doublestarPattern alongside existing globPattern
│   │   ├── policy_test.go                # +tests
│   │
│   └── stage/
│       ├── secretscan/                   # unchanged
│       └── pathscan/                     # NEW — pipeline.Stage wrapping pathscan + policy.DecidePath
│           ├── stage.go
│           ├── stage_test.go
└── test/
    └── integration/
        └── pathscan_test.go              # NEW — end-to-end agentic tool_use scenarios
```

`internal/pathscan/` and `internal/stage/pathscan/` must satisfy the leaf/integration boundaries:

- `internal/pathscan/` imports stdlib + `internal/parser` only.
- `internal/stage/pathscan/` imports `internal/pathscan` + `internal/parser` + `internal/policy` + `internal/pipeline`.

**New dependency:** `github.com/bmatcuk/doublestar/v4` (MIT). Only new third-party dep.

---

## 4. YAML Schema Additions

The `match:` object gains one field. Top-level structure unchanged from sub-project #3.

```yaml
version: 1

rules:
  # Block agent file access to payments code at any depth.
  - name: block-payments
    match:
      path: "**/payments/**"
    action: block

  # Block agent file access to AWS credential paths.
  - name: block-aws-config
    match:
      path: "**/.aws/**"
    action: block

  # Block writes anywhere under /etc.
  - name: block-etc-writes
    match:
      path: "/etc/**"
    action: block

  # Existing secret rules still work alongside.
  - name: block-aws-keys
    match:
      pattern: aws_*
    action: block
```

### 4.1 New match condition

| Field | Type | Meaning |
|---|---|---|
| `path` | doublestar glob | Match a path event whose path matches the glob. `**` matches any depth; `*` matches within one segment. |

### 4.2 Exclusivity constraints

The loader enforces these at startup:

- `match.path` is **mutually exclusive** with `match.pattern` and `match.severity`. A rule is either a secret rule OR a path rule, not both. (Combining is deferred.)
- `match.all: true` cannot coexist with any other condition (existing constraint, applies to `path` too).

So one rule's `match` block may contain exactly one of:

1. `pattern` (optionally combined with `severity`)
2. `severity` (standalone)
3. `path` (standalone)
4. `all: true`

---

## 5. Components

### 5.1 `internal/pathscan/` — path extraction

Pure: takes a `*parser.ParsedRequest`, returns path events. No HTTP, no decisions, no logging.

```go
// PathEvent is one tool_use invocation that names a file path.
type PathEvent struct {
    Tool         string // "Read" | "Write" | "Edit" | "MultiEdit"
    Path         string // value of input.file_path
    MessageIndex int    // position of the originating message in messages[]
}

// ExtractPathEvents walks the request and returns every file_path
// argument from the file-access tools. Returns nil for non-Anthropic
// vendors or requests with no recognized tool_use blocks.
func ExtractPathEvents(parsed *parser.ParsedRequest) []PathEvent
```

**Implementation notes:**

- `parser.ParsedRequest.Texts` already surfaces tool_use input as a `TextSegment` whose `Content` is the raw JSON of the `input` object (per sub-project #2's `flattenAnthropicContent`). We re-parse that content for the `file_path` field.
- Tool name list is **hardcoded**: `Read`, `Write`, `Edit`, `MultiEdit`. Bash/Glob/Grep/WebFetch/Task are explicitly NOT scanned.
- Skips events with missing, empty, or non-string `file_path` values silently.
- The `Tool` field on `PathEvent` is populated from the `tool_use.name` field. To get this, the segment-walking logic needs to know which tool a given input segment belongs to. The Anthropic parser currently emits `input` as a segment without preserving the tool name, so this sub-project adds a tiny enhancement: a marker prefix in the segment content like `__tool__=Read\n{...input json...}` OR a parallel call into the request body's `tool_use` blocks via a new helper. The cleanest fix: add a tiny method `ExtractToolUses(body []byte) []ToolUse` to `internal/parser/` (a leaf-safe helper) that returns the structured tool_use blocks; pathscan uses that instead of relying on segment hints.

**API addition in `internal/parser/`:**

```go
// ToolUse is one structured tool_use block from an Anthropic messages
// request, returned by ExtractToolUses for callers that need typed
// access to tool names + raw input JSON.
type ToolUse struct {
    Tool         string          // tool name (e.g., "Read")
    Input        json.RawMessage // raw input JSON; caller decodes
    MessageIndex int             // position in messages[]
}

// ExtractToolUses parses an Anthropic messages body and returns every
// tool_use block. Returns nil for non-Anthropic bodies or bodies without
// tool_use blocks. Best-effort — silently skips malformed blocks.
func ExtractToolUses(host string, body []byte) []ToolUse
```

This is a small extension to `internal/parser/anthropic.go` that doesn't change existing behavior. Pathscan calls `ExtractToolUses` and then unmarshals `input` into a struct with `FilePath string`.

### 5.2 `internal/policy/` additions

Two additive changes (no breaking changes to sub-project #3).

**`Match` gains a `Path` field:**

```go
type Match struct {
    Pattern  *globPattern        // existing
    Severity *detector.Severity  // existing
    All      bool                // existing
    Path     *doublestarPattern  // NEW — file path glob (separate from Pattern's name glob)
}
```

**New `DecidePath` method:**

```go
// DecidePath returns the action and matching rule for a path.
// Mirrors Decide for secret findings but matches against the Path
// condition of rules.
//
// A rule with no Path field never matches against a PathEvent.
// Returns (ActionWarn, nil) if no rule matches or if p is nil/empty.
func (p *Policy) DecidePath(path string) (Action, *Rule)
```

**`match.go` gains a `doublestarPattern` type:**

```go
type doublestarPattern struct {
    raw string
}

func compileDoublestar(s string) (*doublestarPattern, error)
func (d *doublestarPattern) match(path string) bool   // wraps doublestar.PathMatch
```

`compileDoublestar` validates by calling `doublestar.PathMatch(s, "")` once at startup — any compile error surfaces here. Empty `s` returns an error.

**`load.go` schema validation grows:**

- `yamlMatch` gets `Path string \`yaml:"path,omitempty"\``.
- `compileMatch` adds path-exclusivity validation:
  - If `path` is set AND (`pattern` is set OR `severity` is set OR `all` is set) → error.
  - If `path` is empty string → error.
  - Empty input (no conditions at all) still fails (existing).

### 5.3 `internal/stage/pathscan/` — pipeline integration

Mirrors the secretscan stage's shape.

```go
type Config struct {
    Policy *policy.Policy
}

type Stage struct {
    cfg Config
    log *slog.Logger
}

func New(cfg Config, log *slog.Logger) *Stage
func (s *Stage) Name() string { return "path-scan" }
func (s *Stage) Process(ctx context.Context, rc *pipeline.RequestCtx) (pipeline.Decision, error)
```

**Process steps:**

1. Read body from `rc.Metadata["body"]`. Continue silently if missing.
2. `parser.ParseRequest(rc.Host, rc.Req, body)` — Continue silently if `nil`.
3. `pathscan.ExtractPathEvents(parsed)` — Continue silently if empty.
4. For each event:
   - `cfg.Policy.DecidePath(event.Path)`.
   - Build a `PathFinding{Tool, Path, MessageIndex, Rule}` for non-allow decisions.
5. If any decision is `Block`: stash `[]PathFinding` in `rc.Metadata["pathscan.findings"]`, log WARN, return `Block`.
6. Else if any decision is `Warn`: stash + INFO log + Continue.
7. Else (all allow or no rule matched on any event): Continue silently.

`PathFinding` is the path-side analogue of `EnrichedFinding`:

```go
type PathFinding struct {
    Tool         string
    Path         string
    MessageIndex int
    Rule         string // "" if no policy or no rule matched
}

// MarshalJSON emits the public shape used in 403 bodies.
func (p PathFinding) MarshalJSON() ([]byte, error)
```

The JSON shape includes `detector: "path-scan"` so consumers can distinguish path findings from secret findings in the same `findings` array.

### 5.4 Proxy 403 body — aggregate from both metadata keys

`internal/proxy/upstream.go`'s `writeBlockResp` currently reads only `rc.Metadata["secretscan.findings"]`. Change it to read BOTH and merge the slices:

```go
func writeBlockResp(w http.ResponseWriter, requestID string, rc *pipeline.RequestCtx) {
    body := map[string]any{
        "error":      "blocked by railcore policy",
        "request_id": requestID,
    }
    var all []any
    if v, ok := rc.Metadata["pathscan.findings"]; ok {
        all = append(all, v.([]pathscan.PathFinding)...)  // pseudocode; actual code uses an interface
    }
    if v, ok := rc.Metadata["secretscan.findings"]; ok {
        all = append(all, v.([]secretscan.EnrichedFinding)...)
    }
    if len(all) > 0 {
        body["findings"] = all
    }
    // detector field is omitted when mixed; each finding has its own detector field
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusForbidden)
    _ = json.NewEncoder(w).Encode(body)
}
```

(Actual implementation uses Go's structural typing — both finding types implement `MarshalJSON` so they serialize to objects that include their own `"detector"` field. We accumulate them as `[]any` and json-encode the whole thing.)

The `detector` field migrates from the top level of the 403 body to **per-finding** (so a mixed-result body has `findings: [{detector:"path-scan", ...}, {detector:"secret-scan", ...}]`). This is a small backward-compat change for sub-project #2's response format, but the existing sub-project #2 integration tests assert `parsed.Detector` from the top level — we'll update those tests too.

### 5.5 Wiring in `cmd/railcore/main.go`

After policy load:

```go
chain := pipeline.NewChain().WithLogger(logger)
chain.Register(pathscan.New(pathscan.Config{Policy: loadedPolicy}, logger))  // NEW, runs FIRST
chain.Register(secretscan.New(secretscan.Config{
    BlockOnDetect: effectiveBlock,
    Policy:        loadedPolicy,
}, logger))
```

When `loadedPolicy == nil`, pathscan's Process returns Continue immediately (no path rules to apply). Zero behavior change for users without a policy file.

---

## 6. Request Data Flow

Walks a Claude Code agent reading `/home/u/proj/src/payments/charge.go` with `block-payments` in effect.

```
 1. Agent sends:
       POST https://api.anthropic.com/v1/messages
       {
         "messages": [
           ...,
           {"role": "assistant", "content": [
             {"type": "text", "text": "Reading the charge handler"},
             {"type": "tool_use", "id": "toolu_01",
              "name": "Read",
              "input": {"file_path": "/home/u/proj/src/payments/charge.go"}}
           ]}
         ]
       }
 2. proxy.handler reads body, stashes in rc.Metadata["body"].
 3. proxy.handler runs pipeline.Chain.Run.
    ──────────────────────────────────────────────────────
 4. Stage 1: pathscan.Stage.Process
       a. parser.ExtractToolUses(host, body)
          → [ToolUse{Tool:"Read", Input:{"file_path":"/home/u/proj/src/payments/charge.go"}, MessageIndex:N}]
       b. pathscan.ExtractPathEvents synthesizes:
          → [PathEvent{Tool:"Read", Path:"/home/u/proj/src/payments/charge.go", MessageIndex:N}]
       c. policy.DecidePath("/home/u/proj/src/payments/charge.go")
          → (ActionBlock, &Rule{Name:"block-payments"})
       d. rc.Metadata["pathscan.findings"] = [
              PathFinding{Tool:"Read", Path:"...", Rule:"block-payments", MessageIndex:N}
          ]
       e. Stage logs:
            WARN pathscan blocked rule=block-payments tool=Read path=... request_id=...
       f. Returns pipeline.Block.
    ──────────────────────────────────────────────────────
 5. pipeline.Chain returns Block. Stage 2 (secretscan) never runs.
 6. proxy.handler returns 403:
       {
         "error": "blocked by railcore policy",
         "request_id": "...",
         "findings": [
           {"detector":"path-scan", "tool":"Read",
            "path":"/home/u/proj/src/payments/charge.go",
            "rule":"block-payments", "message_index":N}
         ]
       }
 7. Claude Code's agent receives 403; its tool call fails.
```

**Key properties:**

- Pathscan runs **first** in the chain. If it blocks, secretscan is skipped (which is fine — both decisions independently halt; the redundant scan would just waste cycles).
- The `detector` field has moved from the top level of the 403 body to per-finding. This unifies the JSON shape across path and secret findings.
- Path values appear in logs AND in the 403 body. Unlike matched secret bytes (which are never echoed), paths are the *actionable signal* operators need.
- Non-Anthropic requests pass through pathscan as silent no-ops.
- Requests with no `Read`/`Write`/`Edit`/`MultiEdit` calls pass through silently too.

---

## 7. Configuration

No new CLI flags. The single `--policy` flag from sub-project #3 controls both the secret rules AND the path rules — they're all in the same YAML file.

When `--policy` is absent and no default policy file exists, both secretscan and pathscan run with `Policy=nil` and produce no findings.

---

## 8. Error Handling

Inherits the previous posture: loud at startup, fail-open per-request.

### 8.1 Startup errors (fatal)

Additions to sub-project #3's catalogue:

| Failure | Message |
|---|---|
| `match.path` is empty | `policy: rule "X": match.path must not be empty` |
| `match.path` doublestar fails to compile | `policy: rule "X": invalid path pattern "...": <doublestar error>` |
| `match.path` combined with `match.pattern` or `match.severity` | `policy: rule "X": match.path cannot be combined with secret-finding conditions (pattern/severity) in this version` |
| `match.path` combined with `match.all=true` | (existing) `policy: rule "X": match.all cannot be combined with other conditions` |

### 8.2 Per-request errors (all fail-open)

| Failure | Behavior |
|---|---|
| Body cached but not Anthropic | `ExtractPathEvents` returns nil; stage returns Continue. |
| Anthropic body with no tool_use blocks | Returns nil; Continue. |
| `tool_use` exists but `file_path` missing/empty/non-string | Silently skipped. |
| Tool name not in our list (Bash/Glob/Grep/WebFetch/Task) | Silently skipped. |
| `DecidePath` on nil policy | Returns `(ActionWarn, nil)`. |
| Stage panics inside extraction | Recovered by `Chain.runStage`. Decision degrades to Continue. Logged at ERROR with stack. |

The invariant: **a path-extraction or policy-decision error never prevents a request from going upstream.** Only an explicit `ActionBlock` blocks.

### 8.3 Edge cases

- **`Task` sub-agent dispatch.** Inputs to `Task` contain a sub-prompt, not a file path. We do not recurse into Task descriptions. The dispatched sub-agent makes its own HTTP request, intercepted on its own round-trip.
- **Same path appears in multiple tool_use blocks.** Each occurrence is a separate `PathEvent`. The 403 body lists each one with its `message_index`. No deduplication.
- **Relative vs absolute paths.** We match the literal string. Policy authors must write globs matching the form their tools actually send. No `filepath.Clean` normalization.
- **Path traversal (`../../etc/passwd`).** Matched literally. A glob like `/etc/**` does NOT match `../../etc/passwd`. Operators wanting traversal defense write explicit globs like `**/etc/**`.

### 8.4 Logging

| Scenario | Log lines |
|---|---|
| Non-Anthropic / no tool_use | nothing |
| All paths matched ALLOW or no rule matched | nothing |
| ≥ 1 WARN-action match | `INFO pathscan findings tool=Read path=/x rule=warn-paths request_id=...` (one line per warned event) |
| ≥ 1 BLOCK-action match | `WARN pathscan blocked tool=Read path=/x rule=block-payments request_id=...` (one line per blocked event) + stage returns Block |

Path values appear in logs. The 403 body also contains paths. This is intentional: unlike secret bytes, paths are the actionable signal.

---

## 9. Testing Strategy

TDD throughout. Three layers.

### 9.1 Unit tests — `internal/pathscan/`

| Scenario | Test |
|---|---|
| Non-Anthropic vendor | `ExtractPathEvents` returns nil for an OpenAI ParsedRequest. |
| Anthropic with no tool_use | Returns nil. |
| Single `Read` with `file_path` | Returns one event with correct Tool, Path, MessageIndex. |
| Each of `Read`/`Write`/`Edit`/`MultiEdit` | Four positive tests confirming each tool name is recognized. |
| `Bash`/`Glob`/`Grep`/`WebFetch`/`Task` | Returns nil (those tools are ignored). |
| `file_path` missing / empty string / non-string | Event silently skipped. |
| Multiple tool_use blocks | All returned, MessageIndex preserved. |

### 9.2 Unit tests — `internal/policy/` (new cases)

Existing 33 tests stay valid. Append:

| Scenario | Test |
|---|---|
| `compileDoublestar` happy paths | `**/payments/**` matches `/a/b/payments/c.go`, doesn't match `/foo/bar`. `**/.aws/**` matches `/home/u/.aws/credentials`. `/etc/**` matches `/etc/foo`, doesn't match `/usr/etc/foo`. |
| `compileDoublestar` empty input | Returns error. |
| `LoadFromBytes` parses `match.path` | `{path: "**/foo/**"}` yields a Match with non-nil Path. |
| `LoadFromBytes` rejects empty `path` | Error. |
| `LoadFromBytes` rejects `path + pattern` | Error message mentions "path cannot be combined". |
| `LoadFromBytes` rejects `path + severity` | Same error class. |
| `LoadFromBytes` rejects `path + all` | Existing all-exclusivity error fires. |
| `DecidePath` happy path | Block rule matching → `(ActionBlock, &rule)`. |
| `DecidePath` rule order | First match wins. |
| `DecidePath` rule with no Path | Skipped — never matches a path. |
| `DecidePath` nil policy | Returns `(ActionWarn, nil)`. |
| `DecidePath` concurrent | `-race` clean. |

### 9.3 Unit tests — `internal/stage/pathscan/`

| Scenario | Test |
|---|---|
| Non-AI host | Continue, no metadata. |
| Anthropic with no tool_use | Continue, no metadata. |
| Read tool, policy blocks the path | Block, `pathscan.findings` has one PathFinding with Rule="block-payments". |
| Read tool, policy warns on path | Continue, finding present in metadata. |
| Read tool, policy allows the path | Continue, finding absent (allow suppresses). |
| Multiple tool_use, mixed actions | Single block within mixed events → Block. |
| Policy is nil | Continue, no metadata. |

### 9.4 In-process integration tests — `internal/proxy/server_test.go` (append)

| Scenario | Test |
|---|---|
| Anthropic tool_use against forbidden path, policy block-payments registered | `TestProxy_PathBlockReturns403WithRule` — 403, no upstream hit, JSON `findings[0].rule == "block-payments"`, `findings[0].path == "..."`, `findings[0].detector == "path-scan"`. |
| Request that triggers BOTH path block AND would-trigger-secret block (verify ordering) | `TestProxy_PathBlockTakesPrecedence` — pathscan blocks first; secretscan never runs. |
| Existing secret-only block scenario | Verify the migration of `detector` from top-level to per-finding doesn't break the existing test shape — update if necessary. |

### 9.5 End-to-end integration tests — `test/integration/pathscan_test.go`

- `TestPathscan_E2E_BlockOnPayments` — full Anthropic agent payload with Read tool_use → 403, rule/path in findings, `detector="path-scan"`.
- `TestPathscan_E2E_AllowOverridesBlock` — `allow` rule for `**/payments/test/**` precedes `block-payments`; agent reads `/payments/test/fixture.go` → 200.
- `TestPathscan_E2E_BadPathYAMLFailsLoader` — `LoadFromBytes` on `match: {path: ""}` returns an error.

### 9.6 Manual acceptance test

With Claude Code through the proxy and this policy:

```yaml
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
  - name: warn-everything-else
    match: {all: true}
    action: warn
```

Ask Claude Code to `read the file src/payments/charge.go` (or `cat` it via a Read tool call). Expected:

- Claude Code's agent gets a 403 when it tries the Read.
- Visible: tool call fails; Claude Code reports the error to you or chooses a different approach.
- Proxy log: `WARN pathscan blocked rule=block-payments tool=Read path=...`.

Record results in §11.

---

## 10. Done Definition

Sub-project #4 is complete when:

1. All unit and in-process integration tests in §9.1–9.4 pass on all three platforms in CI.
2. CI matrix stays green on `ubuntu-latest`, `macos-latest`, `windows-latest`.
3. The manual acceptance test in §9.6 passes against real Claude Code traffic.
4. The design doc and implementation are committed to the repo.

When these four hold, sub-project #5 (CLI + daemon management) or #6 (audit logging) can begin without further changes to the path-scanning architecture.

---

## 11. Acceptance Result

**Date:** 2026-05-17
**Tool exercised:** Claude Code via `HTTPS_PROXY` + `NODE_EXTRA_CA_CERTS`.

**Test policy:**
```yaml
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
  - name: warn-everything-else
    match: {all: true}
    action: warn
```

**Path block rule:** Pass.

- Claude Code's agent attempted `Read` against a payments-path file → 403 returned to the tool call.
- Proxy log: `WARN pathscan blocked rule=block-payments tool=Read path=...`.
- 403 response body included `findings[0].detector = "path-scan"`, `tool = "Read"`, `rule = "block-payments"`.

**Status:** Pass. Sub-project #4 done definition §10 satisfied. Railcore now governs agentic AI file access in addition to secret detection — the agentic-control surface from [`part1.md`](../../../part1.md) §1.4 point #3 is implemented and verified.
