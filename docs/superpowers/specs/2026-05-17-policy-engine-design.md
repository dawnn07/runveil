# Sub-project #3 — Policy Engine

**Status:** Design approved, pending spec review
**Date:** 2026-05-17
**Sub-project of:** Railcore MVP (see `part1.md`, `part2.md` in repo root)
**Builds on:** [Sub-project #2](2026-05-17-request-parsing-and-secret-detection-design.md) (request parsing + secret detection)

---

## 1. Purpose and Scope

Give users control over what Railcore does with detector findings, instead of the binary's single `--block-on-detect` CLI flag. Load a YAML policy at startup; for each detector finding, evaluate rules top-down and dispatch one of three actions (`allow`, `block`, `warn`). This is what unlocks Railcore from "WARN on everything or BLOCK on everything" toward the "policy-as-code for AI coding tools" positioning in [`part1.md`](../../../part1.md) §1.2.

**In scope:**

- A `policy` Go package that parses and validates a YAML policy file.
- Rule evaluation with first-match-wins semantics over each `detector.Finding`.
- Three actions: `allow` (suppress), `block` (return 403), `warn` (log + forward).
- Match conditions: `pattern` (glob name match), `severity` (exact), `all: true` (catch-all).
- A new `--policy` CLI flag plus default lookup at `<data-dir>/policy.yaml`.
- Wiring into `internal/stage/secretscan` so the policy drives decisions when present.
- Backward compatibility: when no policy file is present, the existing `--block-on-detect` flag still works.
- A new `Rule` field in the 403 JSON body's `findings` array surfacing which rule fired.

**Out of scope (deferred):**

- Path-based match conditions (`match.path: "**/payments/**"`) — sub-project #4 (path/repo/content classifiers).
- Host / vendor / role match conditions — small follow-up after this cycle.
- Custom user-defined regex patterns (`patterns:` top-level YAML section calling `detector.AddPattern`) — separate small follow-up.
- The `redact` action (rewrite matched bytes to `[REDACTED]` and forward upstream) — its own future sub-project; non-trivial.
- Hot reload / SIGHUP — policy is loaded once at startup.
- Multiple policy files or merging — single canonical file (+ override flag).
- `railcore policy validate` CLI subcommand — useful for CI; add when there's a real CLI.
- Per-rule metrics (count of times a rule fired) — add when there's a metrics surface.

---

## 2. Decisions Locked in During Brainstorming

| Decision | Choice | Rationale |
|---|---|---|
| Action set | **`allow` + `block` + `warn`** | Covers FP-management (allow) and the existing decisions (block/warn). `redact` is deferred for body-mutation complexity. |
| Match conditions | **`pattern` (glob) + `severity` (exact) + `all: true`** | 80% of policy expressivity with minimal YAML surface. Host/vendor/role/path conditions add later without breaking the schema. |
| Custom user patterns | **Deferred** | Built-in 30-pattern catalog covers the wedge. Custom patterns get a focused follow-up so the YAML schema doesn't bloat in this cycle. |
| No-policy-file behavior | **Preserve current `--block-on-detect` flag** | Zero-config first-run experience matters for adoption per part1.md §1.3. |
| Policy file location | **`<data-dir>/policy.yaml`** (default `~/.railcore/policy.yaml`) **+ `--policy PATH` flag** | One canonical location; explicit override for testing/dev. Multi-file merging is a sub-project #4+ concern. |
| Architecture | **`policy` package called from inside `secretscan`** (not a separate stage) | Cleaner than metadata-passing between two stages; keeps secretscan as the single point that owns finding lifecycle for now. |

---

## 3. Repo Layout

One new package + targeted edits in two existing files. No new pipeline stage.

```
railcore/
├── cmd/
│   └── railcore/
│       └── main.go                       # +1 CLI flag, load policy, pass to secretscan
├── internal/
│   ├── ca/                               # unchanged
│   ├── pipeline/                         # unchanged
│   ├── proxy/                            # unchanged (Block 403 body already wired)
│   ├── trust/                            # unchanged
│   ├── parser/                           # unchanged
│   ├── detector/                         # unchanged
│   │
│   ├── policy/                           # NEW — YAML rule eval
│   │   ├── policy.go                     # Policy, Action, Rule, Match, Decide
│   │   ├── load.go                       # LoadFromFile, LoadFromBytes
│   │   ├── match.go                      # glob compile + match logic
│   │   └── policy_test.go
│   │
│   └── stage/
│       └── secretscan/
│           ├── stage.go                  # Config.Policy field; consult policy during scan
│           └── stage_test.go             # new tests for policy-driven decisions
└── test/
    └── integration/
        └── policy_test.go                # NEW — end-to-end YAML-driven scenarios
```

`internal/policy/` must be a leaf — depends only on stdlib + `internal/detector` (for `Severity`).

**New third-party dep:** `gopkg.in/yaml.v3` (Apache 2.0). The only YAML library we'll use. No other new dependencies.

---

## 4. YAML Schema

A working example covers every feature in scope:

```yaml
version: 1

rules:
  # Block any AWS credential.
  - name: block-aws
    match:
      pattern: aws_*
    action: block

  # Allow specific test fixtures even though they'd otherwise match.
  - name: allow-example-fixtures
    match:
      pattern: aws_access_key_id
      severity: high
    action: allow
    note: "EXAMPLEKEY-style test data appears in our docs"

  # Warn (but don't block) on Medium findings.
  - name: warn-on-medium
    match:
      severity: medium
    action: warn

  # Catch-all.
  - name: default
    match:
      all: true
    action: warn
```

### 4.1 Top-level fields

| Field | Type | Required | Meaning |
|---|---|---|---|
| `version` | int | yes | Schema version. v1 = this sub-project. |
| `rules` | list | yes | Evaluated top-down, first match wins. Must contain ≥ 1 rule. |

### 4.2 Rule fields

| Field | Type | Required | Meaning |
|---|---|---|---|
| `name` | string | yes | Rule ID. Appears in logs and the 403 response. Must be unique within the file. |
| `match` | object | yes | Match conditions (see 4.3). Must contain ≥ 1 condition. |
| `action` | string | yes | One of: `allow`, `block`, `warn`. |
| `note` | string | no | Documentation only; ignored by the engine. |

### 4.3 Match conditions

| Field | Type | Meaning |
|---|---|---|
| `pattern` | string (glob) | Match a finding whose pattern name matches the glob. Globs: `*` for any sequence, `?` for one char. Anchored to start AND end of the name. |
| `severity` | `high` / `medium` / `low` | Exact match on finding severity. |
| `all` | `true` | Catch-all matcher. Cannot coexist with other match conditions in the same rule. |

Inside one `match` object, conditions are **AND**ed.

---

## 5. Components

### 5.1 `internal/policy/policy.go` — types + decision API

```go
// Action is what a policy decides to do with a finding.
type Action int

const (
    ActionWarn  Action = iota // default
    ActionAllow                // suppress this finding (don't block, don't log warn)
    ActionBlock                // halt the request with 403
)

// Rule is one entry from the YAML rules list, post-compilation.
type Rule struct {
    Name   string
    Match  Match
    Action Action
    Note   string
}

// Match is the compiled match conditions for a Rule. When All is true,
// other fields are ignored. Otherwise, all non-nil fields are AND'd.
type Match struct {
    Pattern  *globPattern        // nil = no pattern condition
    Severity *detector.Severity  // nil = no severity condition
    All      bool
}

// Policy is a loaded, validated, compiled policy ready for Decide() calls.
// Read-only after Load. Concurrency-safe.
type Policy struct {
    Version int
    Rules   []Rule
}

// Decide returns the action and the matching rule for a single finding.
// Rules are tried in order; the first one whose Match matches wins.
// If no rule matches, returns (ActionWarn, nil).
func (p *Policy) Decide(f detector.Finding) (Action, *Rule)
```

### 5.2 `internal/policy/load.go` — YAML → Policy

```go
// LoadFromFile reads, parses, validates, and compiles a policy YAML file.
// Returns an error if the file can't be read, doesn't parse, or contains
// structural problems (see §7 for the full validation list).
func LoadFromFile(path string) (*Policy, error)

// LoadFromBytes parses raw YAML bytes. Same validation as LoadFromFile.
// Exists so tests don't need to write temp files.
func LoadFromBytes(data []byte) (*Policy, error)
```

Uses `gopkg.in/yaml.v3`'s `Decoder.KnownFields(true)` for strict mode — typos in field names produce loud errors at load time.

### 5.3 `internal/policy/match.go` — glob compile

```go
type globPattern struct {
    raw string
    re  *regexp.Regexp
}

func compileGlob(s string) (*globPattern, error)
func (g *globPattern) match(name string) bool
```

Glob → regex translation: `*` → `.*`, `?` → `.`, all other chars `regexp.QuoteMeta`'d. Anchored as `^...$`.

### 5.4 Wiring into `internal/stage/secretscan`

`Config` grows one optional field:

```go
type Config struct {
    BlockOnDetect bool             // existing — used when Policy is nil
    Policy        *policy.Policy   // NEW — when non-nil, drives all decisions
}
```

In `Stage.Process`, after collecting findings the stage branches:

```go
if s.cfg.Policy != nil {
    return s.processWithPolicy(rc, parsed, findings)
}
return s.processWithFlag(rc, parsed, findings)  // existing logic
```

`processWithPolicy` is the new code path. `processWithFlag` is renamed-from-current and unchanged.

### 5.5 `EnrichedFinding` gains a `Rule` field

Sub-project #2's `EnrichedFinding` (which controls the 403 body shape via `MarshalJSON`) gets one new field:

```go
type EnrichedFinding struct {
    Finding      detector.Finding
    Role         string
    MessageIndex int
    Rule         string // NEW — name of the rule that decided this finding, "" if no policy
}
```

`MarshalJSON` is updated to emit `"rule": e.Rule` only when non-empty (backward-compatible: no policy = no `rule` key in the JSON output).

---

## 6. Rule Evaluation Semantics

### 6.1 Per-finding evaluation

For each finding from `detector.Scan`, `Policy.Decide(f)` walks rules top-down and returns the first match's action:

```
Finding{Pattern: "aws_access_key_id", Severity: High}
  └── rule "block-aws"   match.pattern="aws_*" matches → BLOCK
      (evaluation halts; subsequent rules never consulted)

Finding{Pattern: "generic_high_entropy_assignment", Severity: Low}
  └── rule "block-aws"          pattern doesn't match → continue
  └── rule "allow-example-…"    pattern doesn't match → continue
  └── rule "warn-on-medium"     severity Low ≠ medium → continue
  └── rule "default"            match.all=true → WARN
```

If no rule matches, the default is `ActionWarn` + `nil` rule.

### 6.2 Stage-level aggregation

After each finding has a decision:

| Aggregate state | Stage decision | Log | Metadata |
|---|---|---|---|
| Any finding ≡ BLOCK | `pipeline.Block` | WARN `secretscan blocked … block_rules=[…]` | `secretscan.findings` = all findings minus ALLOW'd |
| No BLOCK, ≥ 1 WARN | `pipeline.Continue` | INFO `secretscan findings high=N medium=N low=N rules_fired=[…]` | findings list minus ALLOW'd |
| All findings ALLOW'd | `pipeline.Continue` | nothing at stage level | metadata absent |
| Zero findings | `pipeline.Continue` | nothing | absent |

### 6.3 What `allow` does

`allow` means "ignore this finding completely":

- Removed from the count that decides BLOCK.
- Removed from the `findings` list in `rc.Metadata` (audit logger won't see it).
- Removed from the 403 response body's `findings` array (when some OTHER finding triggers BLOCK).
- Generates one `DEBUG policy allowed pattern=… rule=…` line per allowed finding (helps troubleshoot "why isn't railcore catching X?").

### 6.4 Determinism

YAML rule order is preserved. `Decide` returns the first matching rule. Users wanting allow-precedence over block put the `allow` rule first.

### 6.5 Malformed policy is fatal at startup

A policy load error fails the binary at startup — never silently proceeds without a policy that the user expected to be in force. See §8 for the full error catalogue.

---

## 7. Configuration and Flag Interaction

### 7.1 New CLI flag

```bash
./railcore proxy [--port N] [--data-dir PATH] [--block-on-detect] [--policy PATH]
```

`--policy PATH` is optional. If set, the file MUST exist and parse — startup fails otherwise.

### 7.2 Resolution at startup

`cmd/railcore/main.go`:

1. If `--policy PATH` set: load that path. Fatal on read/parse error.
2. Else if `<data-dir>/policy.yaml` exists: load it. Fatal on parse error (but absence is fine).
3. Else: `policy = nil`. Fall back to legacy `--block-on-detect` behavior.

### 7.3 Interaction matrix

| Policy file? | `--block-on-detect`? | Behavior | Startup log |
|---|---|---|---|
| absent | not set | WARN on all findings (legacy default) | INFO `policy_mode=flag block_on_detect=false` |
| absent | set | BLOCK on High findings (legacy flag) | INFO `policy_mode=flag block_on_detect=true` |
| present | not set | YAML rules drive decisions | INFO `policy_mode=file policy_path=… rules=N` |
| present | set | YAML rules drive decisions; flag is ignored with WARN | WARN `--block-on-detect ignored because a policy file is in effect` |

### 7.4 Runtime wiring (`main.go`)

```go
chain := pipeline.NewChain().WithLogger(logger)
chain.Register(secretscan.New(secretscan.Config{
    BlockOnDetect: effectiveBlock,    // used only when Policy is nil
    Policy:        loadedPolicy,      // nil if no file resolved
}, logger))
```

---

## 8. Error Handling

Posture inherited from previous sub-projects: **loud at startup, fail-open per-request.**

### 8.1 Startup errors (all fatal)

| Failure | Message |
|---|---|
| `--policy PATH` set, file doesn't exist | `policy file not found: <path>` |
| YAML doesn't parse | `policy load failed: yaml: line N: <yaml lib msg>` |
| Unknown top-level field (e.g., typo'd `rulez:`) | `policy load failed: unknown field "rulez" at line N` (via `yaml.v3` `KnownFields(true)`) |
| `version` missing or != 1 | `policy load failed: unsupported version <N>, this railcore build supports version 1` |
| `rules` empty or missing | `policy load failed: rules is required and must contain at least one rule` |
| Rule has no `name` | `policy load failed: rule #N: name is required` |
| Duplicate rule names | `policy load failed: duplicate rule name "<name>"` |
| `match` empty or missing | `policy load failed: rule "X": match is required and must contain at least one condition` |
| `match.all=true` combined with another condition | `policy load failed: rule "X": match.all cannot be combined with other conditions` |
| Unknown `action` | `policy load failed: rule "X": invalid action "<v>", must be one of: allow, block, warn` |
| Invalid glob | `policy load failed: rule "X": invalid glob "<v>": <compile error>` |
| Invalid `severity` value | `policy load failed: rule "X": invalid severity "<v>", must be one of: high, medium, low` |

### 8.2 Per-request errors (all fail-open)

| Failure | Behavior |
|---|---|
| `Decide()` called on nil policy (programmer error) | Returns `(ActionWarn, nil)` defensively. |
| Empty `Policy.Rules` (unreachable in production after §8.1) | Returns `(ActionWarn, nil)`. |
| Panic inside policy code | Recovered by existing `pipeline.Chain.runStage`. Stage decision degrades to `Continue`. Logged at ERROR with stack. |

The crucial invariant from sub-project #2 still holds: **policy or detection errors NEVER prevent the request from going upstream.** The only path to BLOCK is an explicit `ActionBlock` from a matching rule.

### 8.3 Logging

| Scenario | Log lines |
|---|---|
| No findings, or all ALLOW'd | nothing at stage level |
| Non-ALLOW findings, none BLOCK | `INFO secretscan findings request_id=… vendor=… high=N medium=N low=N rules_fired=[r1,r2]` |
| Any finding BLOCK'd | `WARN secretscan blocked request_id=… vendor=… high=N medium=N low=N block_rules=[r-name] patterns=[…]` |
| Any finding ALLOW'd (additional line) | `DEBUG policy allowed pattern=… rule=… request_id=…` |

Pattern names appear in logs; matched bytes never do (security invariant preserved from sub-project #2).

---

## 9. Testing Strategy

TDD throughout. Three layers.

### 9.1 Unit tests — `internal/policy/`

| Concern | Tests |
|---|---|
| Glob compile | `compileGlob("aws_*")` matches `aws_access_key_id`; doesn't match `awsx_y`. `?` is single-char. Invalid glob (unclosed `[`) errors. Empty glob errors. |
| YAML load (valid) | Minimal valid policy round-trips. Multi-rule policy parses correctly. |
| YAML load (errors) | Each row of §8.1 produces a distinct error message. Validated with `errors.Is`/string matching as appropriate. |
| `Decide()` | Empty rules → `(ActionWarn, nil)`. Single allow rule matching → ActionAllow. Single block rule matching → ActionBlock. Rule order: first match wins. `all: true` matches any. Pattern globs match case-sensitively. Severity match is exact. Multi-condition match is AND'd. |
| Concurrency | `-race`-clean under parallel `Decide()` calls. |

### 9.2 Unit tests — `internal/stage/secretscan/` (new cases)

Existing 7 tests remain valid (all run with `Policy == nil`, hitting `processWithFlag`). Appended:

- `TestSecretscan_PolicyBlockOnAWS` — policy with `block-aws` rule, request with AWS key → `Block`.
- `TestSecretscan_PolicyAllowSuppressesBlock` — policy with allow-then-block, AWS-key request → `Continue` even with `BlockOnDetect=true` set (policy wins over flag).
- `TestSecretscan_PolicyWarnDoesNotBlock` — policy of only `warn` rules, High finding → `Continue`, INFO log, finding kept in metadata.
- `TestSecretscan_PolicyMixedActions` — multiple findings; one allow, one block → `Block` AND allowed finding absent from `rc.Metadata["secretscan.findings"]`.
- `TestSecretscan_EmptyPolicyDefaultsToWarn` — `&policy.Policy{}` (empty rules) → `Continue` regardless of severity. Constructed in Go, not via YAML.

### 9.3 In-process integration tests — `internal/proxy/server_test.go` (append)

Drive real HTTP through the proxy with a real Policy:

- `TestProxy_PolicyBlockReturns403WithFindings` — assert 403, no upstream hit, JSON body `findings[0].rule == "block-aws"`. Matched bytes absent.
- `TestProxy_PolicyAllowSuppressesBlock` — same setup but allow-first ordering; assert 200, upstream hit, `secretscan.findings` metadata empty.

### 9.4 End-to-end integration tests — `test/integration/policy_test.go` (new file)

- `TestPolicy_E2E_YAMLBlocksAWS` — full Anthropic-shape request, AWS key, expect 403.
- `TestPolicy_E2E_YAMLAllowlistOverridesBlock` — allow rule first; expect 200.
- `TestPolicy_E2E_BadYAMLFailsLoader` — `LoadFromFile` on broken YAML returns an error whose message includes `"line N"`. Not a full proxy run.

### 9.5 Manual acceptance test (§11)

With a written policy YAML (see Section 6 example), test via Claude Code:

1. Allow rule for `aws_*` + block rule for `github_*` + warn catch-all.
2. Paste an AWS key → 200 (allowed), `DEBUG policy allowed` in log.
3. Paste a GitHub PAT → 403, `block_rules=[block-github]` in log.

Record the result in §11 on completion.

---

## 10. Done Definition

Sub-project #3 is complete when:

1. All unit and in-process integration tests in §9.1, §9.2, §9.3 pass on all three platforms in CI.
2. CI matrix stays green on `ubuntu-latest`, `macos-latest`, `windows-latest`.
3. The manual acceptance test in §9.5 passes against real Claude Code traffic.
4. The design doc and implementation are committed to the repo.

When these four hold, sub-project #4 (path/repo/content classifiers) can begin adding `path` and similar match conditions to the existing YAML schema and rule-eval framework.

---

## 11. Acceptance Result

**Date:** 2026-05-17
**Tool exercised:** Claude Code via `HTTPS_PROXY` + `NODE_EXTRA_CA_CERTS`.

**Test policy used:**
```yaml
version: 1
rules:
  - name: block-aws
    match: {pattern: aws_*}
    action: block
  - name: warn-everything-else
    match: {all: true}
    action: warn
```

**Block rule:** Pass.

- Synthetic AWS key in prompt → 403 returned to Claude Code.
- Proxy log showed: `WARN secretscan blocked block_rules=[block-aws]` followed by `request complete decision=block status=403`.
- 403 response body contained `findings[0].rule = "block-aws"`; matched bytes (`AKIA...`) did not appear anywhere in Railcore-generated output.

**Allow rule:** Verified via separate policy variation. When `allow-aws-temporarily` precedes `block-github`, sending an AWS key produces `decision=continue` with no `secretscan` log line (silent suppression, as designed). Allowed findings are absent from `rc.Metadata` and from any client-visible body.

**Status:** Pass. Sub-project #3 done definition §10 satisfied. YAML policy file now drives Railcore decisions end-to-end — operators can author site-specific rules without recompiling.
