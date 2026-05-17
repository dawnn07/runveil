# Path-Based Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Govern AI agent file access by adding a `match.path:` doublestar glob condition to the YAML policy schema, a new `pathscan` pipeline stage that extracts file paths from Anthropic `tool_use` blocks (Read/Write/Edit/MultiEdit), and a `policy.DecidePath` method that mirrors the existing secret-finding decision logic.

**Architecture:** New leaf package `internal/pathscan/` (path extraction) + new pipeline stage `internal/stage/pathscan/` (policy integration). `internal/policy/` gains a `Match.Path *doublestarPattern` field and a `DecidePath(path string) (Action, *Rule)` method. `internal/parser/` gains an `ExtractToolUses` helper for typed access to tool name + input. The proxy's 403 body aggregates findings from BOTH `secretscan.findings` and `pathscan.findings` metadata keys; the `detector` field migrates from the top level to per-finding.

**Tech Stack:** Go 1.25 (stdlib `encoding/json`, `regexp`), `github.com/bmatcuk/doublestar/v4` (MIT) — the only new third-party dep. All existing dependencies unchanged.

**Spec:** [`docs/superpowers/specs/2026-05-17-path-based-rules-design.md`](../specs/2026-05-17-path-based-rules-design.md)

---

## File Map

| File | Purpose |
|---|---|
| `internal/parser/anthropic.go` | **Modify:** add `ToolUse` type + `ExtractToolUses` helper |
| `internal/parser/parser_test.go` | **Modify:** tests for `ExtractToolUses` |
| `internal/policy/match.go` | **Modify:** add `doublestarPattern` type + `compileDoublestar` |
| `internal/policy/policy.go` | **Modify:** add `Match.Path` field + `DecidePath` method |
| `internal/policy/load.go` | **Modify:** add `Path` to `yamlMatch`, validation in `compileMatch` |
| `internal/policy/policy_test.go` | **Modify:** doublestar + DecidePath + new loader validation tests |
| `internal/pathscan/pathscan.go` | **Create:** `PathEvent`, `ExtractPathEvents` |
| `internal/pathscan/pathscan_test.go` | **Create:** unit tests |
| `internal/stage/pathscan/stage.go` | **Create:** `pipeline.Stage` with policy-driven decisions, `PathFinding` |
| `internal/stage/pathscan/stage_test.go` | **Create:** unit tests |
| `internal/proxy/upstream.go` | **Modify:** `writeBlockResp` aggregates from both metadata keys; remove top-level `detector` |
| `internal/proxy/server_test.go` | **Modify:** new path-block integration test; update existing tests for new body shape |
| `internal/stage/secretscan/stage.go` | **Modify:** `EnrichedFinding.MarshalJSON` emits per-finding `detector: "secret-scan"` |
| `internal/stage/secretscan/stage_test.go` | **Modify:** assert new `detector` field in MarshalJSON tests |
| `test/integration/secretscan_test.go` | **Modify:** update detector assertion to per-finding |
| `test/integration/policy_test.go` | **Modify:** update detector assertion to per-finding |
| `test/integration/pathscan_test.go` | **Create:** end-to-end path-block scenarios |
| `cmd/railcore/main.go` | **Modify:** register pathscan stage before secretscan |
| `go.mod`, `go.sum` | **Modify:** `github.com/bmatcuk/doublestar/v4` dep |

**Dependency direction (unchanged + new):**

```
cmd/railcore
   ├── internal/stage/pathscan
   │       ├── internal/pathscan      (NEW leaf — uses parser)
   │       ├── internal/parser         (leaf)
   │       ├── internal/policy         (leaf)
   │       └── internal/pipeline       (leaf)
   └── internal/stage/secretscan       (existing)
           ├── internal/parser
           ├── internal/detector
           ├── internal/policy
           └── internal/pipeline
```

`internal/pathscan/` is a leaf — imports stdlib + `internal/parser` only. `internal/stage/pathscan/` is the only package importing both `pathscan` and `policy` and `pipeline` together.

---

## Task 1: Parser — `ExtractToolUses` helper

**Files:**
- Modify: `internal/parser/anthropic.go`
- Modify: `internal/parser/parser_test.go` (append)

This adds a typed accessor for Anthropic `tool_use` blocks. The existing `flattenAnthropicContent` stringifies the input JSON; this new helper preserves the tool name alongside the raw input.

- [ ] **Step 1: Write the failing test**

Append to `internal/parser/parser_test.go`:

```go

func TestExtractToolUses_AnthropicSingleRead(t *testing.T) {
	body := []byte(`{
		"model": "claude-opus-4-7",
		"messages": [
			{"role": "assistant", "content": [
				{"type": "text", "text": "Let me check"},
				{"type": "tool_use", "id": "toolu_01",
				 "name": "Read",
				 "input": {"file_path": "/src/foo.go"}}
			]}
		]
	}`)
	got := ExtractToolUses("api.anthropic.com", body)
	if len(got) != 1 {
		t.Fatalf("got %d tool_uses, want 1; got %+v", len(got), got)
	}
	tu := got[0]
	if tu.Tool != "Read" {
		t.Errorf("Tool = %q, want Read", tu.Tool)
	}
	if tu.MessageIndex != 0 {
		t.Errorf("MessageIndex = %d, want 0", tu.MessageIndex)
	}
	var inp struct {
		FilePath string `json:"file_path"`
	}
	if err := json.Unmarshal(tu.Input, &inp); err != nil {
		t.Fatalf("unmarshal input: %v", err)
	}
	if inp.FilePath != "/src/foo.go" {
		t.Errorf("file_path = %q, want /src/foo.go", inp.FilePath)
	}
}

func TestExtractToolUses_NoToolUses(t *testing.T) {
	body := []byte(`{
		"model": "claude-opus-4-7",
		"messages": [
			{"role": "user", "content": "hello"}
		]
	}`)
	got := ExtractToolUses("api.anthropic.com", body)
	if len(got) != 0 {
		t.Errorf("expected 0 tool_uses, got %d", len(got))
	}
}

func TestExtractToolUses_NonAnthropicHost(t *testing.T) {
	body := []byte(`{"messages": [{"role": "user", "content": "x"}]}`)
	got := ExtractToolUses("api.openai.com", body)
	if got != nil {
		t.Errorf("expected nil for non-Anthropic host, got %+v", got)
	}
}

func TestExtractToolUses_MalformedJSON(t *testing.T) {
	got := ExtractToolUses("api.anthropic.com", []byte(`{not json`))
	if got != nil {
		t.Errorf("expected nil for malformed JSON, got %+v", got)
	}
}

func TestExtractToolUses_MultipleBlocksAcrossMessages(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/a"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "t1", "content": "..."}
			]},
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "t2", "name": "Write", "input": {"file_path": "/b"}}
			]}
		]
	}`)
	got := ExtractToolUses("api.anthropic.com", body)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2; %+v", len(got), got)
	}
	if got[0].Tool != "Read" || got[0].MessageIndex != 0 {
		t.Errorf("[0] = %+v", got[0])
	}
	if got[1].Tool != "Write" || got[1].MessageIndex != 2 {
		t.Errorf("[1] = %+v", got[1])
	}
}
```

Add `"encoding/json"` to the test file's imports if not already there.

- [ ] **Step 2: Run and confirm tests fail**

```bash
go test ./internal/parser/...
```

Expected: compile error — `ExtractToolUses`, `ToolUse` undefined.

- [ ] **Step 3: Implement in `internal/parser/anthropic.go`**

Append to the existing `internal/parser/anthropic.go`:

```go

// ToolUse is one structured tool_use block from an Anthropic messages
// request. Returned by ExtractToolUses for callers that need typed
// access to tool names alongside raw input JSON.
type ToolUse struct {
	Tool         string          // tool name (e.g., "Read", "Write")
	Input        json.RawMessage // raw input JSON; caller decodes per tool schema
	MessageIndex int             // position of the originating message in messages[]
}

// ExtractToolUses parses an Anthropic messages body and returns every
// tool_use content block. Returns nil for non-Anthropic hosts or for
// bodies that fail to parse. Silently skips malformed individual blocks.
func ExtractToolUses(host string, body []byte) []ToolUse {
	if host != "api.anthropic.com" {
		return nil
	}
	var req anthropicMessagesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}

	var out []ToolUse
	for i, m := range req.Messages {
		// Content is json.RawMessage. Try array form (tool_use only appears in arrays).
		var blocks []map[string]json.RawMessage
		if err := json.Unmarshal(m.Content, &blocks); err != nil {
			continue
		}
		for _, b := range blocks {
			typeRaw, ok := b["type"]
			if !ok {
				continue
			}
			var blockType string
			if err := json.Unmarshal(typeRaw, &blockType); err != nil {
				continue
			}
			if blockType != "tool_use" {
				continue
			}
			var name string
			if nameRaw, ok := b["name"]; ok {
				_ = json.Unmarshal(nameRaw, &name)
			}
			if name == "" {
				continue
			}
			inputRaw := b["input"]
			out = append(out, ToolUse{
				Tool:         name,
				Input:        inputRaw,
				MessageIndex: i,
			})
		}
	}
	return out
}
```

- [ ] **Step 4: Run tests and confirm pass**

```bash
go test -race -count=1 ./internal/parser/...
```

Expected: all parser tests pass (existing + 5 new).

- [ ] **Step 5: Commit**

```bash
git add internal/parser/anthropic.go internal/parser/parser_test.go
git commit -m "feat(parser): add ExtractToolUses helper for typed tool_use access"
```

---

## Task 2: Policy — doublestar pattern + dependency

**Files:**
- Modify: `internal/policy/match.go`
- Modify: `internal/policy/policy_test.go` (append)
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Add the doublestar dependency**

```bash
go get github.com/bmatcuk/doublestar/v4@latest
go mod tidy
```

- [ ] **Step 2: Write failing tests for `compileDoublestar`**

Append to `internal/policy/policy_test.go`:

```go

func TestCompileDoublestar_MatchesDeepPaths(t *testing.T) {
	d, err := compileDoublestar("**/payments/**")
	if err != nil {
		t.Fatalf("compileDoublestar: %v", err)
	}
	cases := []struct {
		path string
		want bool
	}{
		{"/a/b/payments/c.go", true},
		{"/payments/x", true},
		{"src/payments/charge/charge.go", true},
		{"/foo/bar", false},
		{"payments_old/x", false}, // payments must be a path segment
	}
	for _, c := range cases {
		if got := d.match(c.path); got != c.want {
			t.Errorf("doublestar(**/payments/**).match(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestCompileDoublestar_MatchesAwsConfig(t *testing.T) {
	d, err := compileDoublestar("**/.aws/**")
	if err != nil {
		t.Fatalf("compileDoublestar: %v", err)
	}
	if !d.match("/home/u/.aws/credentials") {
		t.Error("expected match on /home/u/.aws/credentials")
	}
	if d.match("/home/u/aws/x") {
		t.Error("expected NO match on /home/u/aws/x (no dot prefix)")
	}
}

func TestCompileDoublestar_AnchoredPrefix(t *testing.T) {
	d, err := compileDoublestar("/etc/**")
	if err != nil {
		t.Fatalf("compileDoublestar: %v", err)
	}
	if !d.match("/etc/foo") {
		t.Error("expected match on /etc/foo")
	}
	if d.match("/usr/etc/foo") {
		t.Error("expected NO match on /usr/etc/foo (anchored prefix)")
	}
}

func TestCompileDoublestar_EmptyIsInvalid(t *testing.T) {
	_, err := compileDoublestar("")
	if err == nil {
		t.Error("expected error for empty doublestar")
	}
}

func TestDoublestarPattern_NilSafe(t *testing.T) {
	var d *doublestarPattern
	if d.match("/anything") {
		t.Error("nil doublestar should not match")
	}
}
```

- [ ] **Step 3: Confirm tests fail to compile**

```bash
go test ./internal/policy/...
```

Expected: compile error — `compileDoublestar`, `doublestarPattern` undefined.

- [ ] **Step 4: Modify `internal/policy/match.go`**

Append to the existing `internal/policy/match.go`:

```go

// doublestarPattern is a compiled file-path glob using doublestar
// syntax: ** matches any number of path segments, * matches within
// one segment.
//
// We use github.com/bmatcuk/doublestar/v4 — the de facto Go standard
// implementation (also used by gitignore-like tools).
type doublestarPattern struct {
	raw string
}

// compileDoublestar validates a doublestar glob by calling
// doublestar.PathMatch with a dummy input. Returns an error on
// invalid syntax or empty input.
func compileDoublestar(s string) (*doublestarPattern, error) {
	if s == "" {
		return nil, fmt.Errorf("empty doublestar pattern")
	}
	// Validate by attempting a match. doublestar reports parse errors here.
	if _, err := doublestar.PathMatch(s, ""); err != nil {
		return nil, fmt.Errorf("compile doublestar %q: %w", s, err)
	}
	return &doublestarPattern{raw: s}, nil
}

func (d *doublestarPattern) match(path string) bool {
	if d == nil {
		return false
	}
	matched, err := doublestar.PathMatch(d.raw, path)
	if err != nil {
		return false
	}
	return matched
}
```

Add `"github.com/bmatcuk/doublestar/v4"` to the imports of `match.go`.

- [ ] **Step 5: Run tests and confirm pass**

```bash
go test -race -count=1 ./internal/policy/...
```

Expected: existing policy tests + 5 new ones all pass.

- [ ] **Step 6: Commit**

```bash
git add internal/policy/match.go internal/policy/policy_test.go go.mod go.sum
git commit -m "feat(policy): add doublestar pattern compile + match"
```

---

## Task 3: Policy — `Match.Path` field + `DecidePath` method

**Files:**
- Modify: `internal/policy/policy.go`
- Modify: `internal/policy/policy_test.go` (append)

- [ ] **Step 1: Append failing tests**

Append to `internal/policy/policy_test.go`:

```go

func mustDoublestar(t *testing.T, s string) *doublestarPattern {
	t.Helper()
	d, err := compileDoublestar(s)
	if err != nil {
		t.Fatalf("compileDoublestar(%q): %v", s, err)
	}
	return d
}

func TestDecidePath_BlockOnPaymentsGlob(t *testing.T) {
	p := mustPolicy(t, Rule{
		Name:   "block-payments",
		Match:  Match{Path: mustDoublestar(t, "**/payments/**")},
		Action: ActionBlock,
	})
	a, r := p.DecidePath("/src/payments/charge.go")
	if a != ActionBlock {
		t.Errorf("action = %v, want Block", a)
	}
	if r == nil || r.Name != "block-payments" {
		t.Errorf("rule = %+v, want block-payments", r)
	}
}

func TestDecidePath_NoMatchReturnsWarn(t *testing.T) {
	p := mustPolicy(t, Rule{
		Name:   "block-payments",
		Match:  Match{Path: mustDoublestar(t, "**/payments/**")},
		Action: ActionBlock,
	})
	a, r := p.DecidePath("/src/billing/foo.go")
	if a != ActionWarn {
		t.Errorf("action = %v, want Warn (no match)", a)
	}
	if r != nil {
		t.Errorf("rule = %+v, want nil", r)
	}
}

func TestDecidePath_NilPolicyReturnsWarn(t *testing.T) {
	var p *Policy
	a, r := p.DecidePath("/x")
	if a != ActionWarn {
		t.Errorf("nil policy: action = %v, want Warn", a)
	}
	if r != nil {
		t.Errorf("nil policy: rule = %v, want nil", r)
	}
}

func TestDecidePath_RuleWithoutPathSkipped(t *testing.T) {
	// A rule with no Path condition must NOT match a PathEvent.
	p := mustPolicy(t,
		Rule{
			Name:   "block-aws-pattern",
			Match:  Match{Pattern: mustGlob(t, "aws_*")},
			Action: ActionBlock,
		},
		Rule{
			Name:   "block-payments-path",
			Match:  Match{Path: mustDoublestar(t, "**/payments/**")},
			Action: ActionBlock,
		},
	)
	// The aws_* pattern rule has Match.Path == nil. It must be skipped.
	// The block-payments-path rule has Match.Path set. It must match.
	a, r := p.DecidePath("/src/payments/charge.go")
	if a != ActionBlock {
		t.Errorf("action = %v, want Block", a)
	}
	if r == nil || r.Name != "block-payments-path" {
		t.Errorf("rule = %+v, want block-payments-path", r)
	}
}

func TestDecidePath_FirstMatchWins(t *testing.T) {
	p := mustPolicy(t,
		Rule{
			Name:   "allow-payments-tests",
			Match:  Match{Path: mustDoublestar(t, "**/payments/test/**")},
			Action: ActionAllow,
		},
		Rule{
			Name:   "block-payments",
			Match:  Match{Path: mustDoublestar(t, "**/payments/**")},
			Action: ActionBlock,
		},
	)
	a, r := p.DecidePath("/src/payments/test/fixture.go")
	if a != ActionAllow {
		t.Errorf("action = %v, want Allow", a)
	}
	if r == nil || r.Name != "allow-payments-tests" {
		t.Errorf("rule = %+v, want allow-payments-tests", r)
	}
}

func TestDecidePath_AllMatchesAnyPath(t *testing.T) {
	// match.all = true should also match path events (the catch-all rule).
	p := mustPolicy(t, Rule{
		Name:   "default",
		Match:  Match{All: true},
		Action: ActionWarn,
	})
	a, r := p.DecidePath("/anything")
	if a != ActionWarn {
		t.Errorf("action = %v, want Warn", a)
	}
	if r == nil || r.Name != "default" {
		t.Errorf("rule = %+v, want default", r)
	}
}

func TestDecidePath_ConcurrentSafe(t *testing.T) {
	p := mustPolicy(t,
		Rule{Name: "block-payments", Match: Match{Path: mustDoublestar(t, "**/payments/**")}, Action: ActionBlock},
	)
	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func(i int) {
			path := "/src/payments/charge.go"
			if i%2 == 0 {
				path = "/src/other/foo.go"
			}
			a, _ := p.DecidePath(path)
			_ = a
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 50; i++ {
		<-done
	}
}
```

- [ ] **Step 2: Confirm tests fail to compile**

```bash
go test ./internal/policy/...
```

Expected: compile error — `Match.Path`, `Policy.DecidePath` undefined.

- [ ] **Step 3: Modify `internal/policy/policy.go`**

Update the `Match` struct:

```go
type Match struct {
	Pattern  *globPattern        // existing — secret pattern glob
	Severity *detector.Severity  // existing — secret severity
	All      bool                // existing — catch-all
	Path     *doublestarPattern  // NEW — file path glob
}
```

Add a new `pathMatches` helper and `DecidePath` method (place after the existing `matches` function):

```go

// pathMatches reports whether m matches a path event.
// A rule's Match must have either Path or All set to be eligible.
// Rules with only Pattern or only Severity are skipped for path events.
func pathMatches(m *Match, path string) bool {
	if m.All {
		return true
	}
	if m.Path != nil {
		return m.Path.match(path)
	}
	// Pattern / Severity only — not a path rule. Never matches a path.
	return false
}

// DecidePath returns the action and matching rule for a file path.
// Mirrors Decide for secret findings but matches against the Path
// condition of rules. Rules with no Path field never match a PathEvent
// (except the catch-all All:true rule, which matches everything).
//
// Returns (ActionWarn, nil) if p is nil/empty or no rule matches.
// Safe for concurrent use after construction.
func (p *Policy) DecidePath(path string) (Action, *Rule) {
	if p == nil {
		return ActionWarn, nil
	}
	for i := range p.Rules {
		if pathMatches(&p.Rules[i].Match, path) {
			return p.Rules[i].Action, &p.Rules[i]
		}
	}
	return ActionWarn, nil
}
```

- [ ] **Step 4: Run tests and confirm pass**

```bash
go test -race -count=1 ./internal/policy/...
```

Expected: existing tests + 7 new ones pass.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/policy.go internal/policy/policy_test.go
git commit -m "feat(policy): add Match.Path field and DecidePath method"
```

---

## Task 4: Policy — YAML loader gains `path` field

**Files:**
- Modify: `internal/policy/load.go`
- Modify: `internal/policy/policy_test.go` (append)

- [ ] **Step 1: Append failing tests**

Append to `internal/policy/policy_test.go`:

```go

func TestLoadFromBytes_PathField(t *testing.T) {
	yaml := []byte(`
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
`)
	p, err := LoadFromBytes(yaml)
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	if p.Rules[0].Match.Path == nil {
		t.Fatal("Path not compiled")
	}
	if !p.Rules[0].Match.Path.match("/src/payments/x.go") {
		t.Error("compiled path glob does not match /src/payments/x.go")
	}
}

func TestLoadFromBytes_PathPlusPatternRejected(t *testing.T) {
	yaml := []byte(`
version: 1
rules:
  - name: r
    match: {path: "**/foo/**", pattern: aws_*}
    action: block
`)
	_, err := LoadFromBytes(yaml)
	if err == nil {
		t.Fatal("expected error for path + pattern combination")
	}
}

func TestLoadFromBytes_PathPlusSeverityRejected(t *testing.T) {
	yaml := []byte(`
version: 1
rules:
  - name: r
    match: {path: "**/foo/**", severity: high}
    action: block
`)
	_, err := LoadFromBytes(yaml)
	if err == nil {
		t.Fatal("expected error for path + severity combination")
	}
}

func TestLoadFromBytes_PathPlusAllRejected(t *testing.T) {
	yaml := []byte(`
version: 1
rules:
  - name: r
    match: {path: "**/foo/**", all: true}
    action: block
`)
	_, err := LoadFromBytes(yaml)
	if err == nil {
		t.Fatal("expected error for path + all combination")
	}
}

func TestLoadFromBytes_EmptyPathRejected(t *testing.T) {
	yaml := []byte(`
version: 1
rules:
  - name: r
    match: {path: ""}
    action: block
`)
	_, err := LoadFromBytes(yaml)
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}
```

- [ ] **Step 2: Confirm new tests fail**

```bash
go test ./internal/policy/...
```

Expected: tests fail because `yamlMatch.Path` not defined and `compileMatch` doesn't handle path.

- [ ] **Step 3: Modify `internal/policy/load.go`**

Update `yamlMatch`:

```go
type yamlMatch struct {
	Pattern  string `yaml:"pattern,omitempty"`
	Severity string `yaml:"severity,omitempty"`
	All      bool   `yaml:"all,omitempty"`
	Path     string `yaml:"path,omitempty"`
}
```

Update `compileMatch` to add path-exclusivity validation. Replace the function body with:

```go
func compileMatch(ym yamlMatch) (Match, error) {
	hasPattern := ym.Pattern != ""
	hasSeverity := ym.Severity != ""
	hasAll := ym.All
	hasPath := ym.Path != ""

	if !hasPattern && !hasSeverity && !hasAll && !hasPath {
		return Match{}, fmt.Errorf("match is required and must contain at least one condition")
	}
	if hasAll && (hasPattern || hasSeverity || hasPath) {
		return Match{}, fmt.Errorf("match.all cannot be combined with other conditions")
	}
	if hasPath && (hasPattern || hasSeverity) {
		return Match{}, fmt.Errorf("match.path cannot be combined with secret-finding conditions (pattern/severity) in this version")
	}

	m := Match{All: hasAll}

	if hasPattern {
		g, err := compileGlob(ym.Pattern)
		if err != nil {
			return Match{}, fmt.Errorf("invalid pattern %q: %w", ym.Pattern, err)
		}
		m.Pattern = g
	}

	if hasSeverity {
		s, err := parseSeverity(ym.Severity)
		if err != nil {
			return Match{}, err
		}
		m.Severity = &s
	}

	if hasPath {
		d, err := compileDoublestar(ym.Path)
		if err != nil {
			return Match{}, fmt.Errorf("invalid path %q: %w", ym.Path, err)
		}
		m.Path = d
	}

	return m, nil
}
```

- [ ] **Step 4: Run tests and confirm pass**

```bash
go test -race -count=1 ./internal/policy/...
```

Expected: existing policy tests + 5 new path-related load tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/load.go internal/policy/policy_test.go
git commit -m "feat(policy): YAML schema gains match.path with exclusivity validation"
```

---

## Task 5: `internal/pathscan/` — `PathEvent` and `ExtractPathEvents`

**Files:**
- Create: `internal/pathscan/pathscan.go`
- Create: `internal/pathscan/pathscan_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/pathscan/pathscan_test.go`:

```go
package pathscan

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"railcore/internal/parser"
)

func mustParse(t *testing.T, host, body string) *parser.ParsedRequest {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "https://"+host+"/v1/messages", nil)
	parsed, err := parser.ParseRequest(host, req, []byte(body))
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	return parsed
}

func TestExtractPathEvents_NonAnthropicReturnsNil(t *testing.T) {
	// OpenAI shape — parser will produce a ParsedRequest with Vendor=openai.
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`
	parsed := mustParse(t, "api.openai.com", body)
	got := ExtractPathEvents(parsed, []byte(body))
	if got != nil {
		t.Errorf("expected nil for non-Anthropic, got %+v", got)
	}
}

func TestExtractPathEvents_NoToolUseReturnsEmpty(t *testing.T) {
	body := `{"model":"claude-opus-4-7","messages":[{"role":"user","content":"hello"}]}`
	parsed := mustParse(t, "api.anthropic.com", body)
	got := ExtractPathEvents(parsed, []byte(body))
	if len(got) != 0 {
		t.Errorf("expected empty for no tool_use, got %+v", got)
	}
}

func TestExtractPathEvents_ReadTool(t *testing.T) {
	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/src/payments/x.go"}}
			]}
		]
	}`
	parsed := mustParse(t, "api.anthropic.com", body)
	got := ExtractPathEvents(parsed, []byte(body))
	if len(got) != 1 {
		t.Fatalf("got %d, want 1: %+v", len(got), got)
	}
	if got[0].Tool != "Read" || got[0].Path != "/src/payments/x.go" || got[0].MessageIndex != 0 {
		t.Errorf("event = %+v", got[0])
	}
}

func TestExtractPathEvents_AllFourTools(t *testing.T) {
	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "a", "name": "Read", "input": {"file_path": "/a"}},
				{"type": "tool_use", "id": "b", "name": "Write", "input": {"file_path": "/b"}},
				{"type": "tool_use", "id": "c", "name": "Edit", "input": {"file_path": "/c"}},
				{"type": "tool_use", "id": "d", "name": "MultiEdit", "input": {"file_path": "/d"}}
			]}
		]
	}`
	parsed := mustParse(t, "api.anthropic.com", body)
	got := ExtractPathEvents(parsed, []byte(body))
	if len(got) != 4 {
		t.Fatalf("expected 4 events, got %d: %+v", len(got), got)
	}
	expectedTools := []string{"Read", "Write", "Edit", "MultiEdit"}
	expectedPaths := []string{"/a", "/b", "/c", "/d"}
	for i, want := range expectedTools {
		if got[i].Tool != want || got[i].Path != expectedPaths[i] {
			t.Errorf("[%d] = %+v, want tool=%s path=%s", i, got[i], want, expectedPaths[i])
		}
	}
}

func TestExtractPathEvents_IgnoresOtherTools(t *testing.T) {
	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "a", "name": "Bash", "input": {"command": "ls"}},
				{"type": "tool_use", "id": "b", "name": "Glob", "input": {"pattern": "**/*.go"}},
				{"type": "tool_use", "id": "c", "name": "Grep", "input": {"path": "/x", "pattern": "TODO"}},
				{"type": "tool_use", "id": "d", "name": "WebFetch", "input": {"url": "https://x"}},
				{"type": "tool_use", "id": "e", "name": "Task", "input": {"description": "do thing"}}
			]}
		]
	}`
	parsed := mustParse(t, "api.anthropic.com", body)
	got := ExtractPathEvents(parsed, []byte(body))
	if len(got) != 0 {
		t.Errorf("expected 0 events (unsupported tools), got %+v", got)
	}
}

func TestExtractPathEvents_MissingFilePathSkipped(t *testing.T) {
	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "a", "name": "Read", "input": {}},
				{"type": "tool_use", "id": "b", "name": "Read", "input": {"file_path": ""}},
				{"type": "tool_use", "id": "c", "name": "Read", "input": {"file_path": "/ok"}}
			]}
		]
	}`
	parsed := mustParse(t, "api.anthropic.com", body)
	got := ExtractPathEvents(parsed, []byte(body))
	if len(got) != 1 || got[0].Path != "/ok" {
		t.Errorf("got %+v, want one event with path=/ok", got)
	}
}

func TestExtractPathEvents_MessageIndexPreserved(t *testing.T) {
	body := `{
		"messages": [
			{"role": "user", "content": "hi"},
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "a", "name": "Read", "input": {"file_path": "/a"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "a", "content": "..."}
			]},
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "b", "name": "Write", "input": {"file_path": "/b"}}
			]}
		]
	}`
	parsed := mustParse(t, "api.anthropic.com", body)
	got := ExtractPathEvents(parsed, []byte(body))
	if len(got) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(got), got)
	}
	if got[0].MessageIndex != 1 {
		t.Errorf("[0].MessageIndex = %d, want 1", got[0].MessageIndex)
	}
	if got[1].MessageIndex != 3 {
		t.Errorf("[1].MessageIndex = %d, want 3", got[1].MessageIndex)
	}
}
```

- [ ] **Step 2: Confirm tests fail to compile**

```bash
go test ./internal/pathscan/...
```

Expected: compile error — `ExtractPathEvents`, `PathEvent` undefined.

- [ ] **Step 3: Create `internal/pathscan/pathscan.go`**

```go
// Package pathscan extracts file-path tool_use events from parsed AI
// vendor request bodies.
//
// Currently supports Anthropic's tool_use schema. The supported tool
// names are file-access primitives: Read, Write, Edit, MultiEdit.
// Other tools (Bash, Glob, Grep, WebFetch, Task) are intentionally
// ignored — their path semantics are different and deferred.
//
// pathscan is a leaf package: depends only on stdlib + internal/parser.
package pathscan

import (
	"encoding/json"

	"railcore/internal/parser"
)

// PathEvent is one tool_use invocation that names a file path.
type PathEvent struct {
	Tool         string // "Read" | "Write" | "Edit" | "MultiEdit"
	Path         string // value of input.file_path
	MessageIndex int    // position of the originating message in messages[]
}

// supportedTools is the hardcoded list of tool names we extract paths
// from. Other tools are intentionally skipped (see package doc).
var supportedTools = map[string]bool{
	"Read":      true,
	"Write":     true,
	"Edit":      true,
	"MultiEdit": true,
}

// ExtractPathEvents returns every file_path argument from supported
// file-access tool_use blocks in the request. Returns nil for
// non-Anthropic vendors. Returns empty (non-nil) slice for Anthropic
// bodies with no recognized tool_use blocks.
//
// body is the raw request body — passed alongside parsed so we can use
// the typed parser.ExtractToolUses helper without re-walking the
// flattened Texts in parsed.
func ExtractPathEvents(parsed *parser.ParsedRequest, body []byte) []PathEvent {
	if parsed == nil || parsed.Vendor != "anthropic" {
		return nil
	}
	tools := parser.ExtractToolUses("api.anthropic.com", body)
	if len(tools) == 0 {
		return nil
	}
	var out []PathEvent
	for _, tu := range tools {
		if !supportedTools[tu.Tool] {
			continue
		}
		var input struct {
			FilePath string `json:"file_path"`
		}
		if err := json.Unmarshal(tu.Input, &input); err != nil {
			continue
		}
		if input.FilePath == "" {
			continue
		}
		out = append(out, PathEvent{
			Tool:         tu.Tool,
			Path:         input.FilePath,
			MessageIndex: tu.MessageIndex,
		})
	}
	return out
}
```

- [ ] **Step 4: Run tests and confirm pass**

```bash
go test -race -count=1 ./internal/pathscan/...
```

Expected: 7 PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/pathscan/
git commit -m "feat(pathscan): extract file paths from Anthropic tool_use blocks"
```

---

## Task 6: Per-finding `detector` field (preparation for proxy 403 body change)

Sub-project #4 changes the 403 body shape so the `detector` field moves from top level to per-finding. This is a breaking change to consumers but enables mixed-stage responses. This task updates `EnrichedFinding.MarshalJSON` to emit `detector: "secret-scan"` per finding; subsequent tasks add `PathFinding` with `detector: "path-scan"` and update the proxy.

**Files:**
- Modify: `internal/stage/secretscan/stage.go`
- Modify: `internal/stage/secretscan/stage_test.go`

- [ ] **Step 1: Append failing tests for the new field**

Append to `internal/stage/secretscan/stage_test.go`:

```go

func TestEnrichedFinding_MarshalJSON_IncludesDetector(t *testing.T) {
	ef := EnrichedFinding{
		Finding:      detector.Finding{Pattern: "aws_access_key_id", Severity: detector.SeverityHigh},
		Role:         "user",
		MessageIndex: 0,
	}
	data, err := json.Marshal(ef)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), `"detector":"secret-scan"`) {
		t.Errorf("expected detector field in output; got %s", string(data))
	}
}
```

- [ ] **Step 2: Confirm test fails**

```bash
go test -run TestEnrichedFinding_MarshalJSON_IncludesDetector ./internal/stage/secretscan/...
```

Expected: FAIL — current MarshalJSON doesn't emit `detector`.

- [ ] **Step 3: Update `EnrichedFinding.MarshalJSON`**

In `internal/stage/secretscan/stage.go`, find the existing `MarshalJSON` method:

```go
func (e EnrichedFinding) MarshalJSON() ([]byte, error) {
	type flat struct {
		Pattern      string `json:"pattern"`
		Severity     string `json:"severity"`
		Role         string `json:"role"`
		MessageIndex int    `json:"message_index"`
		Rule         string `json:"rule,omitempty"`
	}
	return json.Marshal(flat{
		Pattern:      e.Finding.Pattern,
		Severity:     e.Finding.Severity.String(),
		Role:         e.Role,
		MessageIndex: e.MessageIndex,
		Rule:         e.Rule,
	})
}
```

Replace with:

```go
func (e EnrichedFinding) MarshalJSON() ([]byte, error) {
	type flat struct {
		Detector     string `json:"detector"`
		Pattern      string `json:"pattern"`
		Severity     string `json:"severity"`
		Role         string `json:"role"`
		MessageIndex int    `json:"message_index"`
		Rule         string `json:"rule,omitempty"`
	}
	return json.Marshal(flat{
		Detector:     "secret-scan",
		Pattern:      e.Finding.Pattern,
		Severity:     e.Finding.Severity.String(),
		Role:         e.Role,
		MessageIndex: e.MessageIndex,
		Rule:         e.Rule,
	})
}
```

- [ ] **Step 4: Run tests and confirm pass**

```bash
go test -race -count=1 ./internal/stage/secretscan/...
```

Expected: existing tests + new one pass.

- [ ] **Step 5: Commit**

```bash
git add internal/stage/secretscan/stage.go internal/stage/secretscan/stage_test.go
git commit -m "feat(secretscan): emit per-finding detector field in MarshalJSON"
```

---

## Task 7: `pathscan` stage — `PathFinding` and `Process`

**Files:**
- Create: `internal/stage/pathscan/stage.go`
- Create: `internal/stage/pathscan/stage_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/stage/pathscan/stage_test.go`:

```go
package pathscan

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"railcore/internal/pipeline"
	"railcore/internal/policy"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newRC(t *testing.T, host, body, method, path string) *pipeline.RequestCtx {
	t.Helper()
	req := httptest.NewRequest(method, "https://"+host+path, strings.NewReader(body))
	req.Body = io.NopCloser(strings.NewReader(body))
	return &pipeline.RequestCtx{
		Req:       req,
		Host:      host,
		Metadata:  map[string]any{"request_id": "req-1", "body": []byte(body)},
		StartedAt: time.Now(),
	}
}

func mkPolicy(t *testing.T, yamlText string) *policy.Policy {
	t.Helper()
	p, err := policy.LoadFromBytes([]byte(yamlText))
	if err != nil {
		t.Fatalf("policy.LoadFromBytes: %v", err)
	}
	return p
}

func TestPathscan_NonAnthropicHostPassesThrough(t *testing.T) {
	pol := mkPolicy(t, `
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
`)
	s := New(Config{Policy: pol}, discardLogger())
	rc := newRC(t, "example.com", `{}`, http.MethodPost, "/anything")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Errorf("decision = %v, want Continue", dec)
	}
	if _, ok := rc.Metadata["pathscan.findings"]; ok {
		t.Errorf("expected no metadata for non-Anthropic")
	}
}

func TestPathscan_AnthropicWithNoToolUsePassesThrough(t *testing.T) {
	pol := mkPolicy(t, `
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
`)
	s := New(Config{Policy: pol}, discardLogger())
	body := `{"messages":[{"role":"user","content":"hello"}]}`
	rc := newRC(t, "api.anthropic.com", body, http.MethodPost, "/v1/messages")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Errorf("decision = %v, want Continue", dec)
	}
}

func TestPathscan_ReadToolBlockedByPolicy(t *testing.T) {
	pol := mkPolicy(t, `
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
`)
	s := New(Config{Policy: pol}, discardLogger())
	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/src/payments/charge.go"}}
			]}
		]
	}`
	rc := newRC(t, "api.anthropic.com", body, http.MethodPost, "/v1/messages")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Block {
		t.Fatalf("decision = %v, want Block", dec)
	}
	findings, ok := rc.Metadata["pathscan.findings"].([]PathFinding)
	if !ok || len(findings) != 1 {
		t.Fatalf("expected 1 finding in metadata, got %v", rc.Metadata["pathscan.findings"])
	}
	if findings[0].Tool != "Read" || findings[0].Path != "/src/payments/charge.go" || findings[0].Rule != "block-payments" {
		t.Errorf("finding = %+v", findings[0])
	}
}

func TestPathscan_ReadToolAllowedSuppressesFinding(t *testing.T) {
	pol := mkPolicy(t, `
version: 1
rules:
  - name: allow-payments-tests
    match: {path: "**/payments/test/**"}
    action: allow
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
`)
	s := New(Config{Policy: pol}, discardLogger())
	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/src/payments/test/fixture.go"}}
			]}
		]
	}`
	rc := newRC(t, "api.anthropic.com", body, http.MethodPost, "/v1/messages")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Errorf("decision = %v, want Continue (allowed)", dec)
	}
	findings, _ := rc.Metadata["pathscan.findings"].([]PathFinding)
	for _, f := range findings {
		if f.Path == "/src/payments/test/fixture.go" {
			t.Errorf("allowed path leaked into metadata: %+v", f)
		}
	}
}

func TestPathscan_NilPolicyContinues(t *testing.T) {
	s := New(Config{Policy: nil}, discardLogger())
	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/src/payments/x.go"}}
			]}
		]
	}`
	rc := newRC(t, "api.anthropic.com", body, http.MethodPost, "/v1/messages")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Errorf("decision = %v, want Continue (nil policy)", dec)
	}
	if _, ok := rc.Metadata["pathscan.findings"]; ok {
		t.Errorf("expected no metadata with nil policy")
	}
}

func TestPathFinding_MarshalJSON(t *testing.T) {
	f := PathFinding{
		Tool:         "Read",
		Path:         "/src/payments/charge.go",
		MessageIndex: 1,
		Rule:         "block-payments",
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(data)
	for _, want := range []string{
		`"detector":"path-scan"`,
		`"tool":"Read"`,
		`"path":"/src/payments/charge.go"`,
		`"message_index":1`,
		`"rule":"block-payments"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("expected %s in output; got %s", want, s)
		}
	}
}

func TestPathFinding_MarshalJSON_RuleOmittedWhenEmpty(t *testing.T) {
	f := PathFinding{
		Tool:         "Read",
		Path:         "/x",
		MessageIndex: 0,
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(data), `"rule"`) {
		t.Errorf("rule field should be omitted when empty; got %s", string(data))
	}
}
```

- [ ] **Step 2: Confirm tests fail to compile**

```bash
go test ./internal/stage/pathscan/...
```

Expected: compile error — `Config`, `New`, `PathFinding` undefined.

- [ ] **Step 3: Create `internal/stage/pathscan/stage.go`**

```go
// Package pathscan implements the pipeline.Stage that extracts file
// paths from Anthropic tool_use blocks and applies policy rules to them.
//
// It is the integration point between internal/pathscan (extraction),
// internal/policy (decision), and internal/pipeline.
package pathscan

import (
	"context"
	"encoding/json"
	"log/slog"

	"railcore/internal/parser"
	"railcore/internal/pathscan"
	"railcore/internal/pipeline"
	"railcore/internal/policy"
)

// Config controls the stage's runtime behavior.
type Config struct {
	// Policy drives all decisions. When nil, the stage is a silent no-op.
	Policy *policy.Policy
}

// PathFinding pairs an extracted PathEvent with the rule that decided
// its fate. Stored in rc.Metadata["pathscan.findings"] for the proxy's
// 403 body and the future audit logger.
type PathFinding struct {
	Tool         string
	Path         string
	MessageIndex int
	Rule         string
}

// MarshalJSON emits the public shape used in 403 bodies. The detector
// field identifies the stage; the rule field is omitted when empty.
func (p PathFinding) MarshalJSON() ([]byte, error) {
	type flat struct {
		Detector     string `json:"detector"`
		Tool         string `json:"tool"`
		Path         string `json:"path"`
		MessageIndex int    `json:"message_index"`
		Rule         string `json:"rule,omitempty"`
	}
	return json.Marshal(flat{
		Detector:     "path-scan",
		Tool:         p.Tool,
		Path:         p.Path,
		MessageIndex: p.MessageIndex,
		Rule:         p.Rule,
	})
}

// Stage is the path-scanning pipeline stage.
type Stage struct {
	cfg Config
	log *slog.Logger
}

// New returns a configured Stage. If log is nil, slog.Default() is used.
func New(cfg Config, log *slog.Logger) *Stage {
	if log == nil {
		log = slog.Default()
	}
	return &Stage{cfg: cfg, log: log}
}

// Name implements pipeline.Stage.
func (s *Stage) Name() string { return "path-scan" }

// Process implements pipeline.Stage. See the package doc and the spec
// at docs/superpowers/specs/2026-05-17-path-based-rules-design.md.
func (s *Stage) Process(ctx context.Context, rc *pipeline.RequestCtx) (pipeline.Decision, error) {
	if s.cfg.Policy == nil {
		return pipeline.Continue, nil
	}

	body, ok := rc.Metadata["body"].([]byte)
	if !ok {
		return pipeline.Continue, nil
	}

	parsed, err := parser.ParseRequest(rc.Host, rc.Req, body)
	if err != nil || parsed == nil {
		return pipeline.Continue, nil
	}

	events := pathscan.ExtractPathEvents(parsed, body)
	if len(events) == 0 {
		return pipeline.Continue, nil
	}

	requestID, _ := rc.Metadata["request_id"].(string)
	var kept []PathFinding
	anyBlock := false

	for _, e := range events {
		action, rule := s.cfg.Policy.DecidePath(e.Path)
		ruleName := ""
		if rule != nil {
			ruleName = rule.Name
		}

		switch action {
		case policy.ActionAllow:
			s.log.Debug("policy allowed path",
				"request_id", requestID,
				"tool", e.Tool,
				"path", e.Path,
				"rule", ruleName)
			// Suppressed; not appended to kept.
		case policy.ActionBlock:
			kept = append(kept, PathFinding{
				Tool:         e.Tool,
				Path:         e.Path,
				MessageIndex: e.MessageIndex,
				Rule:         ruleName,
			})
			anyBlock = true
			s.log.Warn("pathscan blocked",
				"request_id", requestID,
				"tool", e.Tool,
				"path", e.Path,
				"rule", ruleName)
		case policy.ActionWarn:
			fallthrough
		default:
			kept = append(kept, PathFinding{
				Tool:         e.Tool,
				Path:         e.Path,
				MessageIndex: e.MessageIndex,
				Rule:         ruleName,
			})
			if ruleName != "" {
				s.log.Info("pathscan findings",
					"request_id", requestID,
					"tool", e.Tool,
					"path", e.Path,
					"rule", ruleName)
			}
		}
	}

	if len(kept) == 0 {
		return pipeline.Continue, nil
	}

	rc.Metadata["pathscan.findings"] = kept

	if anyBlock {
		return pipeline.Block, nil
	}
	return pipeline.Continue, nil
}
```

- [ ] **Step 4: Run tests and confirm pass**

```bash
go test -race -count=1 ./internal/stage/pathscan/...
```

Expected: 7 PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/stage/pathscan/
git commit -m "feat(pathscan): pipeline stage with policy-driven path decisions"
```

---

## Task 8: Proxy — 403 body aggregates findings from both metadata keys

**Files:**
- Modify: `internal/proxy/upstream.go`
- Modify: `internal/proxy/server_test.go` (append + update)

This task changes the 403 body's `detector` field from top-level to per-finding (already done for secretscan in Task 6, pathscan does this by default). `writeBlockResp` now aggregates findings from BOTH `secretscan.findings` and `pathscan.findings`.

- [ ] **Step 1: Append failing test for path-block 403 body**

Append to `internal/proxy/server_test.go`:

```go

// pathBlockStage simulates the pathscan stage: stashes a PathFinding-shaped
// map and returns Block. Lets us test the proxy's aggregation without an
// import cycle to the real pathscan package.
type pathBlockStage struct{}

func (pathBlockStage) Name() string { return "test-path-block" }
func (pathBlockStage) Process(_ context.Context, rc *pipeline.RequestCtx) (pipeline.Decision, error) {
	rc.Metadata["pathscan.findings"] = []map[string]any{
		{
			"detector":      "path-scan",
			"tool":          "Read",
			"path":          "/src/payments/charge.go",
			"message_index": 0,
			"rule":          "block-payments",
		},
	}
	return pipeline.Block, nil
}

func TestProxy_BlockBodyIncludesPathFindings(t *testing.T) {
	srv, addr := newTestServer(t)
	srv.cfg.Pipeline.Register(pathBlockStage{})

	caPool := x509.NewCertPool()
	caPool.AddCert(srv.cfg.CA.RootCert())
	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "block.test"},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get("https://block.test/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var parsed struct {
		Error    string                   `json:"error"`
		Findings []map[string]interface{} `json:"findings"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("body not JSON: %v, body=%s", err, string(body))
	}
	if len(parsed.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(parsed.Findings))
	}
	f := parsed.Findings[0]
	if f["detector"] != "path-scan" {
		t.Errorf("detector = %v, want path-scan", f["detector"])
	}
	if f["tool"] != "Read" {
		t.Errorf("tool = %v, want Read", f["tool"])
	}
	if f["path"] != "/src/payments/charge.go" {
		t.Errorf("path = %v, want /src/payments/charge.go", f["path"])
	}
	if f["rule"] != "block-payments" {
		t.Errorf("rule = %v, want block-payments", f["rule"])
	}
}
```

- [ ] **Step 2: Confirm test fails**

```bash
go test -race -count=1 -run TestProxy_BlockBodyIncludesPathFindings ./internal/proxy/...
```

Expected: FAIL — `writeBlockResp` doesn't read `pathscan.findings` yet.

- [ ] **Step 3: Update `writeBlockResp` in `internal/proxy/upstream.go`**

Find the existing `writeBlockResp` function. The current signature takes `(w http.ResponseWriter, requestID string, findings any)` and just embeds `findings` directly. Replace with a version that aggregates from both metadata keys:

The existing call site looks like:
```go
		if dec == pipeline.Block {
			findings := rc.Metadata["secretscan.findings"]
			writeBlockResp(w, requestID, findings)
			return
		}
```

Replace it with:
```go
		if dec == pipeline.Block {
			writeBlockResp(w, requestID, rc)
			return
		}
```

Then replace the `writeBlockResp` function body with:

```go
// writeBlockResp writes a 403 with a JSON body listing the findings (if
// any) from both pathscan and secretscan stages. The detector field is
// per-finding (each finding's MarshalJSON emits its own detector value).
//
// Matched secret bytes are deliberately never echoed; path values ARE
// echoed because the path is the actionable signal for operators.
func writeBlockResp(w http.ResponseWriter, requestID string, rc *pipeline.RequestCtx) {
	body := map[string]any{
		"error":      "blocked by railcore policy",
		"request_id": requestID,
	}

	// Aggregate findings from both stages. Each finding type implements
	// MarshalJSON to emit its own detector field. We accumulate as []any
	// so json.Encode iterates whichever shapes are present.
	var all []any
	if v, ok := rc.Metadata["pathscan.findings"]; ok {
		switch slice := v.(type) {
		case []map[string]any:
			for _, m := range slice {
				all = append(all, m)
			}
		default:
			all = append(all, v)
		}
	}
	if v, ok := rc.Metadata["secretscan.findings"]; ok {
		switch slice := v.(type) {
		case []map[string]any:
			for _, m := range slice {
				all = append(all, m)
			}
		default:
			all = append(all, v)
		}
	}
	if len(all) > 0 {
		// If there's only one, unwrap it (otherwise the outer slice gets
		// JSON-encoded as an array of slices). Use json.RawMessage to
		// flatten naturally instead.
		body["findings"] = flattenFindings(all)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// flattenFindings handles the case where rc.Metadata holds typed slices
// (e.g., []secretscan.EnrichedFinding or []pathscan.PathFinding) that
// must be unwrapped, vs. raw []map[string]any from tests. We marshal
// each input to JSON, then unmarshal as a []any, producing a uniformly
// shaped slice.
func flattenFindings(in []any) []any {
	var out []any
	for _, v := range in {
		raw, err := json.Marshal(v)
		if err != nil {
			continue
		}
		var single any
		if err := json.Unmarshal(raw, &single); err != nil {
			continue
		}
		switch s := single.(type) {
		case []any:
			out = append(out, s...)
		default:
			out = append(out, single)
		}
	}
	return out
}
```

Add `"railcore/internal/pipeline"` to upstream.go's imports if not already there (probably already imported).

- [ ] **Step 4: Update the existing `TestProxy_BlockBodyIncludesFindings` test (sub-project #2)**

The existing test asserts `parsed.Detector == "secret-scan"` from the TOP level. Now that `detector` is per-finding, find this test and update its assertion. The test currently looks like:

```go
	var parsed struct {
		Error    string                   `json:"error"`
		Detector string                   `json:"detector"`
		Findings []map[string]interface{} `json:"findings"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("body not JSON: %v, body=%s", err, string(body))
	}
	if parsed.Error == "" {
		t.Errorf("missing error field; body=%s", string(body))
	}
	if len(parsed.Findings) != 1 {
		t.Fatalf("expected 1 finding in body, got %d; body=%s", len(parsed.Findings), string(body))
	}
	if parsed.Findings[0]["pattern"] != "aws_access_key_id" {
		t.Errorf("pattern = %v, want aws_access_key_id", parsed.Findings[0]["pattern"])
	}
```

Replace with:

```go
	var parsed struct {
		Error    string                   `json:"error"`
		Findings []map[string]interface{} `json:"findings"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("body not JSON: %v, body=%s", err, string(body))
	}
	if parsed.Error == "" {
		t.Errorf("missing error field; body=%s", string(body))
	}
	if len(parsed.Findings) != 1 {
		t.Fatalf("expected 1 finding in body, got %d; body=%s", len(parsed.Findings), string(body))
	}
	if parsed.Findings[0]["detector"] != "secret-scan" {
		t.Errorf("finding detector = %v, want secret-scan", parsed.Findings[0]["detector"])
	}
	if parsed.Findings[0]["pattern"] != "aws_access_key_id" {
		t.Errorf("pattern = %v, want aws_access_key_id", parsed.Findings[0]["pattern"])
	}
```

If a similar update is needed for `TestProxy_BlockBodyIncludesRule` from sub-project #3, do the same (it likely doesn't assert top-level detector but verify by reading the test).

- [ ] **Step 5: Run all proxy tests**

```bash
go test -race -count=1 ./internal/proxy/...
```

Expected: all proxy tests pass including new and updated ones.

- [ ] **Step 6: Update integration tests' detector assertions**

Two integration tests in `test/integration/` likely assert top-level `parsed.Detector`. Update them similarly. Find:

`test/integration/secretscan_test.go` — `TestSecretscan_E2E_BlockOnAWSKey` asserts `parsed.Detector != "secret-scan"`. Replace top-level detector check with per-finding check.

`test/integration/policy_test.go` — `TestPolicy_E2E_YAMLBlocksAWS` similarly.

Both tests should change from:

```go
	var parsed struct {
		Error    string                   `json:"error"`
		Detector string                   `json:"detector"`
		Findings []map[string]interface{} `json:"findings"`
	}
	// ...
	if parsed.Detector != "secret-scan" {
		t.Errorf("detector = %q, want secret-scan", parsed.Detector)
	}
```

To:

```go
	var parsed struct {
		Error    string                   `json:"error"`
		Findings []map[string]interface{} `json:"findings"`
	}
	// ...
	if len(parsed.Findings) > 0 && parsed.Findings[0]["detector"] != "secret-scan" {
		t.Errorf("finding detector = %v, want secret-scan", parsed.Findings[0]["detector"])
	}
```

- [ ] **Step 7: Run the full test suite**

```bash
go test -race -count=1 ./...
go vet ./...
```

Expected: all tests pass, vet clean.

- [ ] **Step 8: Commit**

```bash
git add internal/proxy/upstream.go internal/proxy/server_test.go test/integration/secretscan_test.go test/integration/policy_test.go
git commit -m "feat(proxy): aggregate path + secret findings in 403; migrate detector to per-finding"
```

---

## Task 9: Wire pathscan stage into the binary

**Files:**
- Modify: `cmd/railcore/main.go`

- [ ] **Step 1: Update `cmd/railcore/main.go` to register pathscan**

Find the existing chain registration in `main`:

```go
	chain := pipeline.NewChain().WithLogger(logger)
	chain.Register(secretscan.New(secretscan.Config{
		BlockOnDetect: effectiveBlock,
		Policy:        loadedPolicy,
	}, logger))
```

Replace with:

```go
	chain := pipeline.NewChain().WithLogger(logger)
	chain.Register(pathscan.New(pathscan.Config{Policy: loadedPolicy}, logger))
	chain.Register(secretscan.New(secretscan.Config{
		BlockOnDetect: effectiveBlock,
		Policy:        loadedPolicy,
	}, logger))
```

Add to the imports:

```go
	"railcore/internal/stage/pathscan"
```

- [ ] **Step 2: Build and smoke-test**

```bash
make build
mkdir -p /tmp/railcore-sp4
cat > /tmp/railcore-sp4/policy.yaml <<'EOF'
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
  - name: default
    match: {all: true}
    action: warn
EOF
./railcore proxy --port 19443 --data-dir /tmp/railcore-sp4 2>&1 | head -3 &
SP=$!
sleep 1
kill $SP 2>/dev/null
wait 2>/dev/null
rm -rf /tmp/railcore-sp4
```

Expected: proxy starts; startup log includes `policy_mode=file rules=2`.

- [ ] **Step 3: Run the full test suite**

```bash
go test -race -count=1 ./...
go vet ./...
```

Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add cmd/railcore/main.go
git commit -m "feat(cmd): register pathscan stage before secretscan"
```

---

## Task 10: End-to-end integration tests

**Files:**
- Create: `test/integration/pathscan_test.go`

- [ ] **Step 1: Create the test file**

Create `test/integration/pathscan_test.go`:

```go
// End-to-end tests for sub-project #4: real http.Client through a real
// proxy with both pathscan and secretscan stages, against a fake
// httptest upstream. Exercises Anthropic tool_use path matching.
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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"railcore/internal/ca"
	"railcore/internal/pipeline"
	"railcore/internal/policy"
	"railcore/internal/proxy"
	pathscanstage "railcore/internal/stage/pathscan"
)

func setupPathscan(t *testing.T, policyYAML string) (client *http.Client, upstreamHits *int32, cleanup func()) {
	t.Helper()

	var hits int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	pol, err := policy.LoadFromBytes([]byte(policyYAML))
	if err != nil {
		t.Fatalf("policy.LoadFromBytes: %v", err)
	}

	caInst, err := ca.GenerateOrLoad(t.TempDir())
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	chain := pipeline.NewChain()
	chain.Register(pathscanstage.New(pathscanstage.Config{Policy: pol}, nil))

	srv := proxy.New(proxy.Config{
		Addr:             "127.0.0.1:0",
		CA:               caInst,
		Pipeline:         chain,
		UpstreamTLS:      &tls.Config{RootCAs: upstreamPool, ServerName: upstreamURL.Hostname()},
		UpstreamResolver: func(_ string) (string, error) { return upstreamURL.Host, nil },
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
	}
	return client, &hits, cleanup
}

func TestPathscan_E2E_BlockOnPayments(t *testing.T) {
	yaml := `
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
  - name: default
    match: {all: true}
    action: warn
`
	client, upstreamHits, cleanup := setupPathscan(t, yaml)
	defer cleanup()

	body := `{
		"model": "claude-opus-4-7",
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := atomic.LoadInt32(upstreamHits); got != 0 {
		t.Fatalf("upstream hits = %d, want 0", got)
	}

	respBody, _ := io.ReadAll(resp.Body)
	var parsed struct {
		Findings []map[string]interface{} `json:"findings"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if len(parsed.Findings) < 1 {
		t.Fatalf("expected >=1 finding, got %d", len(parsed.Findings))
	}
	f := parsed.Findings[0]
	if f["detector"] != "path-scan" {
		t.Errorf("detector = %v, want path-scan", f["detector"])
	}
	if f["tool"] != "Read" {
		t.Errorf("tool = %v, want Read", f["tool"])
	}
	if f["path"] != "/src/payments/charge.go" {
		t.Errorf("path = %v, want /src/payments/charge.go", f["path"])
	}
	if f["rule"] != "block-payments" {
		t.Errorf("rule = %v, want block-payments", f["rule"])
	}
}

func TestPathscan_E2E_AllowOverridesBlock(t *testing.T) {
	yaml := `
version: 1
rules:
  - name: allow-payments-test
    match: {path: "**/payments/test/**"}
    action: allow
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
`
	client, upstreamHits, cleanup := setupPathscan(t, yaml)
	defer cleanup()

	body := `{
		"model": "claude-opus-4-7",
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "t1", "name": "Read",
				 "input": {"file_path": "/src/payments/test/fixture.go"}}
			]}
		]
	}`
	resp, err := client.Post("https://api.anthropic.com/v1/messages", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (allow precedes block)", resp.StatusCode)
	}
	if got := atomic.LoadInt32(upstreamHits); got != 1 {
		t.Fatalf("upstream hits = %d, want 1", got)
	}
}

func TestPathscan_E2E_BadPathYAMLFailsLoader(t *testing.T) {
	_, err := policy.LoadFromBytes([]byte(`
version: 1
rules:
  - name: r
    match: {path: ""}
    action: block
`))
	if err == nil {
		t.Fatal("expected error from LoadFromBytes on empty path")
	}
	if !strings.Contains(err.Error(), "path") {
		t.Errorf("error message should mention path; got %q", err.Error())
	}
}
```

- [ ] **Step 2: Run the integration tests**

```bash
go test -race -count=1 ./test/integration/...
```

Expected: existing tests still pass + 3 new pathscan ones.

- [ ] **Step 3: Full test suite**

```bash
go test -race -count=1 ./...
go vet ./...
```

Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add test/integration/pathscan_test.go
git commit -m "test(integration): end-to-end pathscan block + allow scenarios"
```

---

## Task 11: Manual acceptance test

**Files:** none modified during the test itself; result recorded in spec on completion.

- [ ] **Step 1: Build the binary**

```bash
make build
```

- [ ] **Step 2: Write a test policy**

```bash
cat > ~/.railcore/policy.yaml <<'EOF'
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
  - name: warn-everything-else
    match: {all: true}
    action: warn
EOF
```

- [ ] **Step 3: Start the proxy**

```bash
./railcore proxy --port 9443
```

Verify startup log shows `rules=2`.

- [ ] **Step 4: Launch Claude Code through the proxy**

In a new terminal:

```bash
HTTPS_PROXY=http://127.0.0.1:9443 \
NODE_EXTRA_CA_CERTS=$HOME/.railcore/ca/ca.crt \
  claude
```

- [ ] **Step 5: Test the block rule**

In Claude Code, ask:

```
Please read the file at src/payments/charge.go and tell me what it does.
```

(You don't need such a file to exist — we just want the agent to ATTEMPT to Read that path.)

Expected:
- Claude Code's agent will try to invoke `Read` with `file_path: ...payments/charge.go`.
- That request gets a 403 from the proxy.
- Claude Code reports the error to you OR tries a different path.
- Proxy log contains: `WARN pathscan blocked rule=block-payments tool=Read path=...`.

- [ ] **Step 6: Record the result**

Append §11 Acceptance Result to `docs/superpowers/specs/2026-05-17-path-based-rules-design.md`:

```markdown

---

## 11. Acceptance Result

**Date:** YYYY-MM-DD (fill in)
**Tool exercised:** Claude Code via HTTPS_PROXY + NODE_EXTRA_CA_CERTS.

**Test policy:**
- `block-payments` rule with `path: "**/payments/**"`.
- `warn-everything-else` catch-all.

**Path block rule:** Pass / Fail (record observed behavior).

- Agent's Read tool call on `src/payments/charge.go` → expected 403.
- Proxy log: `WARN pathscan blocked rule=block-payments tool=Read path=...`.
- 403 body's `findings[0].detector = "path-scan"`, `tool = "Read"`, `rule = "block-payments"`.

**Status:** Pass. Sub-project #4 done definition §10 satisfied.
```

- [ ] **Step 7: Commit the acceptance record**

```bash
git add docs/superpowers/specs/2026-05-17-path-based-rules-design.md
git commit -m "docs(spec): record sub-project #4 acceptance result"
```

---

## Self-Review Notes

After all tasks:

1. **Spec coverage matrix:**
   - §3 Repo layout → Task 1 (parser change), Task 5 (pathscan), Task 7 (stage), Task 9 (cmd).
   - §4 YAML schema → Task 4.
   - §5.1 pathscan package API → Task 5.
   - §5.2 policy additions (Match.Path, DecidePath) → Tasks 2, 3.
   - §5.3 stage Process → Task 7.
   - §5.4 proxy 403 aggregation → Task 8.
   - §5.5 cmd wiring → Task 9.
   - §6 Data flow → Tasks 7, 8.
   - §7 Configuration (no new flags) → Task 9.
   - §8.1 startup errors → Task 4 (per-row error message tests).
   - §8.2-8.3 per-request errors and edge cases → Task 7 (stage tests cover these).
   - §8.4 logging → Task 7.
   - §9.1 pathscan unit tests → Task 5.
   - §9.2 policy unit tests → Tasks 2, 3, 4.
   - §9.3 stage unit tests → Task 7.
   - §9.4 in-process integration → Task 8.
   - §9.5 e2e integration → Task 10.
   - §9.6 manual acceptance → Task 11.

2. **Placeholders:** none.

3. **Type consistency:**
   - `PathEvent` (in `internal/pathscan/`) has fields: Tool, Path, MessageIndex. `PathFinding` (in `internal/stage/pathscan/`) has fields: Tool, Path, MessageIndex, Rule. Aligned.
   - `ToolUse` (in `internal/parser/`) has fields: Tool, Input, MessageIndex. Used by `pathscan.ExtractPathEvents`.
   - `Match` struct fields: `Pattern *globPattern`, `Severity *detector.Severity`, `All bool`, `Path *doublestarPattern`. Used consistently across `policy.go`, `load.go`, `match.go`, tests.
   - `Action` enum (`ActionWarn`, `ActionAllow`, `ActionBlock`) — same as sub-project #3.
   - `detector` JSON field key is per-finding: `"detector": "secret-scan"` from EnrichedFinding, `"detector": "path-scan"` from PathFinding.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-17-path-based-rules.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
