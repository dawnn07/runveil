# Policy Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give users a YAML policy file that controls Railcore's response to detector findings — three actions (`allow`/`block`/`warn`), top-down first-match-wins evaluation, glob-and-severity match conditions — wired into the existing secretscan stage without adding a new pipeline stage.

**Architecture:** One new leaf package `internal/policy/` (types, glob compile, decide logic, YAML loader). Two file edits: `internal/stage/secretscan/stage.go` gets a `Config.Policy` field and a new `processWithPolicy` code path; `cmd/railcore/main.go` gets a `--policy` CLI flag and a policy-resolution startup block. The 403 JSON body already produced by sub-project #2 gains one optional new field (`rule`) via `EnrichedFinding.MarshalJSON`.

**Tech Stack:** Go 1.25 (stdlib `regexp`, `errors`, `os`), `gopkg.in/yaml.v3` (Apache 2.0) — the only new third-party dependency. Existing deps (`github.com/google/uuid`, `golang.org/x/net`, `go.uber.org/goleak`) are unchanged.

**Spec:** [`docs/superpowers/specs/2026-05-17-policy-engine-design.md`](../specs/2026-05-17-policy-engine-design.md)

---

## File Map

| File | Purpose |
|---|---|
| `internal/policy/policy.go` | `Action`, `Rule`, `Match`, `Policy` types; `Decide` method |
| `internal/policy/match.go` | Glob → regex compile, `globPattern.match` |
| `internal/policy/load.go` | YAML schema, `LoadFromBytes`, `LoadFromFile`, validation |
| `internal/policy/policy_test.go` | Unit tests for types, glob, Decide, loader |
| `internal/stage/secretscan/stage.go` | **Modify:** add `Config.Policy`, `EnrichedFinding.Rule`, `processWithPolicy` |
| `internal/stage/secretscan/stage_test.go` | **Modify:** append policy-driven decision tests |
| `internal/proxy/server_test.go` | **Modify:** append proxy-level test asserting `findings[0].rule` in 403 body |
| `cmd/railcore/main.go` | **Modify:** add `--policy` flag, resolve+load policy, wire to secretscan Config |
| `test/integration/policy_test.go` | End-to-end YAML-driven block + allow scenarios |
| `go.mod`, `go.sum` | **Modify:** new `gopkg.in/yaml.v3` dep |

**Dependency direction (unchanged from previous sub-projects):**

```
cmd/railcore
   └── internal/stage/secretscan
          ├── internal/parser     (leaf)
          ├── internal/detector   (leaf)
          ├── internal/policy     (NEW leaf — depends on stdlib + internal/detector)
          └── internal/pipeline   (leaf)
```

`internal/policy/` is a leaf: it imports only stdlib + `internal/detector` (for `Severity`). No other internal imports.

---

## Task 1: Policy package — types + empty Decide

**Files:**
- Create: `internal/policy/policy.go`
- Create: `internal/policy/policy_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/policy/policy_test.go`:

```go
package policy

import (
	"testing"

	"railcore/internal/detector"
)

func TestAction_String(t *testing.T) {
	cases := []struct {
		a    Action
		want string
	}{
		{ActionWarn, "warn"},
		{ActionAllow, "allow"},
		{ActionBlock, "block"},
	}
	for _, c := range cases {
		if got := c.a.String(); got != c.want {
			t.Errorf("Action(%d).String() = %q, want %q", c.a, got, c.want)
		}
	}
}

func TestDecide_NilPolicyReturnsWarn(t *testing.T) {
	var p *Policy
	a, r := p.Decide(detector.Finding{Pattern: "anything", Severity: detector.SeverityHigh})
	if a != ActionWarn {
		t.Errorf("nil policy: action = %v, want ActionWarn", a)
	}
	if r != nil {
		t.Errorf("nil policy: rule = %v, want nil", r)
	}
}

func TestDecide_EmptyPolicyReturnsWarn(t *testing.T) {
	p := &Policy{Version: 1, Rules: nil}
	a, r := p.Decide(detector.Finding{Pattern: "anything", Severity: detector.SeverityHigh})
	if a != ActionWarn {
		t.Errorf("empty policy: action = %v, want ActionWarn", a)
	}
	if r != nil {
		t.Errorf("empty policy: rule = %v, want nil", r)
	}
}
```

- [ ] **Step 2: Run and confirm tests fail**

```bash
go test ./internal/policy/...
```

Expected: compile error — `Action`, `ActionWarn`, etc., `Policy`, `Decide` undefined.

- [ ] **Step 3: Implement `policy.go`**

Create `internal/policy/policy.go`:

```go
// Package policy parses and evaluates YAML-driven decision rules over
// detector findings. It is a leaf package: it depends only on stdlib
// and internal/detector (for the Severity enum).
//
// See internal/policy/load.go for the YAML schema and validation.
package policy

import (
	"railcore/internal/detector"
)

// Action is what a policy decides to do with a single finding.
//
// Only ActionBlock causes the proxy to return 403. ActionAllow suppresses
// the finding from logs and from the BLOCK count. ActionWarn is the
// "log but allow upstream" default.
type Action int

const (
	ActionWarn  Action = iota // default
	ActionAllow                // suppress this finding
	ActionBlock                // halt the request
)

// String returns a stable lowercase name for logs and JSON.
func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionBlock:
		return "block"
	case ActionWarn:
		return "warn"
	default:
		return "unknown"
	}
}

// Rule is one entry from the YAML rules list, post-compilation and
// validation. Rules are evaluated top-down; the first matching rule wins.
type Rule struct {
	Name   string
	Match  Match
	Action Action
	Note   string
}

// Match is the compiled match conditions for a Rule.
//
// At evaluation time the engine checks: if All is true, the match is
// unconditional. Otherwise, all non-nil/zero-valued fields are AND'd —
// e.g., Pattern!=nil AND Severity!=nil means both must match.
//
// The loader rejects a Match with no conditions at all, so at least one
// of {Pattern, Severity, All} is always meaningful.
type Match struct {
	Pattern  *globPattern        // nil = no pattern condition
	Severity *detector.Severity  // nil = no severity condition
	All      bool
}

// Policy is a loaded, validated, compiled policy ready for Decide.
// Read-only after loading. Concurrency-safe.
type Policy struct {
	Version int
	Rules   []Rule
}

// Decide returns the action and matching rule for a single finding.
// Rules are tried in order; the first match wins. Returns
// (ActionWarn, nil) if no rule matches or if p is nil/empty.
//
// Decide is safe for concurrent use after construction.
func (p *Policy) Decide(f detector.Finding) (Action, *Rule) {
	if p == nil {
		return ActionWarn, nil
	}
	for i := range p.Rules {
		if matches(&p.Rules[i].Match, f) {
			return p.Rules[i].Action, &p.Rules[i]
		}
	}
	return ActionWarn, nil
}

// matches reports whether m matches f. Defined here (not in match.go)
// so the rule-iteration logic and the match logic can be unit-tested
// independently. The actual glob compile machinery lives in match.go.
func matches(m *Match, f detector.Finding) bool {
	if m.All {
		return true
	}
	if m.Pattern != nil && !m.Pattern.match(f.Pattern) {
		return false
	}
	if m.Severity != nil && *m.Severity != f.Severity {
		return false
	}
	// At least one condition must have been present (loader validates this).
	// All present conditions matched.
	return m.Pattern != nil || m.Severity != nil
}
```

- [ ] **Step 4: Stub `match.go` so the package compiles**

Create `internal/policy/match.go`:

```go
package policy

// globPattern is filled in by Task 2; this file exists only so policy.go
// compiles standalone.
type globPattern struct{}

func (g *globPattern) match(_ string) bool { return false }
```

- [ ] **Step 5: Run tests and confirm pass**

```bash
go test -race -count=1 ./internal/policy/...
```

Expected: 3 PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/policy/
git commit -m "feat(policy): add Action, Rule, Match, Policy types with empty Decide"
```

---

## Task 2: Policy package — glob compile and match

**Files:**
- Modify: `internal/policy/match.go`
- Modify: `internal/policy/policy_test.go` (append)

- [ ] **Step 1: Append failing tests for glob**

Append to `internal/policy/policy_test.go`:

```go

func TestCompileGlob_StarMatchesAnySequence(t *testing.T) {
	g, err := compileGlob("aws_*")
	if err != nil {
		t.Fatalf("compileGlob: %v", err)
	}
	cases := []struct {
		s    string
		want bool
	}{
		{"aws_access_key_id", true},
		{"aws_secret_access_key", true},
		{"aws_", true}, // * matches empty string too
		{"awsx_y", false},
		{"AWS_ACCESS_KEY_ID", false}, // case-sensitive
		{"github_token", false},
	}
	for _, c := range cases {
		if got := g.match(c.s); got != c.want {
			t.Errorf("glob(aws_*).match(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestCompileGlob_QuestionMatchesSingleChar(t *testing.T) {
	g, err := compileGlob("a?c")
	if err != nil {
		t.Fatalf("compileGlob: %v", err)
	}
	cases := []struct {
		s    string
		want bool
	}{
		{"abc", true},
		{"axc", true},
		{"ac", false},
		{"abbc", false},
	}
	for _, c := range cases {
		if got := g.match(c.s); got != c.want {
			t.Errorf("glob(a?c).match(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestCompileGlob_LiteralAnchored(t *testing.T) {
	g, err := compileGlob("jwt")
	if err != nil {
		t.Fatalf("compileGlob: %v", err)
	}
	cases := []struct {
		s    string
		want bool
	}{
		{"jwt", true},
		{"jwt_x", false},
		{"x_jwt", false},
		{"JWT", false},
	}
	for _, c := range cases {
		if got := g.match(c.s); got != c.want {
			t.Errorf("glob(jwt).match(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestCompileGlob_QuoteMetaSafety(t *testing.T) {
	// Glob characters with regex meaning must be quoted so the compiled
	// regex doesn't get hijacked.
	g, err := compileGlob("a.b+c")
	if err != nil {
		t.Fatalf("compileGlob: %v", err)
	}
	if g.match("axbxc") {
		t.Error("glob(a.b+c) should not match axbxc; the dot must be literal")
	}
	if !g.match("a.b+c") {
		t.Error("glob(a.b+c) should match the literal string a.b+c")
	}
}

func TestCompileGlob_EmptyIsInvalid(t *testing.T) {
	_, err := compileGlob("")
	if err == nil {
		t.Error("compileGlob(\"\") should return an error")
	}
}
```

- [ ] **Step 2: Run and confirm tests fail**

```bash
go test ./internal/policy/...
```

Expected: failures — current `globPattern` is a no-op stub.

- [ ] **Step 3: Replace `match.go` with real implementation**

Replace `internal/policy/match.go` contents:

```go
package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// globPattern is a compiled glob. We translate the glob syntax into a
// fully-anchored regex (^...$) so equality is a single boolean.
//
// Supported metacharacters:
//
//   *  matches any sequence of characters (including empty)
//   ?  matches exactly one character
//
// All other characters are matched literally. Regex metacharacters in
// the input are quoted via regexp.QuoteMeta so they cannot escape into
// the underlying regex.
type globPattern struct {
	raw string
	re  *regexp.Regexp
}

// compileGlob translates a glob string into an anchored regex.
// Empty input is invalid (and likely a YAML mistake).
func compileGlob(s string) (*globPattern, error) {
	if s == "" {
		return nil, fmt.Errorf("empty glob")
	}

	// Build the regex by walking the glob char-by-char so we can quote
	// regex metacharacters literally.
	var b strings.Builder
	b.WriteString("^")
	for _, r := range s {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")

	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, fmt.Errorf("compile glob %q: %w", s, err)
	}
	return &globPattern{raw: s, re: re}, nil
}

// match reports whether name matches the compiled glob. Case-sensitive.
func (g *globPattern) match(name string) bool {
	if g == nil || g.re == nil {
		return false
	}
	return g.re.MatchString(name)
}
```

- [ ] **Step 4: Run tests and confirm pass**

```bash
go test -race -count=1 ./internal/policy/...
```

Expected: all 8 tests pass (3 from Task 1 + 5 new).

- [ ] **Step 5: Commit**

```bash
git add internal/policy/match.go internal/policy/policy_test.go
git commit -m "feat(policy): glob compile + match (full-name anchored, quote-meta safe)"
```

---

## Task 3: Policy package — Decide first-match-wins semantics

**Files:**
- Modify: `internal/policy/policy_test.go` (append)

- [ ] **Step 1: Append failing tests for Decide rule iteration**

Append to `internal/policy/policy_test.go`:

```go

// mustPolicy builds a Policy with the given rules. Pre-compiled globs
// (not loader-validated) — for unit-testing Decide in isolation.
func mustPolicy(t *testing.T, rules ...Rule) *Policy {
	t.Helper()
	return &Policy{Version: 1, Rules: rules}
}

func mustGlob(t *testing.T, s string) *globPattern {
	t.Helper()
	g, err := compileGlob(s)
	if err != nil {
		t.Fatalf("compileGlob(%q): %v", s, err)
	}
	return g
}

func sevPtr(s detector.Severity) *detector.Severity { return &s }

func TestDecide_SinglePatternMatchBlocks(t *testing.T) {
	p := mustPolicy(t, Rule{
		Name:   "block-aws",
		Match:  Match{Pattern: mustGlob(t, "aws_*")},
		Action: ActionBlock,
	})
	a, r := p.Decide(detector.Finding{Pattern: "aws_access_key_id", Severity: detector.SeverityHigh})
	if a != ActionBlock {
		t.Errorf("action = %v, want ActionBlock", a)
	}
	if r == nil || r.Name != "block-aws" {
		t.Errorf("rule = %+v, want block-aws", r)
	}
}

func TestDecide_FirstMatchWins(t *testing.T) {
	// allow rule comes first, so it wins for aws_access_key_id even
	// though a later block-aws rule would also match.
	p := mustPolicy(t,
		Rule{
			Name:   "allow-fixture",
			Match:  Match{Pattern: mustGlob(t, "aws_access_key_id")},
			Action: ActionAllow,
		},
		Rule{
			Name:   "block-aws",
			Match:  Match{Pattern: mustGlob(t, "aws_*")},
			Action: ActionBlock,
		},
	)
	a, r := p.Decide(detector.Finding{Pattern: "aws_access_key_id", Severity: detector.SeverityHigh})
	if a != ActionAllow {
		t.Errorf("action = %v, want ActionAllow", a)
	}
	if r == nil || r.Name != "allow-fixture" {
		t.Errorf("rule = %+v, want allow-fixture", r)
	}
}

func TestDecide_NoRuleMatchesReturnsWarn(t *testing.T) {
	p := mustPolicy(t,
		Rule{
			Name:   "block-github",
			Match:  Match{Pattern: mustGlob(t, "github_*")},
			Action: ActionBlock,
		},
	)
	a, r := p.Decide(detector.Finding{Pattern: "aws_access_key_id", Severity: detector.SeverityHigh})
	if a != ActionWarn {
		t.Errorf("action = %v, want ActionWarn", a)
	}
	if r != nil {
		t.Errorf("rule = %+v, want nil", r)
	}
}

func TestDecide_SeverityMatch(t *testing.T) {
	p := mustPolicy(t,
		Rule{
			Name:   "warn-medium",
			Match:  Match{Severity: sevPtr(detector.SeverityMedium)},
			Action: ActionWarn,
		},
		Rule{
			Name:   "block-high",
			Match:  Match{Severity: sevPtr(detector.SeverityHigh)},
			Action: ActionBlock,
		},
	)
	a, _ := p.Decide(detector.Finding{Pattern: "x", Severity: detector.SeverityMedium})
	if a != ActionWarn {
		t.Errorf("medium → %v, want ActionWarn", a)
	}
	a, _ = p.Decide(detector.Finding{Pattern: "x", Severity: detector.SeverityHigh})
	if a != ActionBlock {
		t.Errorf("high → %v, want ActionBlock", a)
	}
	a, _ = p.Decide(detector.Finding{Pattern: "x", Severity: detector.SeverityLow})
	if a != ActionWarn {
		t.Errorf("low → %v, want ActionWarn (no rule matches)", a)
	}
}

func TestDecide_PatternAndSeverityANDed(t *testing.T) {
	// Both conditions must match.
	p := mustPolicy(t, Rule{
		Name:   "block-high-aws",
		Match:  Match{Pattern: mustGlob(t, "aws_*"), Severity: sevPtr(detector.SeverityHigh)},
		Action: ActionBlock,
	})
	// pattern matches, severity matches → BLOCK
	a, _ := p.Decide(detector.Finding{Pattern: "aws_access_key_id", Severity: detector.SeverityHigh})
	if a != ActionBlock {
		t.Errorf("aws+high → %v, want ActionBlock", a)
	}
	// pattern matches, severity doesn't → WARN (no match, default)
	a, _ = p.Decide(detector.Finding{Pattern: "aws_access_key_id", Severity: detector.SeverityLow})
	if a != ActionWarn {
		t.Errorf("aws+low → %v, want ActionWarn", a)
	}
	// pattern doesn't match → WARN
	a, _ = p.Decide(detector.Finding{Pattern: "github_pat_classic", Severity: detector.SeverityHigh})
	if a != ActionWarn {
		t.Errorf("github+high → %v, want ActionWarn", a)
	}
}

func TestDecide_AllMatchesAnything(t *testing.T) {
	p := mustPolicy(t, Rule{
		Name:   "default",
		Match:  Match{All: true},
		Action: ActionWarn,
	})
	cases := []detector.Finding{
		{Pattern: "aws_access_key_id", Severity: detector.SeverityHigh},
		{Pattern: "anything", Severity: detector.SeverityLow},
		{Pattern: "jwt", Severity: detector.SeverityMedium},
	}
	for _, f := range cases {
		a, r := p.Decide(f)
		if a != ActionWarn {
			t.Errorf("all-match on %+v → %v, want ActionWarn", f, a)
		}
		if r == nil || r.Name != "default" {
			t.Errorf("all-match on %+v → rule %v, want default", f, r)
		}
	}
}

func TestDecide_ConcurrentSafe(t *testing.T) {
	p := mustPolicy(t,
		Rule{Name: "block-aws", Match: Match{Pattern: mustGlob(t, "aws_*")}, Action: ActionBlock},
		Rule{Name: "default", Match: Match{All: true}, Action: ActionWarn},
	)
	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func(i int) {
			f := detector.Finding{Pattern: "aws_access_key_id"}
			if i%2 == 0 {
				f = detector.Finding{Pattern: "other"}
			}
			a, _ := p.Decide(f)
			_ = a
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 50; i++ {
		<-done
	}
}
```

- [ ] **Step 2: Run and confirm tests pass**

These tests should already pass — `Decide` and `matches` were fully implemented in Task 1. This task is a TDD-discipline check (write the behavior tests for code that already exists) plus race coverage.

```bash
go test -race -count=1 ./internal/policy/...
```

Expected: all 14 tests pass.

If anything fails, fix the logic in `policy.go`'s `matches` function before continuing — Task 1's empty-conditions implementation might have an edge case.

- [ ] **Step 3: Commit**

```bash
git add internal/policy/policy_test.go
git commit -m "test(policy): Decide rule iteration, AND-conditions, concurrency"
```

---

## Task 4: Policy package — YAML loader

**Files:**
- Create: `internal/policy/load.go`
- Modify: `internal/policy/policy_test.go` (append)
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Add yaml.v3 dependency**

```bash
go get gopkg.in/yaml.v3@latest
go mod tidy
```

- [ ] **Step 2: Append failing tests for the loader**

Append to `internal/policy/policy_test.go`:

```go

func TestLoadFromBytes_MinimalValidPolicy(t *testing.T) {
	yaml := []byte(`
version: 1
rules:
  - name: block-aws
    match:
      pattern: aws_*
    action: block
`)
	p, err := LoadFromBytes(yaml)
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	if p.Version != 1 {
		t.Errorf("Version = %d, want 1", p.Version)
	}
	if len(p.Rules) != 1 {
		t.Fatalf("Rules len = %d, want 1", len(p.Rules))
	}
	r := p.Rules[0]
	if r.Name != "block-aws" || r.Action != ActionBlock {
		t.Errorf("rule = %+v", r)
	}
	if r.Match.Pattern == nil || !r.Match.Pattern.match("aws_access_key_id") {
		t.Errorf("pattern not compiled / not matching: %+v", r.Match)
	}
}

func TestLoadFromBytes_AllActionsParse(t *testing.T) {
	yaml := []byte(`
version: 1
rules:
  - name: a
    match: {all: true}
    action: allow
  - name: b
    match: {all: true}
    action: block
  - name: c
    match: {all: true}
    action: warn
`)
	p, err := LoadFromBytes(yaml)
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	want := []Action{ActionAllow, ActionBlock, ActionWarn}
	for i, w := range want {
		if p.Rules[i].Action != w {
			t.Errorf("rule[%d].Action = %v, want %v", i, p.Rules[i].Action, w)
		}
	}
}

func TestLoadFromBytes_SeverityMatchParses(t *testing.T) {
	yaml := []byte(`
version: 1
rules:
  - name: warn-medium
    match: {severity: medium}
    action: warn
`)
	p, err := LoadFromBytes(yaml)
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	if p.Rules[0].Match.Severity == nil || *p.Rules[0].Match.Severity != detector.SeverityMedium {
		t.Errorf("severity not parsed: %+v", p.Rules[0].Match.Severity)
	}
}

func TestLoadFromBytes_NoteFieldIgnored(t *testing.T) {
	// Note is documentation only — parses fine, exposed as Rule.Note.
	yaml := []byte(`
version: 1
rules:
  - name: r
    match: {all: true}
    action: allow
    note: this is a comment
`)
	p, err := LoadFromBytes(yaml)
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	if p.Rules[0].Note != "this is a comment" {
		t.Errorf("Note = %q, want %q", p.Rules[0].Note, "this is a comment")
	}
}

// --- error cases ---

func TestLoadFromBytes_MissingVersion(t *testing.T) {
	yaml := []byte(`
rules:
  - name: r
    match: {all: true}
    action: warn
`)
	_, err := LoadFromBytes(yaml)
	if err == nil {
		t.Fatal("expected error for missing version")
	}
}

func TestLoadFromBytes_UnsupportedVersion(t *testing.T) {
	yaml := []byte(`
version: 2
rules:
  - name: r
    match: {all: true}
    action: warn
`)
	_, err := LoadFromBytes(yaml)
	if err == nil {
		t.Fatal("expected error for version 2")
	}
}

func TestLoadFromBytes_EmptyRules(t *testing.T) {
	yaml := []byte(`
version: 1
rules: []
`)
	_, err := LoadFromBytes(yaml)
	if err == nil {
		t.Fatal("expected error for empty rules")
	}
}

func TestLoadFromBytes_RuleWithoutName(t *testing.T) {
	yaml := []byte(`
version: 1
rules:
  - match: {all: true}
    action: warn
`)
	_, err := LoadFromBytes(yaml)
	if err == nil {
		t.Fatal("expected error for rule without name")
	}
}

func TestLoadFromBytes_DuplicateRuleName(t *testing.T) {
	yaml := []byte(`
version: 1
rules:
  - name: r
    match: {all: true}
    action: warn
  - name: r
    match: {all: true}
    action: block
`)
	_, err := LoadFromBytes(yaml)
	if err == nil {
		t.Fatal("expected error for duplicate rule name")
	}
}

func TestLoadFromBytes_EmptyMatch(t *testing.T) {
	yaml := []byte(`
version: 1
rules:
  - name: r
    match: {}
    action: warn
`)
	_, err := LoadFromBytes(yaml)
	if err == nil {
		t.Fatal("expected error for empty match")
	}
}

func TestLoadFromBytes_AllPlusOtherCondition(t *testing.T) {
	yaml := []byte(`
version: 1
rules:
  - name: r
    match: {all: true, pattern: aws_*}
    action: warn
`)
	_, err := LoadFromBytes(yaml)
	if err == nil {
		t.Fatal("expected error for all combined with another condition")
	}
}

func TestLoadFromBytes_InvalidAction(t *testing.T) {
	yaml := []byte(`
version: 1
rules:
  - name: r
    match: {all: true}
    action: bock
`)
	_, err := LoadFromBytes(yaml)
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestLoadFromBytes_InvalidSeverity(t *testing.T) {
	yaml := []byte(`
version: 1
rules:
  - name: r
    match: {severity: critical}
    action: warn
`)
	_, err := LoadFromBytes(yaml)
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
}

func TestLoadFromBytes_InvalidGlob(t *testing.T) {
	yaml := []byte(`
version: 1
rules:
  - name: r
    match: {pattern: "[unclosed"}
    action: warn
`)
	_, err := LoadFromBytes(yaml)
	if err == nil {
		t.Fatal("expected error for invalid glob (compile fails on '[unclosed')")
	}
}

func TestLoadFromBytes_UnknownField(t *testing.T) {
	// yaml.v3 KnownFields(true) should reject typos.
	yaml := []byte(`
version: 1
rulez:
  - name: r
    match: {all: true}
    action: warn
`)
	_, err := LoadFromBytes(yaml)
	if err == nil {
		t.Fatal("expected error for unknown top-level field 'rulez'")
	}
}

func TestLoadFromBytes_MalformedYAML(t *testing.T) {
	_, err := LoadFromBytes([]byte("{ not valid yaml :"))
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
}
```

- [ ] **Step 3: Run and confirm tests fail**

```bash
go test ./internal/policy/...
```

Expected: compile error — `LoadFromBytes` undefined.

- [ ] **Step 4: Implement `load.go`**

Note: there's one regex compile issue to be careful about — `regexp.Compile("[unclosed")` *succeeds in some regex engines but fails in Go's RE2*. The glob `"[unclosed"` translates to regex `^\[unclosed$` which is a valid regex (the `[` is quoted by `QuoteMeta`). To make `TestLoadFromBytes_InvalidGlob` actually exercise an invalid glob, we need to either (a) define a glob syntax error (e.g., reject square brackets entirely) or (b) use a different test case that produces an invalid regex. The cleanest approach: detect literally empty globs in `compileGlob` (Task 2 already does this) and have the invalid-glob test use an empty string. Update the test below.

REPLACE the `TestLoadFromBytes_InvalidGlob` test you just appended with this corrected version:

```go
func TestLoadFromBytes_InvalidGlob(t *testing.T) {
	// Empty glob is invalid per compileGlob (Task 2).
	yaml := []byte(`
version: 1
rules:
  - name: r
    match: {pattern: ""}
    action: warn
`)
	_, err := LoadFromBytes(yaml)
	if err == nil {
		t.Fatal("expected error for empty glob")
	}
}
```

Now create `internal/policy/load.go`:

```go
package policy

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"railcore/internal/detector"
)

// yamlRoot is the on-wire schema of a policy file. Field names lowercase
// per yaml.v3's default mapping. KnownFields(true) rejects typos.
type yamlRoot struct {
	Version int        `yaml:"version"`
	Rules   []yamlRule `yaml:"rules"`
}

type yamlRule struct {
	Name   string    `yaml:"name"`
	Match  yamlMatch `yaml:"match"`
	Action string    `yaml:"action"`
	Note   string    `yaml:"note,omitempty"`
}

type yamlMatch struct {
	Pattern  string `yaml:"pattern,omitempty"`
	Severity string `yaml:"severity,omitempty"`
	All      bool   `yaml:"all,omitempty"`
}

// LoadFromFile reads, parses, validates, and compiles a policy YAML file.
func LoadFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	return LoadFromBytes(data)
}

// LoadFromBytes parses raw YAML bytes. Same validation as LoadFromFile.
//
// All structural errors are returned with descriptive messages so the
// operator can fix the YAML without reading railcore source.
func LoadFromBytes(data []byte) (*Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var root yamlRoot
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("policy parse: %w", err)
	}

	if root.Version == 0 {
		return nil, fmt.Errorf("policy: version is required (must be 1)")
	}
	if root.Version != 1 {
		return nil, fmt.Errorf("policy: unsupported version %d, this railcore build supports version 1", root.Version)
	}
	if len(root.Rules) == 0 {
		return nil, fmt.Errorf("policy: rules is required and must contain at least one rule")
	}

	policy := &Policy{Version: root.Version, Rules: make([]Rule, 0, len(root.Rules))}
	seen := make(map[string]bool, len(root.Rules))

	for i, yr := range root.Rules {
		if yr.Name == "" {
			return nil, fmt.Errorf("policy: rule #%d: name is required", i+1)
		}
		if seen[yr.Name] {
			return nil, fmt.Errorf("policy: duplicate rule name %q", yr.Name)
		}
		seen[yr.Name] = true

		rule, err := compileRule(yr)
		if err != nil {
			return nil, fmt.Errorf("policy: rule %q: %w", yr.Name, err)
		}
		policy.Rules = append(policy.Rules, rule)
	}

	return policy, nil
}

func compileRule(yr yamlRule) (Rule, error) {
	// Action.
	action, err := parseAction(yr.Action)
	if err != nil {
		return Rule{}, err
	}

	// Match.
	m, err := compileMatch(yr.Match)
	if err != nil {
		return Rule{}, err
	}

	return Rule{
		Name:   yr.Name,
		Match:  m,
		Action: action,
		Note:   yr.Note,
	}, nil
}

func parseAction(s string) (Action, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "allow":
		return ActionAllow, nil
	case "block":
		return ActionBlock, nil
	case "warn":
		return ActionWarn, nil
	case "":
		return 0, fmt.Errorf("action is required")
	default:
		return 0, fmt.Errorf("invalid action %q, must be one of: allow, block, warn", s)
	}
}

func compileMatch(ym yamlMatch) (Match, error) {
	hasPattern := ym.Pattern != ""
	hasSeverity := ym.Severity != ""
	hasAll := ym.All

	if !hasPattern && !hasSeverity && !hasAll {
		return Match{}, fmt.Errorf("match is required and must contain at least one condition")
	}
	if hasAll && (hasPattern || hasSeverity) {
		return Match{}, fmt.Errorf("match.all cannot be combined with other conditions")
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

	return m, nil
}

func parseSeverity(s string) (detector.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return detector.SeverityHigh, nil
	case "medium":
		return detector.SeverityMedium, nil
	case "low":
		return detector.SeverityLow, nil
	default:
		return 0, fmt.Errorf("invalid severity %q, must be one of: high, medium, low", s)
	}
}
```

- [ ] **Step 5: Run tests and confirm pass**

```bash
go test -race -count=1 ./internal/policy/...
```

Expected: all policy tests pass (Task 1: 3, Task 2: 5, Task 3: 7, Task 4: ~16 — total ~31).

- [ ] **Step 6: Commit**

```bash
git add internal/policy/load.go internal/policy/policy_test.go go.mod go.sum
git commit -m "feat(policy): YAML loader with strict validation"
```

---

## Task 5: `LoadFromFile` integration test

**Files:**
- Modify: `internal/policy/policy_test.go` (append)

- [ ] **Step 1: Append a test that round-trips through a temp file**

Append to `internal/policy/policy_test.go`:

```go

func TestLoadFromFile_RoundTripsViaDisk(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/policy.yaml"
	content := []byte(`
version: 1
rules:
  - name: block-aws
    match: {pattern: aws_*}
    action: block
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write temp policy: %v", err)
	}
	p, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if len(p.Rules) != 1 || p.Rules[0].Name != "block-aws" {
		t.Errorf("loaded policy mismatch: %+v", p.Rules)
	}
}

func TestLoadFromFile_NonExistentFails(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/does-not-exist.yaml")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}
```

Add `"os"` to the test file's imports if not already present.

- [ ] **Step 2: Run and confirm pass**

```bash
go test -race -count=1 ./internal/policy/...
```

Expected: all tests pass including the two new ones.

- [ ] **Step 3: Commit**

```bash
git add internal/policy/policy_test.go
git commit -m "test(policy): LoadFromFile round-trip and non-existent path"
```

---

## Task 6: Secretscan — add `Policy` field and `Rule` enrichment

**Files:**
- Modify: `internal/stage/secretscan/stage.go`
- Modify: `internal/stage/secretscan/stage_test.go` (append)

This task adds the `Config.Policy` field and the new `Rule` field on `EnrichedFinding`, but does NOT yet wire the decision logic. That comes in Task 7.

- [ ] **Step 1: Append failing test**

Append to `internal/stage/secretscan/stage_test.go`:

```go

func TestEnrichedFinding_MarshalJSON_RuleIncludedWhenSet(t *testing.T) {
	ef := EnrichedFinding{
		Finding:      detector.Finding{Pattern: "aws_access_key_id", Severity: detector.SeverityHigh},
		Role:         "user",
		MessageIndex: 0,
		Rule:         "block-aws",
	}
	data, err := json.Marshal(ef)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), `"rule":"block-aws"`) {
		t.Errorf("expected rule field in output; got %s", string(data))
	}
}

func TestEnrichedFinding_MarshalJSON_RuleOmittedWhenEmpty(t *testing.T) {
	ef := EnrichedFinding{
		Finding:      detector.Finding{Pattern: "aws_access_key_id", Severity: detector.SeverityHigh},
		Role:         "user",
		MessageIndex: 0,
		// Rule is empty
	}
	data, err := json.Marshal(ef)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(data), `"rule"`) {
		t.Errorf("rule field should be omitted when empty; got %s", string(data))
	}
}
```

Add to the test file's imports if not present:
```go
"encoding/json"
"strings"

"railcore/internal/detector"
```

- [ ] **Step 2: Confirm tests fail to compile**

```bash
go test ./internal/stage/secretscan/...
```

Expected: compile error — `EnrichedFinding.Rule` undefined.

- [ ] **Step 3: Modify `stage.go`**

In `internal/stage/secretscan/stage.go`:

**(a)** Add `"railcore/internal/policy"` to the imports.

**(b)** Update `Config`:

```go
type Config struct {
	BlockOnDetect bool           // used when Policy is nil
	Policy        *policy.Policy // when non-nil, drives all decisions
}
```

**(c)** Update `EnrichedFinding`:

```go
type EnrichedFinding struct {
	Finding      detector.Finding
	Role         string
	MessageIndex int
	Rule         string // name of the rule that decided this finding; "" if no policy in use
}
```

**(d)** Update `MarshalJSON` to emit `rule` only when non-empty:

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

- [ ] **Step 4: Run tests and confirm pass**

```bash
go test -race -count=1 ./internal/stage/secretscan/...
```

Expected: existing 7 secretscan tests plus the 2 new ones — 9 PASS. The existing tests still work because `Policy` is nil by default and `Rule` defaults to "".

- [ ] **Step 5: Commit**

```bash
git add internal/stage/secretscan/stage.go internal/stage/secretscan/stage_test.go
git commit -m "feat(secretscan): add Config.Policy field and EnrichedFinding.Rule"
```

---

## Task 7: Secretscan — `processWithPolicy` code path

**Files:**
- Modify: `internal/stage/secretscan/stage.go`
- Modify: `internal/stage/secretscan/stage_test.go` (append)

- [ ] **Step 1: Append failing tests**

Append to `internal/stage/secretscan/stage_test.go`:

```go

// helper: build a minimal Policy from inline rules without the YAML round-trip.
func mkPolicy(t *testing.T, yamlText string) *policy.Policy {
	t.Helper()
	p, err := policy.LoadFromBytes([]byte(yamlText))
	if err != nil {
		t.Fatalf("policy.LoadFromBytes: %v", err)
	}
	return p
}

func TestSecretscan_PolicyBlockOnAWS(t *testing.T) {
	pol := mkPolicy(t, `
version: 1
rules:
  - name: block-aws
    match: {pattern: aws_*}
    action: block
  - name: default
    match: {all: true}
    action: warn
`)
	s := New(Config{Policy: pol}, discardLogger())
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"key: AKIAIOSFODNN7EXAMPLE"}]}`
	rc := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Block {
		t.Fatalf("decision = %v, want Block", dec)
	}
	findings, ok := rc.Metadata["secretscan.findings"].([]EnrichedFinding)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected findings in metadata, got %v", rc.Metadata["secretscan.findings"])
	}
	if findings[0].Rule != "block-aws" {
		t.Errorf("Rule = %q, want block-aws", findings[0].Rule)
	}
}

func TestSecretscan_PolicyAllowSuppressesBlock(t *testing.T) {
	// Allow rule precedes block rule — wins for aws_access_key_id.
	pol := mkPolicy(t, `
version: 1
rules:
  - name: allow-example
    match: {pattern: aws_access_key_id}
    action: allow
  - name: block-aws
    match: {pattern: aws_*}
    action: block
`)
	// BlockOnDetect=true is set, but policy takes precedence.
	s := New(Config{BlockOnDetect: true, Policy: pol}, discardLogger())
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"key: AKIAIOSFODNN7EXAMPLE"}]}`
	rc := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Fatalf("decision = %v, want Continue (allow precedes block)", dec)
	}
	// The allowed finding should NOT appear in metadata.
	findings, _ := rc.Metadata["secretscan.findings"].([]EnrichedFinding)
	for _, f := range findings {
		if f.Finding.Pattern == "aws_access_key_id" {
			t.Errorf("allowed finding leaked into metadata: %+v", f)
		}
	}
}

func TestSecretscan_PolicyWarnDoesNotBlock(t *testing.T) {
	pol := mkPolicy(t, `
version: 1
rules:
  - name: warn-all
    match: {all: true}
    action: warn
`)
	s := New(Config{Policy: pol}, discardLogger())
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"key: AKIAIOSFODNN7EXAMPLE"}]}`
	rc := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Fatalf("decision = %v, want Continue (warn never blocks)", dec)
	}
	findings, ok := rc.Metadata["secretscan.findings"].([]EnrichedFinding)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected findings, got %v", rc.Metadata["secretscan.findings"])
	}
	if findings[0].Rule != "warn-all" {
		t.Errorf("Rule = %q, want warn-all", findings[0].Rule)
	}
}

func TestSecretscan_PolicyMixedActions(t *testing.T) {
	// Two findings: AWS key (allowed), GitHub PAT (blocked). Expect Block.
	pol := mkPolicy(t, `
version: 1
rules:
  - name: allow-aws
    match: {pattern: aws_*}
    action: allow
  - name: block-github
    match: {pattern: github_*}
    action: block
`)
	s := New(Config{Policy: pol}, discardLogger())
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"AKIAIOSFODNN7EXAMPLE and ghp_abcdefghijklmnopqrstuvwxyz0123456789"}]}`
	rc := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Block {
		t.Fatalf("decision = %v, want Block (github blocks even though aws allowed)", dec)
	}
	findings, _ := rc.Metadata["secretscan.findings"].([]EnrichedFinding)
	// AWS finding allowed → must NOT be in metadata. GitHub finding must be present.
	sawGithub, sawAWS := false, false
	for _, f := range findings {
		if f.Finding.Pattern == "github_pat_classic" {
			sawGithub = true
			if f.Rule != "block-github" {
				t.Errorf("github rule = %q, want block-github", f.Rule)
			}
		}
		if f.Finding.Pattern == "aws_access_key_id" {
			sawAWS = true
		}
	}
	if !sawGithub {
		t.Error("expected github finding in metadata")
	}
	if sawAWS {
		t.Error("allowed aws finding should be absent from metadata")
	}
}

func TestSecretscan_EmptyPolicyDefaultsToWarn(t *testing.T) {
	// Constructed in Go (loader doesn't allow empty rules, but Decide tolerates it).
	pol := &policy.Policy{Version: 1}
	s := New(Config{Policy: pol}, discardLogger())
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"key: AKIAIOSFODNN7EXAMPLE"}]}`
	rc := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Fatalf("decision = %v, want Continue (empty rules → warn default)", dec)
	}
}
```

Add to imports if missing:

```go
"railcore/internal/policy"
```

- [ ] **Step 2: Confirm tests fail**

```bash
go test ./internal/stage/secretscan/...
```

Expected: tests compile but the new policy ones fail because `Process` doesn't yet branch on `cfg.Policy`.

- [ ] **Step 3: Modify `stage.go` to add `processWithPolicy`**

Open `internal/stage/secretscan/stage.go`. The current `Process` method does:

```go
func (s *Stage) Process(ctx context.Context, rc *pipeline.RequestCtx) (pipeline.Decision, error) {
	body, ok := rc.Metadata["body"].([]byte)
	if !ok {
		return pipeline.Continue, nil
	}

	parsed, err := parser.ParseRequest(rc.Host, rc.Req, body)
	if err != nil {
		s.log.Debug("secretscan parser error", "host", rc.Host, "err", err.Error())
		return pipeline.Continue, nil
	}
	if parsed == nil {
		return pipeline.Continue, nil
	}

	var enriched []EnrichedFinding
	var highCount, medCount, lowCount int
	var highPatterns []string

	for _, seg := range parsed.Texts {
		if !utf8.ValidString(seg.Content) {
			continue
		}
		for _, f := range detector.Scan(seg.Content) {
			enriched = append(enriched, EnrichedFinding{
				Finding:      f,
				Role:         seg.Role,
				MessageIndex: seg.Index,
			})
			switch f.Severity {
			case detector.SeverityHigh:
				highCount++
				highPatterns = append(highPatterns, f.Pattern)
			case detector.SeverityMedium:
				medCount++
			case detector.SeverityLow:
				lowCount++
			}
		}
	}

	if len(enriched) == 0 {
		return pipeline.Continue, nil
	}

	rc.Metadata["secretscan.findings"] = enriched
	requestID, _ := rc.Metadata["request_id"].(string)

	if highCount > 0 && s.cfg.BlockOnDetect {
		s.log.Warn("secretscan blocked", ...)
		return pipeline.Block, nil
	}

	s.log.Info("secretscan findings", ...)
	return pipeline.Continue, nil
}
```

Refactor it so the body-read + parse + per-segment scan is shared, but the decision logic branches based on whether `cfg.Policy` is set. Replace the entire `Process` body with this:

```go
func (s *Stage) Process(ctx context.Context, rc *pipeline.RequestCtx) (pipeline.Decision, error) {
	body, ok := rc.Metadata["body"].([]byte)
	if !ok {
		return pipeline.Continue, nil
	}

	parsed, err := parser.ParseRequest(rc.Host, rc.Req, body)
	if err != nil {
		s.log.Debug("secretscan parser error", "host", rc.Host, "err", err.Error())
		return pipeline.Continue, nil
	}
	if parsed == nil {
		return pipeline.Continue, nil
	}

	// Collect raw findings (one per detector.Scan hit per text segment).
	var raw []EnrichedFinding
	for _, seg := range parsed.Texts {
		if !utf8.ValidString(seg.Content) {
			continue
		}
		for _, f := range detector.Scan(seg.Content) {
			raw = append(raw, EnrichedFinding{
				Finding:      f,
				Role:         seg.Role,
				MessageIndex: seg.Index,
			})
		}
	}

	if len(raw) == 0 {
		return pipeline.Continue, nil
	}

	if s.cfg.Policy != nil {
		return s.decideWithPolicy(rc, parsed, raw)
	}
	return s.decideWithFlag(rc, parsed, raw)
}

// decideWithFlag implements the sub-project #2 semantics: WARN by default,
// BLOCK on any High finding when cfg.BlockOnDetect is true.
func (s *Stage) decideWithFlag(rc *pipeline.RequestCtx, parsed *parser.ParsedRequest, raw []EnrichedFinding) (pipeline.Decision, error) {
	var highCount, medCount, lowCount int
	var highPatterns []string
	for _, f := range raw {
		switch f.Finding.Severity {
		case detector.SeverityHigh:
			highCount++
			highPatterns = append(highPatterns, f.Finding.Pattern)
		case detector.SeverityMedium:
			medCount++
		case detector.SeverityLow:
			lowCount++
		}
	}

	rc.Metadata["secretscan.findings"] = raw
	requestID, _ := rc.Metadata["request_id"].(string)

	if highCount > 0 && s.cfg.BlockOnDetect {
		s.log.Warn("secretscan blocked",
			"request_id", requestID,
			"vendor", parsed.Vendor,
			"endpoint", parsed.Endpoint,
			"high", highCount,
			"medium", medCount,
			"low", lowCount,
			"patterns", highPatterns)
		return pipeline.Block, nil
	}

	s.log.Info("secretscan findings",
		"request_id", requestID,
		"vendor", parsed.Vendor,
		"endpoint", parsed.Endpoint,
		"high", highCount,
		"medium", medCount,
		"low", lowCount)
	return pipeline.Continue, nil
}

// decideWithPolicy applies the configured Policy rule-by-rule, suppresses
// allowed findings, blocks if any rule's action is Block, otherwise warns.
func (s *Stage) decideWithPolicy(rc *pipeline.RequestCtx, parsed *parser.ParsedRequest, raw []EnrichedFinding) (pipeline.Decision, error) {
	requestID, _ := rc.Metadata["request_id"].(string)

	var kept []EnrichedFinding
	var blockRules []string
	var ruleNames []string
	var blockPatterns []string
	var highCount, medCount, lowCount int
	anyBlock := false

	for _, f := range raw {
		action, rule := s.cfg.Policy.Decide(f.Finding)
		ruleName := ""
		if rule != nil {
			ruleName = rule.Name
		}

		switch action {
		case policy.ActionAllow:
			s.log.Debug("policy allowed",
				"request_id", requestID,
				"pattern", f.Finding.Pattern,
				"rule", ruleName)
			// Suppressed: do not keep, do not count.
		case policy.ActionBlock:
			f.Rule = ruleName
			kept = append(kept, f)
			anyBlock = true
			blockRules = append(blockRules, ruleName)
			blockPatterns = append(blockPatterns, f.Finding.Pattern)
			bumpCount(&highCount, &medCount, &lowCount, f.Finding.Severity)
		case policy.ActionWarn:
			fallthrough
		default:
			f.Rule = ruleName
			kept = append(kept, f)
			if ruleName != "" {
				ruleNames = append(ruleNames, ruleName)
			}
			bumpCount(&highCount, &medCount, &lowCount, f.Finding.Severity)
		}
	}

	if len(kept) == 0 {
		// Everything was allowed away. Quiet.
		return pipeline.Continue, nil
	}

	rc.Metadata["secretscan.findings"] = kept

	if anyBlock {
		s.log.Warn("secretscan blocked",
			"request_id", requestID,
			"vendor", parsed.Vendor,
			"endpoint", parsed.Endpoint,
			"high", highCount,
			"medium", medCount,
			"low", lowCount,
			"block_rules", blockRules,
			"patterns", blockPatterns)
		return pipeline.Block, nil
	}

	s.log.Info("secretscan findings",
		"request_id", requestID,
		"vendor", parsed.Vendor,
		"endpoint", parsed.Endpoint,
		"high", highCount,
		"medium", medCount,
		"low", lowCount,
		"rules_fired", ruleNames)
	return pipeline.Continue, nil
}

func bumpCount(high, med, low *int, sev detector.Severity) {
	switch sev {
	case detector.SeverityHigh:
		*high++
	case detector.SeverityMedium:
		*med++
	case detector.SeverityLow:
		*low++
	}
}
```

- [ ] **Step 4: Run tests and confirm all pass**

```bash
go test -race -count=1 ./internal/stage/secretscan/...
```

Expected: 14 PASS (9 from before + 5 new).

- [ ] **Step 5: Commit**

```bash
git add internal/stage/secretscan/stage.go internal/stage/secretscan/stage_test.go
git commit -m "feat(secretscan): policy-driven decisions via Config.Policy"
```

---

## Task 8: Proxy 403 body includes rule (integration test)

**Files:**
- Modify: `internal/proxy/server_test.go` (append)

The 403 body already uses `EnrichedFinding.MarshalJSON` (sub-project #2's `writeBlockResp`). Since `Rule` is now serialized when non-empty, no proxy code changes are needed. Just an integration test to lock the behavior in.

- [ ] **Step 1: Append the test**

Append to `internal/proxy/server_test.go`:

```go

// policyBlockStage simulates secretscan: registers a finding WITH a rule
// name set, returns Block. Verifies the proxy's 403 body serializes the
// rule field correctly.
type policyBlockStage struct{}

func (policyBlockStage) Name() string { return "test-policy-block" }
func (policyBlockStage) Process(_ context.Context, rc *pipeline.RequestCtx) (pipeline.Decision, error) {
	rc.Metadata["secretscan.findings"] = []map[string]any{
		{
			"pattern":       "aws_access_key_id",
			"severity":      "high",
			"role":          "user",
			"message_index": 0,
			"rule":          "block-aws",
		},
	}
	return pipeline.Block, nil
}

func TestProxy_BlockBodyIncludesRule(t *testing.T) {
	srv, addr := newTestServer(t)
	srv.cfg.Pipeline.Register(policyBlockStage{})

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
		Findings []map[string]interface{} `json:"findings"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("body not JSON: %v, body=%s", err, string(body))
	}
	if len(parsed.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(parsed.Findings))
	}
	if parsed.Findings[0]["rule"] != "block-aws" {
		t.Errorf("rule = %v, want block-aws; body=%s", parsed.Findings[0]["rule"], string(body))
	}
}
```

- [ ] **Step 2: Run and confirm pass**

```bash
go test -race -count=1 ./internal/proxy/...
```

Expected: all proxy tests pass including the new one.

- [ ] **Step 3: Commit**

```bash
git add internal/proxy/server_test.go
git commit -m "test(proxy): 403 body surfaces rule name when policy decides Block"
```

---

## Task 9: Wire `--policy` flag into `cmd/railcore/main.go`

**Files:**
- Modify: `cmd/railcore/main.go`

- [ ] **Step 1: Replace `cmd/railcore/main.go`**

Replace the file's contents:

```go
// Package main is the Railcore proxy entrypoint.
//
// Sub-project #1: forward HTTPS proxy with TLS interception.
// Sub-project #2: secret detection with --block-on-detect flag.
// Sub-project #3: YAML policy file (--policy or ~/.railcore/policy.yaml).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"railcore/internal/ca"
	"railcore/internal/pipeline"
	"railcore/internal/policy"
	"railcore/internal/proxy"
	"railcore/internal/stage/secretscan"
	"railcore/internal/trust"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "proxy" {
		fmt.Fprintln(os.Stderr, "usage: railcore proxy [--port N] [--data-dir PATH] [--block-on-detect] [--policy PATH]")
		os.Exit(2)
	}

	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	port := fs.Int("port", defaultPort(), "TCP port to listen on (overrides RAILCORE_PORT)")
	dataDir := fs.String("data-dir", defaultDataDir(), "directory for CA + state")
	blockOnDetect := fs.Bool("block-on-detect", false, "return 403 on High-severity secret findings (default WARN only). Ignored when a policy file is in effect.")
	policyPath := fs.String("policy", "", "path to a YAML policy file (default: <data-dir>/policy.yaml if it exists)")
	_ = fs.Parse(os.Args[2:])

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	caInst, err := ca.GenerateOrLoad(filepath.Join(*dataDir, "ca"))
	if err != nil {
		logger.Error("ca init failed", "err", err.Error())
		os.Exit(1)
	}

	if err := trust.New().Install(caInst.RootPath()); err != nil {
		logger.Warn("trust-store auto-install did not complete",
			"err", err.Error(),
			"manual_steps", trust.ManualInstructions(caInst.RootPath()))
	}

	// Resolve the policy: --policy wins, else default path if exists, else nil.
	loadedPolicy, policyMode, resolvedPath := resolvePolicy(*policyPath, *dataDir, logger)

	// Effective BlockOnDetect: ignored when a policy is in effect.
	effectiveBlock := *blockOnDetect || os.Getenv("RAILCORE_BLOCK_ON_DETECT") == "1"
	if loadedPolicy != nil && effectiveBlock {
		logger.Warn("--block-on-detect ignored because a policy file is in effect",
			"policy_path", resolvedPath)
	}

	chain := pipeline.NewChain().WithLogger(logger)
	chain.Register(secretscan.New(secretscan.Config{
		BlockOnDetect: effectiveBlock,
		Policy:        loadedPolicy,
	}, logger))

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	srv := proxy.New(proxy.Config{
		Addr:     addr,
		CA:       caInst,
		Pipeline: chain,
		Logger:   logger,
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("listen failed", "addr", addr, "err", err.Error())
		fmt.Fprintf(os.Stderr, "port %d in use; set RAILCORE_PORT or stop other process\n", *port)
		os.Exit(1)
	}

	startupArgs := []any{
		"addr", addr,
		"ca_path", caInst.RootPath(),
		"policy_mode", policyMode,
		"block_on_detect", effectiveBlock,
	}
	if resolvedPath != "" {
		startupArgs = append(startupArgs, "policy_path", resolvedPath, "rules", len(loadedPolicy.Rules))
	}
	logger.Info("railcore proxy listening", startupArgs...)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	if err := srv.Serve(ctx, ln); err != nil {
		logger.Error("serve failed", "err", err.Error())
		os.Exit(1)
	}
}

// resolvePolicy returns (policy, mode, resolvedPath). mode is "flag" when
// no policy file is in use (legacy --block-on-detect behavior applies),
// or "file" when a YAML policy was loaded.
//
// Exits the process on any load error (explicit --policy path missing or
// any YAML parse/validation failure).
func resolvePolicy(flagPath, dataDir string, logger *slog.Logger) (*policy.Policy, string, string) {
	if flagPath != "" {
		p, err := policy.LoadFromFile(flagPath)
		if err != nil {
			logger.Error("policy load failed (--policy)", "path", flagPath, "err", err.Error())
			os.Exit(1)
		}
		return p, "file", flagPath
	}

	defaultPath := filepath.Join(dataDir, "policy.yaml")
	if _, err := os.Stat(defaultPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "flag", ""
		}
		logger.Error("policy stat failed", "path", defaultPath, "err", err.Error())
		os.Exit(1)
	}

	p, err := policy.LoadFromFile(defaultPath)
	if err != nil {
		logger.Error("policy load failed (default path)", "path", defaultPath, "err", err.Error())
		os.Exit(1)
	}
	return p, "file", defaultPath
}

func defaultPort() int {
	if v := os.Getenv("RAILCORE_PORT"); v != "" {
		var p int
		if _, err := fmt.Sscanf(v, "%d", &p); err == nil && p > 0 {
			return p
		}
	}
	return 9443
}

func defaultDataDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".railcore")
	}
	return ".railcore-data"
}
```

- [ ] **Step 2: Build and smoke-test**

```bash
make build
```

Smoke test with no policy (legacy behavior):

```bash
mkdir -p /tmp/railcore-sp3-1
./railcore proxy --port 19443 --data-dir /tmp/railcore-sp3-1 2>&1 | head -5 &
SP=$!
sleep 1
kill $SP 2>/dev/null
wait 2>/dev/null
rm -rf /tmp/railcore-sp3-1
```

Expected: startup log contains `policy_mode=flag`.

Smoke test with a policy:

```bash
mkdir -p /tmp/railcore-sp3-2
cat > /tmp/railcore-sp3-2/policy.yaml <<'EOF'
version: 1
rules:
  - name: default
    match: {all: true}
    action: warn
EOF
./railcore proxy --port 19444 --data-dir /tmp/railcore-sp3-2 2>&1 | head -5 &
SP=$!
sleep 1
kill $SP 2>/dev/null
wait 2>/dev/null
rm -rf /tmp/railcore-sp3-2
```

Expected: startup log contains `policy_mode=file policy_path=/tmp/railcore-sp3-2/policy.yaml rules=1`.

- [ ] **Step 3: Run full test suite to confirm nothing regressed**

```bash
go test -race -count=1 ./...
go vet ./...
```

Expected: all tests pass, vet clean.

- [ ] **Step 4: Commit**

```bash
git add cmd/railcore/main.go
git commit -m "feat(cmd): wire --policy flag with default ~/.railcore/policy.yaml lookup"
```

---

## Task 10: End-to-end integration tests

**Files:**
- Create: `test/integration/policy_test.go`

- [ ] **Step 1: Create the integration test file**

Create `test/integration/policy_test.go`:

```go
// End-to-end tests for sub-project #3: real http.Client through a real
// proxy that has a real Policy loaded from inline YAML, against a fake
// httptest upstream.
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
	"railcore/internal/stage/secretscan"
)

func setupPolicy(t *testing.T, policyYAML string) (client *http.Client, upstreamHits *int32, cleanup func()) {
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
	chain.Register(secretscan.New(secretscan.Config{Policy: pol}, nil))

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
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "api.openai.com"},
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

func TestPolicy_E2E_YAMLBlocksAWS(t *testing.T) {
	yaml := `
version: 1
rules:
  - name: block-aws
    match: {pattern: aws_*}
    action: block
  - name: default
    match: {all: true}
    action: warn
`
	client, upstreamHits, cleanup := setupPolicy(t, yaml)
	defer cleanup()

	body := `{
		"model": "gpt-4o",
		"messages": [
			{"role": "user", "content": "key: AKIAIOSFODNN7EXAMPLE here"}
		]
	}`
	resp, err := client.Post("https://api.openai.com/v1/chat/completions", "application/json", strings.NewReader(body))
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
	if parsed.Findings[0]["rule"] != "block-aws" {
		t.Errorf("rule = %v, want block-aws", parsed.Findings[0]["rule"])
	}
	if strings.Contains(string(respBody), "AKIA") {
		t.Errorf("response body contains matched secret bytes: %s", string(respBody))
	}
}

func TestPolicy_E2E_YAMLAllowlistOverridesBlock(t *testing.T) {
	yaml := `
version: 1
rules:
  - name: allow-fixture
    match: {pattern: aws_access_key_id}
    action: allow
  - name: block-aws
    match: {pattern: aws_*}
    action: block
`
	client, upstreamHits, cleanup := setupPolicy(t, yaml)
	defer cleanup()

	body := `{
		"model": "gpt-4o",
		"messages": [
			{"role": "user", "content": "key: AKIAIOSFODNN7EXAMPLE"}
		]
	}`
	resp, err := client.Post("https://api.openai.com/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (allow rule precedes block)", resp.StatusCode)
	}
	if got := atomic.LoadInt32(upstreamHits); got != 1 {
		t.Fatalf("upstream hits = %d, want 1", got)
	}
}

func TestPolicy_E2E_BadYAMLFailsLoader(t *testing.T) {
	_, err := policy.LoadFromBytes([]byte(`
version: 1
rules:
  - name: r
    match: {pattern: ""}
    action: warn
`))
	if err == nil {
		t.Fatal("expected error from policy.LoadFromBytes on invalid glob")
	}
	if !strings.Contains(err.Error(), "rule") {
		t.Errorf("error message should mention which rule failed; got %q", err.Error())
	}
}
```

- [ ] **Step 2: Run integration tests**

```bash
go test -race -count=1 ./test/integration/...
```

Expected: all integration tests pass (existing ones plus the 3 new policy ones).

- [ ] **Step 3: Run full suite for confidence**

```bash
go test -race -count=1 ./...
go vet ./...
```

Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add test/integration/policy_test.go
git commit -m "test(integration): end-to-end YAML-driven block + allowlist scenarios"
```

---

## Task 11: Manual acceptance test (real Claude Code)

**Files:** none modified during the test itself; result recorded in spec at end.

- [ ] **Step 1: Build the binary**

```bash
make build
```

- [ ] **Step 2: Write a test policy**

```bash
cat > ~/.railcore/policy.yaml <<'EOF'
version: 1
rules:
  - name: allow-aws-temporarily
    match: {pattern: aws_*}
    action: allow
  - name: block-github
    match: {pattern: github_*}
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

Verify startup log contains `policy_mode=file policy_path=...policy.yaml rules=3`.

- [ ] **Step 4: Launch Claude Code through the proxy**

In a new terminal:

```bash
HTTPS_PROXY=http://127.0.0.1:9443 \
NODE_EXTRA_CA_CERTS=$HOME/.railcore/ca/ca.crt \
  claude
```

- [ ] **Step 5: Test the allow rule (AWS should pass)**

In Claude Code, send:

```
review:
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

Expected:
- Claude Code completes the request normally (200).
- Proxy log contains `DEBUG policy allowed pattern=aws_access_key_id rule=allow-aws-temporarily`.

- [ ] **Step 6: Test the block rule (GitHub PAT should 403)**

In Claude Code, send:

```
review this token:
ghp_abcdefghijklmnopqrstuvwxyz0123456789
```

Expected:
- Claude Code receives a 403 (visible as a request error).
- Proxy log contains `WARN secretscan blocked block_rules=[block-github]`.

- [ ] **Step 7: Record the result**

Append §11 Acceptance Result to the spec doc at `docs/superpowers/specs/2026-05-17-policy-engine-design.md`:

```markdown

---

## 11. Acceptance Result

**Date:** YYYY-MM-DD (fill in)
**Tool exercised:** Claude Code via HTTPS_PROXY + NODE_EXTRA_CA_CERTS.

**Allow rule:** Pass.
- Synthetic AWS key in prompt → 200 returned.
- Proxy log: `DEBUG policy allowed pattern=aws_access_key_id rule=allow-aws-temporarily`.

**Block rule:** Pass.
- GitHub PAT in prompt → 403 returned with `findings[0].rule = "block-github"`.
- Proxy log: `WARN secretscan blocked block_rules=[block-github]`.

**Status:** Pass. Sub-project #3 done definition §10 satisfied.
```

- [ ] **Step 8: Commit the acceptance record**

```bash
git add docs/superpowers/specs/2026-05-17-policy-engine-design.md
git commit -m "docs(spec): record sub-project #3 acceptance result"
```

---

## Self-Review Notes

After completing all tasks:

1. **Spec coverage matrix:**
   - §3 repo layout → Task 1 (policy package start), Task 7 (secretscan changes), Task 9 (main.go).
   - §4 YAML schema → Task 4.
   - §5.1 types + Decide → Tasks 1, 3.
   - §5.2 LoadFromBytes/LoadFromFile → Tasks 4, 5.
   - §5.3 globPattern → Task 2.
   - §5.4 Config.Policy + processWithPolicy → Tasks 6, 7.
   - §5.5 EnrichedFinding.Rule → Task 6.
   - §6 evaluation semantics → Task 3 (Decide), Task 7 (stage-level aggregation).
   - §7 CLI flag + resolution → Task 9.
   - §8.1 startup error catalogue → Task 4 (LoadFromBytes validation tests cover each row).
   - §8.2 per-request fail-open → Tasks 1, 7.
   - §8.3 logging shape → Task 7.
   - §9.1–9.4 tests → Tasks 1–8, 10.
   - §9.5 acceptance → Task 11.
   - §10 done definition → Tasks 9 (build+test), 10 (integration), 11 (acceptance).

2. **Placeholders:** none. Each step has complete code or exact commands.

3. **Type consistency:**
   - `Action` constants: `ActionWarn=0`, `ActionAllow=1`, `ActionBlock=2` — referenced consistently across `policy`, `secretscan`, tests.
   - `Severity` reused from `internal/detector` (`SeverityLow=0`, `SeverityMedium=1`, `SeverityHigh=2`).
   - `Match` fields: `Pattern *globPattern`, `Severity *detector.Severity`, `All bool` — consistent across `policy.go`, `load.go`, tests.
   - `Rule` field on `EnrichedFinding` is a `string`; serialized as `rule` JSON key with `omitempty`. Consistent across stage, test stage, integration test.
   - `Policy.Decide` returns `(Action, *Rule)`; `*Rule` is non-nil only when an action other than the default fired.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-17-policy-engine.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
