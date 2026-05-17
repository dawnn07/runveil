# Request Parsing + Secret Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn Railcore from a passthrough proxy into an actual AI firewall — parse OpenAI `chat.completions` and Anthropic `messages` requests, scan extracted prompt content against 30 curated secret patterns, and either log (default) or block (opt-in) high-severity findings before they leave the machine.

**Architecture:** Three new leaf packages (`internal/parser`, `internal/detector`, `internal/stage/secretscan`) plus a 3-line change to `internal/proxy/upstream.go` to stash the request body in `rc.Metadata` before the pipeline runs. The stage implements the existing `pipeline.Stage` interface; no changes to `internal/pipeline`, `internal/ca`, `internal/trust`.

**Tech Stack:** Go 1.25 (stdlib only — `regexp`, `encoding/json`, `unicode/utf8`); existing dependencies (`github.com/google/uuid`, `golang.org/x/net/http2`, `go.uber.org/goleak`) are sufficient — no new third-party deps.

**Spec:** [`docs/superpowers/specs/2026-05-17-request-parsing-and-secret-detection-design.md`](../specs/2026-05-17-request-parsing-and-secret-detection-design.md)

---

## File Map

| File | Purpose |
|---|---|
| `internal/parser/parser.go` | `ParsedRequest`, `TextSegment` types; `ParseRequest` dispatcher |
| `internal/parser/openai.go` | OpenAI `chat.completions` parser |
| `internal/parser/anthropic.go` | Anthropic `messages` parser (handles both string and content-block-array forms) |
| `internal/parser/parser_test.go` | Unit tests for parser dispatch + each vendor |
| `internal/detector/detector.go` | `Severity`, `Finding`, `Pattern`, `Scan`, `AddPattern` |
| `internal/detector/entropy.go` | Shannon entropy helper |
| `internal/detector/patterns.go` | The 30 curated patterns |
| `internal/detector/detector_test.go` | Unit tests for `Scan`, entropy, AddPattern, per-pattern positives/negatives |
| `internal/detector/corpus_test.go` | FP-rate sanity test against a small clean corpus |
| `internal/stage/secretscan/stage.go` | The `pipeline.Stage` that wires parser + detector |
| `internal/stage/secretscan/stage_test.go` | Unit tests for the stage |
| `internal/proxy/upstream.go` | **Modify:** stash request body in `rc.Metadata["body"]` before pipeline runs; enrich Block 403 body with findings |
| `internal/proxy/server_test.go` | **Modify:** new integration tests for secretscan via the live proxy |
| `cmd/railcore/main.go` | **Modify:** register the secretscan stage, add `--block-on-detect` flag, remove the no-op `forwardStage` |
| `test/integration/secretscan_test.go` | End-to-end block + warn scenarios |

**Dependency direction (must not be violated):**

```
cmd/railcore
   └── internal/stage/secretscan
          ├── internal/parser     (leaf — depends only on stdlib)
          ├── internal/detector   (leaf — depends only on stdlib + regexp)
          └── internal/pipeline   (existing leaf, unchanged)

internal/proxy   ──→  internal/pipeline   (existing edge, unchanged)
```

`parser` and `detector` must not import any other `railcore/internal/*` package. `secretscan` is the only package that imports both.

---

## Task 1: Detector — types and empty `Scan`

**Files:**
- Create: `internal/detector/detector.go`
- Create: `internal/detector/detector_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/detector/detector_test.go`:

```go
package detector

import "testing"

func TestSeverity_String(t *testing.T) {
	cases := []struct {
		s    Severity
		want string
	}{
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
	}
	for _, tc := range cases {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tc.s, got, tc.want)
		}
	}
}

func TestScan_EmptyPatternsReturnsEmpty(t *testing.T) {
	findings := Scan("anything at all")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings with no patterns registered, got %d", len(findings))
	}
}

func TestScan_EmptyTextReturnsEmpty(t *testing.T) {
	findings := Scan("")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on empty text, got %d", len(findings))
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test ./internal/detector/...
```

Expected: compile error — `Severity`, `SeverityLow`, `Scan`, etc. are undefined.

- [ ] **Step 3: Implement `detector.go`**

Create `internal/detector/detector.go`:

```go
// Package detector scans plain text for high-confidence secrets like API
// keys, tokens, and private keys. It is a leaf package: it must not
// import any other internal/ package.
//
// Pattern definitions live in patterns.go. Pattern provenance is
// documented in patterns.go's header — most patterns are derived from
// the open-source secretlint, trufflehog, and gitleaks catalogs.
package detector

import (
	"regexp"
	"sort"
	"sync"
)

// Severity is the confidence tier of a finding.
//
// Only High-severity findings are eligible for Block when the operator
// has enabled --block-on-detect. Medium and Low are WARN-only regardless
// of flag state.
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
)

func (s Severity) String() string {
	switch s {
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "unknown"
	}
}

// Finding describes one detected secret. The matched substring is
// deliberately NOT included — callers can compute it from text[Offset:Offset+Length]
// if they need it, but the Finding itself never carries secret bytes.
type Finding struct {
	Pattern  string
	Severity Severity
	Offset   int
	Length   int
}

// Pattern is one secret-detection rule.
type Pattern struct {
	Name             string
	Severity         Severity
	Regex            *regexp.Regexp
	EntropyThreshold float64 // 0 = no entropy filter
	// EntropySpan, if non-nil, returns the byte range within a match
	// whose entropy is measured. Defaults to the whole match.
	EntropySpan func(text string, match []int) (start, end int)
}

var (
	mu       sync.RWMutex
	patterns []Pattern
)

// AddPattern registers an additional pattern at runtime. Intended for
// sub-project #3's YAML policy loader. Not part of a stable API yet;
// behaviour may change.
func AddPattern(p Pattern) {
	mu.Lock()
	patterns = append(patterns, p)
	mu.Unlock()
}

// Scan runs all registered patterns over text and returns findings
// sorted by offset. Scan is pure: no I/O, no logging, no side effects.
// Safe for concurrent use.
func Scan(text string) []Finding {
	if text == "" {
		return nil
	}
	mu.RLock()
	defer mu.RUnlock()
	var out []Finding
	for _, p := range patterns {
		matches := p.Regex.FindAllStringIndex(text, -1)
		for _, m := range matches {
			if p.EntropyThreshold > 0 {
				start, end := m[0], m[1]
				if p.EntropySpan != nil {
					start, end = p.EntropySpan(text, m)
				}
				if end <= start || end > len(text) {
					continue
				}
				if shannonEntropy(text[start:end]) < p.EntropyThreshold {
					continue
				}
			}
			out = append(out, Finding{
				Pattern:  p.Name,
				Severity: p.Severity,
				Offset:   m[0],
				Length:   m[1] - m[0],
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	return out
}
```

- [ ] **Step 4: Add a temporary stub for `shannonEntropy`**

Create `internal/detector/entropy.go`:

```go
package detector

// shannonEntropy returns the Shannon entropy of s in bits per byte.
// Implementation lands in Task 2.
func shannonEntropy(s string) float64 {
	return 0
}
```

- [ ] **Step 5: Run the tests and verify they pass**

```bash
go test -race -count=1 ./internal/detector/...
```

Expected: 3 PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/detector/
git commit -m "feat(detector): add Severity, Finding, Pattern types and empty Scan"
```

---

## Task 2: Detector — Shannon entropy

**Files:**
- Modify: `internal/detector/entropy.go`
- Modify: `internal/detector/detector_test.go` (append)

- [ ] **Step 1: Append failing tests for entropy**

Append to `internal/detector/detector_test.go`:

```go

func TestShannonEntropy(t *testing.T) {
	cases := []struct {
		name string
		in   string
		min  float64
		max  float64
	}{
		{"empty", "", 0, 0},
		{"single char repeated", "aaaaaaaaaa", 0, 0.001},
		{"two equal chars", "abababab", 0.999, 1.001},
		{"random-looking 16-char suffix", "IOSFODNN7EXAMPLE", 3.4, 4.1},
		{"high-entropy hex", "0123456789abcdef0123456789abcdef", 3.9, 4.001},
	}
	for _, tc := range cases {
		got := shannonEntropy(tc.in)
		if got < tc.min || got > tc.max {
			t.Errorf("shannonEntropy(%q) = %f, want in [%f, %f]", tc.in, got, tc.min, tc.max)
		}
	}
}
```

- [ ] **Step 2: Run and confirm tests fail**

```bash
go test ./internal/detector/...
```

Expected: `TestShannonEntropy` fails — current stub returns 0 for all inputs.

- [ ] **Step 3: Implement entropy**

Replace `internal/detector/entropy.go` contents:

```go
package detector

import "math"

// shannonEntropy returns the Shannon entropy of s in bits per byte.
// Returns 0 for the empty string. Computed over the byte distribution
// of s — this is sufficient for distinguishing low-entropy patterns
// (test fixtures, ALL-CAPS placeholders) from high-entropy random keys.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * math.Log2(p)
	}
	return h
}
```

- [ ] **Step 4: Run tests and confirm pass**

```bash
go test -race -count=1 ./internal/detector/...
```

Expected: 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/detector/entropy.go internal/detector/detector_test.go
git commit -m "feat(detector): add Shannon entropy helper"
```

---

## Task 3: Detector — AWS access key pattern (proof-of-pattern)

This task adds ONE pattern end-to-end so the pattern-registration idiom is established before bulk-adding the other 29.

**Files:**
- Create: `internal/detector/patterns.go`
- Modify: `internal/detector/detector_test.go` (append)

- [ ] **Step 1: Append failing tests for AWS access key**

Append to `internal/detector/detector_test.go`:

```go

func TestScan_AWSAccessKeyID_Positive(t *testing.T) {
	text := `here is my key AKIAIOSFODNN7EXAMPLE for the bucket`
	findings := Scan(text)
	want := "aws_access_key_id"
	found := false
	for _, f := range findings {
		if f.Pattern == want && f.Severity == SeverityHigh {
			found = true
			if got := text[f.Offset : f.Offset+f.Length]; got != "AKIAIOSFODNN7EXAMPLE" {
				t.Errorf("matched substring = %q, want %q", got, "AKIAIOSFODNN7EXAMPLE")
			}
		}
	}
	if !found {
		t.Fatalf("Scan did not find aws_access_key_id in %q; got %+v", text, findings)
	}
}

func TestScan_AWSAccessKeyID_LowEntropySuffixRejected(t *testing.T) {
	// AKIA + all-zeros suffix has entropy 0, must NOT match.
	text := "value: AKIA0000000000000000"
	findings := Scan(text)
	for _, f := range findings {
		if f.Pattern == "aws_access_key_id" {
			t.Fatalf("low-entropy AWS suffix should be filtered, but got finding %+v", f)
		}
	}
}

func TestScan_AWSAccessKeyID_NoFalseMatch(t *testing.T) {
	text := "this string contains the word akia in lowercase and AKIA only"
	findings := Scan(text)
	for _, f := range findings {
		if f.Pattern == "aws_access_key_id" {
			t.Fatalf("expected no aws_access_key_id finding in %q, got %+v", text, f)
		}
	}
}
```

- [ ] **Step 2: Run and confirm they fail**

```bash
go test ./internal/detector/...
```

Expected: `TestScan_AWSAccessKeyID_Positive` fails — no patterns registered.

- [ ] **Step 3: Create `patterns.go` with the AWS access key pattern**

Create `internal/detector/patterns.go`:

```go
// Pattern provenance: patterns in this file are derived from public
// catalogs in secretlint (MIT), gitleaks (MIT), and trufflehog (various
// licenses; the regex strings themselves are facts and we cite for
// hygiene rather than legal necessity). Where patterns differ from
// upstream we have tightened them to reduce false positives.
//
// Each pattern entry: name, severity, regex, optional entropy threshold,
// optional entropy span. Add a corresponding positive + negative unit
// test in detector_test.go when adding a new pattern.

package detector

import "regexp"

func init() {
	// AWS Access Key ID: AKIA + 16 random base32-ish chars.
	// Entropy filter on the 16-char suffix rejects test fixtures like
	// AKIAEXAMPLEKEY or AKIA0000000000000000.
	register(Pattern{
		Name:             "aws_access_key_id",
		Severity:         SeverityHigh,
		Regex:            regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		EntropyThreshold: 3.0,
		EntropySpan: func(text string, m []int) (int, int) {
			// Skip the AKIA prefix; measure entropy on the 16-char suffix.
			return m[0] + 4, m[1]
		},
	})
}

// register is a package-private convenience for init-time pattern
// registration. AddPattern (exported) is for runtime registration by
// the policy loader.
func register(p Pattern) {
	mu.Lock()
	patterns = append(patterns, p)
	mu.Unlock()
}
```

- [ ] **Step 4: Run tests and confirm pass**

```bash
go test -race -count=1 ./internal/detector/...
```

Expected: 7 PASS (4 prior + 3 new).

- [ ] **Step 5: Commit**

```bash
git add internal/detector/patterns.go internal/detector/detector_test.go
git commit -m "feat(detector): add aws_access_key_id pattern with entropy filter"
```

---

## Task 4: Detector — remaining 29 patterns

Bulk-add the rest of the catalog. Each pattern gets one `register(...)` call in `patterns.go` (in an `init()` block) plus one positive + one negative test.

**Files:**
- Modify: `internal/detector/patterns.go`
- Modify: `internal/detector/detector_test.go` (append)

- [ ] **Step 1: Replace `patterns.go` with the full catalog**

Replace the contents of `internal/detector/patterns.go` with:

```go
// Pattern provenance: patterns in this file are derived from public
// catalogs in secretlint (MIT), gitleaks (MIT), and trufflehog. We have
// tightened several to reduce false positives.

package detector

import "regexp"

func init() {
	// --- AWS ---
	register(Pattern{
		Name:             "aws_access_key_id",
		Severity:         SeverityHigh,
		Regex:            regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		EntropyThreshold: 3.0,
		EntropySpan:      func(_ string, m []int) (int, int) { return m[0] + 4, m[1] },
	})
	register(Pattern{
		Name:             "aws_secret_access_key",
		Severity:         SeverityHigh,
		Regex:            regexp.MustCompile(`(?i)aws[_\-]?(?:secret|sk)[^\n=:]{0,30}[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
		EntropyThreshold: 4.5,
		EntropySpan: func(text string, m []int) (int, int) {
			// Measure entropy on the captured group (the 40-char secret).
			if len(m) < 4 {
				return m[0], m[1]
			}
			return m[2], m[3]
		},
	})
	register(Pattern{
		Name:     "aws_session_token",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\b(?:FwoG|IQoJ)[A-Za-z0-9/+=]{100,}\b`),
	})

	// --- GitHub ---
	register(Pattern{
		Name:     "github_pat_classic",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`),
	})
	register(Pattern{
		Name:     "github_pat_fine_grained",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{82}\b`),
	})
	register(Pattern{
		Name:     "github_oauth_token",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bgho_[A-Za-z0-9]{36}\b`),
	})
	register(Pattern{
		Name:     "github_app_token",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\b(?:ghu|ghs)_[A-Za-z0-9]{36}\b`),
	})

	// --- GitLab ---
	register(Pattern{
		Name:     "gitlab_pat",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20}\b`),
	})

	// --- Stripe ---
	register(Pattern{
		Name:     "stripe_secret_live",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{24,}\b`),
	})
	register(Pattern{
		Name:     "stripe_restricted_live",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\brk_live_[A-Za-z0-9]{24,}\b`),
	})

	// --- OpenAI / Anthropic ---
	register(Pattern{
		Name:     "openai_api_key",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`),
	})
	register(Pattern{
		Name:     "anthropic_api_key",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{86,}\b`),
	})

	// --- Google ---
	register(Pattern{
		Name:     "google_api_key",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
	})
	register(Pattern{
		Name:     "google_oauth_client_secret",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bGOCSPX-[A-Za-z0-9_-]{28}\b`),
	})
	register(Pattern{
		Name:     "google_service_account_json",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`"type"\s*:\s*"service_account"[\s\S]{1,500}?"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----`),
	})

	// --- Slack ---
	register(Pattern{
		Name:     "slack_bot_token",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bxoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+\b`),
	})
	register(Pattern{
		Name:     "slack_user_token",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bxoxp-[0-9]+-[0-9]+-[0-9]+-[A-Fa-f0-9]+\b`),
	})
	register(Pattern{
		Name:     "slack_app_token",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bxapp-[0-9]+-[A-Z0-9]+-[0-9]+-[A-Fa-f0-9]+\b`),
	})
	register(Pattern{
		Name:     "slack_webhook_url",
		Severity: SeverityMedium,
		Regex:    regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[A-Za-z0-9]+`),
	})

	// --- Discord ---
	register(Pattern{
		Name:     "discord_bot_token",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\b[MN][A-Za-z0-9]{23}\.[\w-]{6}\.[\w-]{27}\b`),
	})
	register(Pattern{
		Name:     "discord_webhook_url",
		Severity: SeverityMedium,
		Regex:    regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+`),
	})

	// --- Package registries ---
	register(Pattern{
		Name:     "npm_token",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),
	})
	register(Pattern{
		Name:     "pypi_token",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b`),
	})

	// --- Private keys ---
	register(Pattern{
		Name:     "private_key_rsa",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
	})
	register(Pattern{
		Name:     "private_key_openssh",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
	})
	register(Pattern{
		Name:     "private_key_ec",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
	})
	register(Pattern{
		Name:     "private_key_pkcs8",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
	})

	// --- JWT / DB URLs / generic ---
	register(Pattern{
		Name:     "jwt",
		Severity: SeverityMedium,
		Regex:    regexp.MustCompile(`\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
	})
	register(Pattern{
		Name:     "db_url_with_password",
		Severity: SeverityMedium,
		Regex:    regexp.MustCompile(`\b(?:postgres|mysql|mongodb)(?:\+srv)?://[^\s:]+:[^@/\s]+@[^/\s]+`),
	})
	register(Pattern{
		Name:             "generic_high_entropy_assignment",
		Severity:         SeverityLow,
		Regex:            regexp.MustCompile(`(?i)(?:password|secret|api[_-]?key|token)\s*[:=]\s*['"]?([A-Za-z0-9/+=_-]{20,})['"]?`),
		EntropyThreshold: 4.0,
		EntropySpan: func(_ string, m []int) (int, int) {
			if len(m) < 4 {
				return m[0], m[1]
			}
			return m[2], m[3]
		},
	})
}

func register(p Pattern) {
	mu.Lock()
	patterns = append(patterns, p)
	mu.Unlock()
}
```

- [ ] **Step 2: Append positive + negative tests for each new pattern**

Append to `internal/detector/detector_test.go`:

```go

// Each new pattern gets a positive + negative test. Test names follow
// the convention TestScan_<PatternName>_Positive / _Negative.

func TestScan_AWSSecretAccessKey_Positive(t *testing.T) {
	text := `AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`
	requireFinding(t, text, "aws_secret_access_key", SeverityHigh)
}
func TestScan_AWSSecretAccessKey_Negative(t *testing.T) {
	text := `secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`
	requireNoFinding(t, text, "aws_secret_access_key")
}

func TestScan_AWSSessionToken_Positive(t *testing.T) {
	text := `tok=FwoGZXIvYXdzEHkaDFAKEFAKEFAKEFAKE` + repeat("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/=", 3)
	requireFinding(t, text, "aws_session_token", SeverityHigh)
}
func TestScan_AWSSessionToken_Negative(t *testing.T) {
	requireNoFinding(t, "FwoGZXIvshort", "aws_session_token")
}

func TestScan_GitHubPATClassic_Positive(t *testing.T) {
	requireFinding(t, `token: ghp_abcdefghijklmnopqrstuvwxyz0123456789`, "github_pat_classic", SeverityHigh)
}
func TestScan_GitHubPATClassic_Negative(t *testing.T) {
	requireNoFinding(t, "ghp_too_short", "github_pat_classic")
}

func TestScan_GitHubPATFineGrained_Positive(t *testing.T) {
	requireFinding(t, `pat: github_pat_`+repeat("A", 82), "github_pat_fine_grained", SeverityHigh)
}
func TestScan_GitHubPATFineGrained_Negative(t *testing.T) {
	requireNoFinding(t, "github_pat_short", "github_pat_fine_grained")
}

func TestScan_GitHubOAuthToken_Positive(t *testing.T) {
	requireFinding(t, `gho_abcdefghijklmnopqrstuvwxyz0123456789`, "github_oauth_token", SeverityHigh)
}
func TestScan_GitHubOAuthToken_Negative(t *testing.T) {
	requireNoFinding(t, "gho_short", "github_oauth_token")
}

func TestScan_GitHubAppToken_Positive(t *testing.T) {
	requireFinding(t, `ghu_abcdefghijklmnopqrstuvwxyz0123456789`, "github_app_token", SeverityHigh)
	requireFinding(t, `ghs_abcdefghijklmnopqrstuvwxyz0123456789`, "github_app_token", SeverityHigh)
}
func TestScan_GitHubAppToken_Negative(t *testing.T) {
	requireNoFinding(t, "ghx_abcdefghijklmnopqrstuvwxyz0123456789", "github_app_token")
}

func TestScan_GitLabPAT_Positive(t *testing.T) {
	requireFinding(t, `pat: glpat-abcdefg-Hij_klmnopq`, "gitlab_pat", SeverityHigh)
}
func TestScan_GitLabPAT_Negative(t *testing.T) {
	requireNoFinding(t, "glpat-short", "gitlab_pat")
}

func TestScan_StripeSecretLive_Positive(t *testing.T) {
	requireFinding(t, `sk_live_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF`, "stripe_secret_live", SeverityHigh)
}
func TestScan_StripeSecretLive_Negative(t *testing.T) {
	requireNoFinding(t, "sk_test_abcdefghijklmnopqrstuvwxyz", "stripe_secret_live")
}

func TestScan_StripeRestrictedLive_Positive(t *testing.T) {
	requireFinding(t, `rk_live_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF`, "stripe_restricted_live", SeverityHigh)
}
func TestScan_StripeRestrictedLive_Negative(t *testing.T) {
	requireNoFinding(t, "rk_test_abc", "stripe_restricted_live")
}

func TestScan_OpenAIAPIKey_Positive(t *testing.T) {
	requireFinding(t, `sk-proj-abcdefghijklmnopqrstuvwxyz0123456789`, "openai_api_key", SeverityHigh)
	requireFinding(t, `sk-abcdefghijklmnopqrstuvwxyz0123456789`, "openai_api_key", SeverityHigh)
}
func TestScan_OpenAIAPIKey_Negative(t *testing.T) {
	requireNoFinding(t, "sk-short", "openai_api_key")
}

func TestScan_AnthropicAPIKey_Positive(t *testing.T) {
	requireFinding(t, `key: sk-ant-`+repeat("A", 86), "anthropic_api_key", SeverityHigh)
}
func TestScan_AnthropicAPIKey_Negative(t *testing.T) {
	requireNoFinding(t, "sk-ant-short", "anthropic_api_key")
}

func TestScan_GoogleAPIKey_Positive(t *testing.T) {
	requireFinding(t, `key=AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`, "google_api_key", SeverityHigh)
}
func TestScan_GoogleAPIKey_Negative(t *testing.T) {
	requireNoFinding(t, "AIzaShort", "google_api_key")
}

func TestScan_GoogleOAuthClientSecret_Positive(t *testing.T) {
	requireFinding(t, `secret: GOCSPX-abcdefghijklmnopqrstuvwx`, "google_oauth_client_secret", SeverityHigh)
}
func TestScan_GoogleOAuthClientSecret_Negative(t *testing.T) {
	requireNoFinding(t, "GOCSPX-short", "google_oauth_client_secret")
}

func TestScan_GoogleServiceAccountJSON_Positive(t *testing.T) {
	requireFinding(t,
		`{"type": "service_account", "project_id": "p", "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE..."}`,
		"google_service_account_json", SeverityHigh)
}
func TestScan_GoogleServiceAccountJSON_Negative(t *testing.T) {
	requireNoFinding(t, `{"type":"user","private_key":"not a key"}`, "google_service_account_json")
}

func TestScan_SlackBotToken_Positive(t *testing.T) {
	requireFinding(t, `tok: xoxb-123456789-987654321-abcDEFghiJKLmnoPQRstu`, "slack_bot_token", SeverityHigh)
}
func TestScan_SlackBotToken_Negative(t *testing.T) {
	requireNoFinding(t, "xoxb-incomplete", "slack_bot_token")
}

func TestScan_SlackUserToken_Positive(t *testing.T) {
	requireFinding(t, `xoxp-123456789-987654321-555555555-abcdef0123456789`, "slack_user_token", SeverityHigh)
}
func TestScan_SlackUserToken_Negative(t *testing.T) {
	requireNoFinding(t, "xoxp-short", "slack_user_token")
}

func TestScan_SlackAppToken_Positive(t *testing.T) {
	requireFinding(t, `xapp-1-A0123ABCDE-1234567890-abcdef0123456789`, "slack_app_token", SeverityHigh)
}
func TestScan_SlackAppToken_Negative(t *testing.T) {
	requireNoFinding(t, "xapp-short", "slack_app_token")
}

func TestScan_SlackWebhook_Positive(t *testing.T) {
	requireFinding(t, `https://hooks.slack.com/services/T01234567/B01234567/abcdefghij`, "slack_webhook_url", SeverityMedium)
}
func TestScan_SlackWebhook_Negative(t *testing.T) {
	requireNoFinding(t, "https://example.com/hook", "slack_webhook_url")
}

func TestScan_DiscordBotToken_Positive(t *testing.T) {
	requireFinding(t, `MTAwMDAwMDAwMDAwMDAwMDAwMA.AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAA`, "discord_bot_token", SeverityHigh)
}
func TestScan_DiscordBotToken_Negative(t *testing.T) {
	requireNoFinding(t, "Mshortdiscord", "discord_bot_token")
}

func TestScan_DiscordWebhook_Positive(t *testing.T) {
	requireFinding(t, `https://discord.com/api/webhooks/123456789/abcdefg_hijkl`, "discord_webhook_url", SeverityMedium)
}
func TestScan_DiscordWebhook_Negative(t *testing.T) {
	requireNoFinding(t, "https://example.com/api/webhooks/123/abc", "discord_webhook_url")
}

func TestScan_NPMToken_Positive(t *testing.T) {
	requireFinding(t, `_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789`, "npm_token", SeverityHigh)
}
func TestScan_NPMToken_Negative(t *testing.T) {
	requireNoFinding(t, "npm_short", "npm_token")
}

func TestScan_PyPIToken_Positive(t *testing.T) {
	requireFinding(t, `pypi-AgEIcHlwaS5vcmc`+repeat("X", 50), "pypi_token", SeverityHigh)
}
func TestScan_PyPIToken_Negative(t *testing.T) {
	requireNoFinding(t, "pypi-short", "pypi_token")
}

func TestScan_PrivateKeyRSA_Positive(t *testing.T) {
	requireFinding(t, "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...", "private_key_rsa", SeverityHigh)
}
func TestScan_PrivateKeyOpenSSH_Positive(t *testing.T) {
	requireFinding(t, "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk...", "private_key_openssh", SeverityHigh)
}
func TestScan_PrivateKeyEC_Positive(t *testing.T) {
	requireFinding(t, "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIGZ4...", "private_key_ec", SeverityHigh)
}
func TestScan_PrivateKeyPKCS8_Positive(t *testing.T) {
	requireFinding(t, "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhk...", "private_key_pkcs8", SeverityHigh)
}

func TestScan_JWT_Positive(t *testing.T) {
	requireFinding(t,
		`eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature_xyz_at_least_ten_chars`,
		"jwt", SeverityMedium)
}
func TestScan_JWT_Negative(t *testing.T) {
	requireNoFinding(t, "not a jwt", "jwt")
}

func TestScan_DBURLWithPassword_Positive(t *testing.T) {
	requireFinding(t, `postgres://user:hunter2@db.example.com:5432/app`, "db_url_with_password", SeverityMedium)
}
func TestScan_DBURLWithPassword_Negative(t *testing.T) {
	requireNoFinding(t, "postgres://db.example.com:5432/app", "db_url_with_password")
}

func TestScan_GenericHighEntropy_Positive(t *testing.T) {
	requireFinding(t,
		`api_key = "Xy7Bz9Qf2vR8N3sM5tK1pL6wA0eD4hCg"`,
		"generic_high_entropy_assignment", SeverityLow)
}
func TestScan_GenericHighEntropy_NegativeLowEntropy(t *testing.T) {
	requireNoFinding(t, `password = "aaaaaaaaaaaaaaaaaaaaaaaa"`, "generic_high_entropy_assignment")
}

// --- test helpers ---

func requireFinding(t *testing.T, text, pattern string, sev Severity) {
	t.Helper()
	for _, f := range Scan(text) {
		if f.Pattern == pattern && f.Severity == sev {
			return
		}
	}
	t.Fatalf("Scan(%q) did not produce %s/%s; got %+v", text, pattern, sev, Scan(text))
}

func requireNoFinding(t *testing.T, text, pattern string) {
	t.Helper()
	for _, f := range Scan(text) {
		if f.Pattern == pattern {
			t.Fatalf("Scan(%q) produced unwanted finding %+v", text, f)
		}
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
```

Note: the test for `pypi-AgEIcHlwaS5vcmc` uses 50 `X`s — high-entropy enough characters to satisfy potential future tightening. The pattern regex itself doesn't currently have an entropy filter so any 50-char tail works.

- [ ] **Step 3: Run tests and confirm all pass**

```bash
go test -race -count=1 ./internal/detector/...
```

Expected: all tests pass (the 4 from Tasks 1-3 plus ~50 new ones from this task).

If any tests fail, the most common cause is a regex that doesn't match because of word-boundary `\b` interactions with surrounding characters. Inspect the failing test's input — the surrounding text in the test string is intentional to exercise the boundaries.

- [ ] **Step 4: Commit**

```bash
git add internal/detector/patterns.go internal/detector/detector_test.go
git commit -m "feat(detector): add 29 remaining secret patterns with positive+negative tests"
```

---

## Task 5: Detector — `AddPattern` runtime hook test

The `AddPattern` function was added in Task 1 but never tested. This task locks in its behaviour.

**Files:**
- Modify: `internal/detector/detector_test.go` (append)

- [ ] **Step 1: Append the test**

```go

func TestAddPattern_RegistersAtRuntime(t *testing.T) {
	// Snapshot the current pattern count.
	mu.RLock()
	before := len(patterns)
	mu.RUnlock()

	AddPattern(Pattern{
		Name:     "test_runtime_pattern",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`runtime-secret-[0-9]+`),
	})

	mu.RLock()
	after := len(patterns)
	mu.RUnlock()
	if after != before+1 {
		t.Fatalf("AddPattern did not grow registry: before=%d after=%d", before, after)
	}

	findings := Scan("here is runtime-secret-12345 in text")
	found := false
	for _, f := range findings {
		if f.Pattern == "test_runtime_pattern" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Scan did not see the runtime-added pattern; got %+v", findings)
	}
}
```

Add `"regexp"` to the test file's imports if not already there.

- [ ] **Step 2: Run and confirm pass**

```bash
go test -race -count=1 ./internal/detector/...
```

Expected: PASS for `TestAddPattern_RegistersAtRuntime` plus everything before it.

- [ ] **Step 3: Commit**

```bash
git add internal/detector/detector_test.go
git commit -m "test(detector): verify AddPattern runtime registration"
```

---

## Task 6: Detector — corpus FP-rate sanity check

**Files:**
- Create: `internal/detector/corpus_test.go`

- [ ] **Step 1: Create the corpus test**

Create `internal/detector/corpus_test.go`:

```go
package detector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCorpus_LowFPOnCleanText runs Scan over a small known-clean corpus
// and asserts the false-positive count stays low. Not a hard CI gate;
// the limit is generous so it catches regressions without blocking
// legitimate new patterns.
func TestCorpus_LowFPOnCleanText(t *testing.T) {
	corpus := loadCorpus(t)
	if len(corpus) < 1000 {
		t.Fatalf("corpus too small (%d bytes); add more files", len(corpus))
	}

	findings := Scan(corpus)

	// We allow up to 3 false positives across the whole corpus. Anything
	// more suggests a recently-added pattern is too eager.
	const maxFP = 3
	if len(findings) > maxFP {
		t.Errorf("corpus produced %d findings; want ≤ %d. Patterns matched:", len(findings), maxFP)
		for _, f := range findings {
			t.Errorf("  - %s (severity=%s) at offset %d", f.Pattern, f.Severity, f.Offset)
		}
	}
}

// loadCorpus concatenates the contents of a few known-clean Go source
// files from this repo to use as the corpus. Using project-internal
// files (rather than checked-in test fixtures) keeps the corpus
// representative and self-updating.
func loadCorpus(t *testing.T) string {
	t.Helper()
	repoRoot := findRepoRoot(t)
	files := []string{
		"cmd/railcore/main.go",
		"internal/ca/ca.go",
		"internal/ca/leaf.go",
		"internal/proxy/server.go",
		"internal/proxy/upstream.go",
		"internal/proxy/intercept.go",
		"internal/pipeline/chain.go",
		"internal/pipeline/stage.go",
	}
	var b strings.Builder
	for _, f := range files {
		path := filepath.Join(repoRoot, f)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read corpus file %s: %v", path, err)
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	return b.String()
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not find repo root (no go.mod within 10 parents of cwd)")
	return ""
}
```

- [ ] **Step 2: Run the test**

```bash
go test -race -count=1 -run TestCorpus_LowFPOnCleanText ./internal/detector/...
```

Expected: PASS. If it fails because a pattern matched something in the source, that's useful — investigate whether the pattern is too eager and tighten its regex.

- [ ] **Step 3: Commit**

```bash
git add internal/detector/corpus_test.go
git commit -m "test(detector): corpus FP-rate sanity check against repo source"
```

---

## Task 7: Parser — types and dispatcher

**Files:**
- Create: `internal/parser/parser.go`
- Create: `internal/parser/parser_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/parser/parser_test.go`:

```go
package parser

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseRequest_UnknownHost(t *testing.T) {
	req := httptest.NewRequest("POST", "https://example.com/foo", nil)
	parsed, err := ParseRequest("example.com", req, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed != nil {
		t.Fatalf("expected nil for unknown host, got %+v", parsed)
	}
}

func TestParseRequest_UnknownPathOnKnownHost(t *testing.T) {
	req := httptest.NewRequest("POST", "https://api.openai.com/v1/embeddings", nil)
	parsed, err := ParseRequest("api.openai.com", req, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed != nil {
		t.Fatalf("expected nil for unknown path, got %+v", parsed)
	}
}

func TestParseRequest_NonPostMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "https://api.openai.com/v1/chat/completions", nil)
	parsed, err := ParseRequest("api.openai.com", req, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed != nil {
		t.Fatalf("expected nil for GET on chat.completions, got %+v", parsed)
	}
}

var _ = http.MethodPost // keep net/http import alive when above tests evolve
```

- [ ] **Step 2: Run and confirm fail**

```bash
go test ./internal/parser/...
```

Expected: compile error — `ParseRequest` undefined.

- [ ] **Step 3: Implement `parser.go`**

Create `internal/parser/parser.go`:

```go
// Package parser extracts the prose payload from AI vendor request
// bodies into a normalized form (ParsedRequest). It is a leaf package:
// it must not import any other internal/ package.
//
// Each vendor file (openai.go, anthropic.go) handles one host's request
// schemas. The exported ParseRequest function dispatches by host + path.
package parser

import "net/http"

// ParsedRequest is the normalized view of an AI-vendor request.
type ParsedRequest struct {
	Vendor   string        // "openai" | "anthropic"
	Endpoint string        // "chat.completions" | "messages"
	Texts    []TextSegment // all scannable prose extracted from the body
	Raw      []byte        // original request body (kept for future redact action)
}

// TextSegment is one piece of prose pulled out of the request — a user
// message, system prompt, assistant turn, or tool result.
type TextSegment struct {
	Role    string // "user" | "assistant" | "system" | "tool"
	Index   int    // position in the original messages array (0-based)
	Content string // raw text content
}

// ParseRequest dispatches by host + method + path. Returns (nil, nil)
// when the request is not a known AI endpoint — callers should treat
// that as "nothing to scan" and pass through.
//
// Returns (nil, err) when a known endpoint has a malformed JSON body.
// Callers should fail-open on such errors.
func ParseRequest(host string, req *http.Request, body []byte) (*ParsedRequest, error) {
	if req.Method != http.MethodPost {
		return nil, nil
	}
	switch host {
	case "api.openai.com":
		if req.URL.Path == "/v1/chat/completions" {
			return parseOpenAIChat(body)
		}
	case "api.anthropic.com":
		if req.URL.Path == "/v1/messages" {
			return parseAnthropicMessages(body)
		}
	}
	return nil, nil
}

// parseOpenAIChat is implemented in openai.go.
// parseAnthropicMessages is implemented in anthropic.go.
```

- [ ] **Step 4: Add minimal vendor stubs so the package compiles**

Create `internal/parser/openai.go`:

```go
package parser

// parseOpenAIChat is a stub. Full implementation lands in Task 8.
func parseOpenAIChat(body []byte) (*ParsedRequest, error) {
	return nil, nil
}
```

Create `internal/parser/anthropic.go`:

```go
package parser

// parseAnthropicMessages is a stub. Full implementation lands in Task 9.
func parseAnthropicMessages(body []byte) (*ParsedRequest, error) {
	return nil, nil
}
```

- [ ] **Step 5: Run tests and confirm pass**

```bash
go test -race -count=1 ./internal/parser/...
```

Expected: 3 PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/parser/
git commit -m "feat(parser): add types and host/path dispatcher"
```

---

## Task 8: Parser — OpenAI `chat.completions`

**Files:**
- Modify: `internal/parser/openai.go`
- Modify: `internal/parser/parser_test.go` (append)

- [ ] **Step 1: Append failing tests**

Append to `internal/parser/parser_test.go`:

```go

func TestParseOpenAI_BasicChat(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4o",
		"messages": [
			{"role": "system", "content": "you are helpful"},
			{"role": "user",   "content": "hello"},
			{"role": "assistant", "content": "hi"}
		]
	}`)
	req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", nil)
	parsed, err := ParseRequest("api.openai.com", req, body)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if parsed == nil {
		t.Fatal("parsed is nil; expected non-nil for OpenAI chat.completions")
	}
	if parsed.Vendor != "openai" || parsed.Endpoint != "chat.completions" {
		t.Fatalf("vendor/endpoint = %q/%q, want openai/chat.completions", parsed.Vendor, parsed.Endpoint)
	}
	if len(parsed.Texts) != 3 {
		t.Fatalf("Texts len = %d, want 3", len(parsed.Texts))
	}
	checks := []struct {
		i        int
		role     string
		content  string
	}{
		{0, "system", "you are helpful"},
		{1, "user", "hello"},
		{2, "assistant", "hi"},
	}
	for _, c := range checks {
		seg := parsed.Texts[c.i]
		if seg.Role != c.role || seg.Content != c.content || seg.Index != c.i {
			t.Errorf("Texts[%d] = %+v, want role=%s content=%q index=%d",
				c.i, seg, c.role, c.content, c.i)
		}
	}
}

func TestParseOpenAI_MissingMessages(t *testing.T) {
	body := []byte(`{"model": "gpt-4o"}`)
	req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", nil)
	parsed, err := ParseRequest("api.openai.com", req, body)
	if err == nil {
		t.Fatalf("expected error for missing messages, got parsed=%+v", parsed)
	}
}

func TestParseOpenAI_MalformedJSON(t *testing.T) {
	body := []byte(`{`)
	req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", nil)
	parsed, err := ParseRequest("api.openai.com", req, body)
	if err == nil {
		t.Fatalf("expected error for malformed JSON, got parsed=%+v", parsed)
	}
}
```

- [ ] **Step 2: Run and confirm tests fail**

```bash
go test ./internal/parser/...
```

Expected: `TestParseOpenAI_BasicChat` fails — stub returns `(nil, nil)`.

- [ ] **Step 3: Implement `openai.go`**

Replace `internal/parser/openai.go` contents:

```go
package parser

import (
	"encoding/json"
	"fmt"
)

type openAIChatRequest struct {
	Messages []openAIMessage `json:"messages"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func parseOpenAIChat(body []byte) (*ParsedRequest, error) {
	var req openAIChatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("openai chat: %w", err)
	}
	if req.Messages == nil {
		return nil, fmt.Errorf("openai chat: missing messages field")
	}

	texts := make([]TextSegment, 0, len(req.Messages))
	for i, m := range req.Messages {
		if m.Content == "" {
			continue
		}
		texts = append(texts, TextSegment{
			Role:    m.Role,
			Index:   i,
			Content: m.Content,
		})
	}

	return &ParsedRequest{
		Vendor:   "openai",
		Endpoint: "chat.completions",
		Texts:    texts,
		Raw:      body,
	}, nil
}
```

- [ ] **Step 4: Run tests and confirm pass**

```bash
go test -race -count=1 ./internal/parser/...
```

Expected: 6 PASS (3 from Task 7 + 3 new).

- [ ] **Step 5: Commit**

```bash
git add internal/parser/openai.go internal/parser/parser_test.go
git commit -m "feat(parser): OpenAI chat.completions parser"
```

---

## Task 9: Parser — Anthropic `messages`

Anthropic's schema differs from OpenAI in two ways: there's a top-level `system` string (no role wrapper), and `messages[].content` can be either a plain string OR an array of content blocks. Both shapes need to flatten into the same `[]TextSegment`.

**Files:**
- Modify: `internal/parser/anthropic.go`
- Modify: `internal/parser/parser_test.go` (append)

- [ ] **Step 1: Append failing tests**

Append to `internal/parser/parser_test.go`:

```go

func TestParseAnthropic_StringContent(t *testing.T) {
	body := []byte(`{
		"model": "claude-opus-4-7",
		"system": "you are a code reviewer",
		"messages": [
			{"role": "user", "content": "review this"}
		]
	}`)
	req := httptest.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	parsed, err := ParseRequest("api.anthropic.com", req, body)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if parsed == nil {
		t.Fatal("parsed is nil")
	}
	if parsed.Vendor != "anthropic" || parsed.Endpoint != "messages" {
		t.Fatalf("vendor/endpoint = %q/%q", parsed.Vendor, parsed.Endpoint)
	}
	if len(parsed.Texts) != 2 {
		t.Fatalf("Texts len = %d, want 2", len(parsed.Texts))
	}
	// system segment comes first, with Index = -1 to indicate "not in messages array".
	if parsed.Texts[0].Role != "system" || parsed.Texts[0].Content != "you are a code reviewer" || parsed.Texts[0].Index != -1 {
		t.Errorf("system seg = %+v", parsed.Texts[0])
	}
	if parsed.Texts[1].Role != "user" || parsed.Texts[1].Content != "review this" || parsed.Texts[1].Index != 0 {
		t.Errorf("user seg = %+v", parsed.Texts[1])
	}
}

func TestParseAnthropic_ContentBlocksArray(t *testing.T) {
	body := []byte(`{
		"model": "claude-opus-4-7",
		"messages": [
			{"role": "user", "content": [
				{"type": "text", "text": "first chunk"},
				{"type": "text", "text": "second chunk"}
			]}
		]
	}`)
	req := httptest.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	parsed, err := ParseRequest("api.anthropic.com", req, body)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if parsed == nil {
		t.Fatal("parsed is nil")
	}
	if len(parsed.Texts) != 2 {
		t.Fatalf("Texts len = %d, want 2", len(parsed.Texts))
	}
	if parsed.Texts[0].Content != "first chunk" || parsed.Texts[1].Content != "second chunk" {
		t.Errorf("flattened content = %+v", parsed.Texts)
	}
	if parsed.Texts[0].Role != "user" || parsed.Texts[1].Role != "user" {
		t.Errorf("expected both segments to inherit role=user; got %+v", parsed.Texts)
	}
}

func TestParseAnthropic_NoSystemNoMessages(t *testing.T) {
	body := []byte(`{"model": "claude-opus-4-7"}`)
	req := httptest.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	parsed, err := ParseRequest("api.anthropic.com", req, body)
	if err == nil {
		t.Fatalf("expected error for missing messages, got parsed=%+v", parsed)
	}
}

func TestParseAnthropic_MalformedJSON(t *testing.T) {
	body := []byte(`{not json`)
	req := httptest.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	parsed, err := ParseRequest("api.anthropic.com", req, body)
	if err == nil {
		t.Fatalf("expected error for malformed JSON, got parsed=%+v", parsed)
	}
}
```

- [ ] **Step 2: Run and confirm tests fail**

```bash
go test ./internal/parser/...
```

Expected: the four new tests fail — stub returns `(nil, nil)`.

- [ ] **Step 3: Implement `anthropic.go`**

Replace `internal/parser/anthropic.go` contents:

```go
package parser

import (
	"encoding/json"
	"fmt"
)

type anthropicMessagesRequest struct {
	System   string             `json:"system"`
	Messages []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"` // either string or []contentBlock
}

type anthropicContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func parseAnthropicMessages(body []byte) (*ParsedRequest, error) {
	var req anthropicMessagesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("anthropic messages: %w", err)
	}
	if req.Messages == nil {
		return nil, fmt.Errorf("anthropic messages: missing messages field")
	}

	var texts []TextSegment

	if req.System != "" {
		texts = append(texts, TextSegment{
			Role:    "system",
			Index:   -1,
			Content: req.System,
		})
	}

	for i, m := range req.Messages {
		// Try string form first.
		var asString string
		if err := json.Unmarshal(m.Content, &asString); err == nil {
			if asString != "" {
				texts = append(texts, TextSegment{
					Role:    m.Role,
					Index:   i,
					Content: asString,
				})
			}
			continue
		}
		// Otherwise, content is an array of blocks.
		var blocks []anthropicContentBlock
		if err := json.Unmarshal(m.Content, &blocks); err != nil {
			return nil, fmt.Errorf("anthropic messages[%d]: content not string or array: %w", i, err)
		}
		for _, b := range blocks {
			if b.Type == "text" && b.Text != "" {
				texts = append(texts, TextSegment{
					Role:    m.Role,
					Index:   i,
					Content: b.Text,
				})
			}
		}
	}

	return &ParsedRequest{
		Vendor:   "anthropic",
		Endpoint: "messages",
		Texts:    texts,
		Raw:      body,
	}, nil
}
```

- [ ] **Step 4: Run tests and confirm pass**

```bash
go test -race -count=1 ./internal/parser/...
```

Expected: all parser tests pass (10 PASS).

- [ ] **Step 5: Commit**

```bash
git add internal/parser/anthropic.go internal/parser/parser_test.go
git commit -m "feat(parser): Anthropic messages parser (string + content-block-array forms)"
```

---

## Task 10: Proxy — body caching in pipeline metadata

**Files:**
- Modify: `internal/proxy/upstream.go`
- Modify: `internal/proxy/server_test.go` (append)

The proxy's handler reads the full request body to enforce the 32 MiB cap, then replays it via `byteReader`. This task caches the bytes in `rc.Metadata["body"]` before the pipeline runs so future stages can scan without re-reading.

- [ ] **Step 1: Append failing test**

Append to `internal/proxy/server_test.go`:

```go

// bodyCaptureStage records rc.Metadata["body"] for assertion.
type bodyCaptureStage struct {
	captured []byte
}

func (s *bodyCaptureStage) Name() string { return "body-capture" }
func (s *bodyCaptureStage) Process(_ context.Context, rc *pipeline.RequestCtx) (pipeline.Decision, error) {
	if b, ok := rc.Metadata["body"].([]byte); ok {
		s.captured = b
	}
	return pipeline.Continue, nil
}

func TestProxy_StashesBodyInMetadata(t *testing.T) {
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

	stage := &bodyCaptureStage{}
	srv.cfg.Pipeline.Register(stage)

	caPool := x509.NewCertPool()
	caPool.AddCert(srv.cfg.CA.RootCert())
	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "bodytest.test"},
		},
		Timeout: 5 * time.Second,
	}

	wantBody := `{"hello":"world"}`
	resp, err := client.Post("https://bodytest.test/x", "application/json", strings.NewReader(wantBody))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()

	if string(stage.captured) != wantBody {
		t.Fatalf("stashed body = %q, want %q", string(stage.captured), wantBody)
	}
}
```

- [ ] **Step 2: Run and confirm test fails**

```bash
go test -race -count=1 -run TestProxy_StashesBodyInMetadata ./internal/proxy/...
```

Expected: FAIL — body is not in metadata yet.

- [ ] **Step 3: Modify `upstream.go` to stash the body**

In `internal/proxy/upstream.go`, find the handler section (in `newHandler`) where `rc := &pipeline.RequestCtx{...}` is built. The current code looks like:

```go
		rc := &pipeline.RequestCtx{
			Req:       r,
			Host:      host,
			Metadata:  map[string]any{"request_id": requestID},
			StartedAt: time.Now(),
		}
```

Change to:

```go
		rc := &pipeline.RequestCtx{
			Req:       r,
			Host:      host,
			Metadata:  map[string]any{"request_id": requestID, "body": body},
			StartedAt: time.Now(),
		}
```

That's the only change. Three lines, one new metadata entry.

- [ ] **Step 4: Run all proxy tests, confirm pass**

```bash
go test -race -count=1 ./internal/proxy/...
```

Expected: all proxy tests pass (the existing 6 plus the new one).

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/upstream.go internal/proxy/server_test.go
git commit -m "feat(proxy): cache request body in rc.Metadata[\"body\"] for stages"
```

---

## Task 11: Secretscan stage — implementation and tests

**Files:**
- Create: `internal/stage/secretscan/stage.go`
- Create: `internal/stage/secretscan/stage_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/stage/secretscan/stage_test.go`:

```go
package secretscan

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"railcore/internal/pipeline"
)

func newRC(t *testing.T, host string, body string, method, path string) *pipeline.RequestCtx {
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

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestSecretscan_NonAIHostPassesThrough(t *testing.T) {
	s := New(Config{}, discardLogger())
	rc := newRC(t, "example.com", `{"x":1}`, http.MethodPost, "/anything")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Fatalf("decision = %v, want Continue", dec)
	}
	if _, ok := rc.Metadata["secretscan.findings"]; ok {
		t.Fatalf("expected no findings metadata for non-AI host")
	}
}

func TestSecretscan_AIRequestNoFindingsContinues(t *testing.T) {
	s := New(Config{}, discardLogger())
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hello world"}]}`
	rc := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Fatalf("decision = %v, want Continue", dec)
	}
}

func TestSecretscan_AIRequestWithAWSKeyWarnModeContinues(t *testing.T) {
	s := New(Config{BlockOnDetect: false}, discardLogger())
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"key: AKIAIOSFODNN7EXAMPLE here"}]}`
	rc := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Fatalf("decision = %v, want Continue (warn mode)", dec)
	}
	findings, ok := rc.Metadata["secretscan.findings"].([]EnrichedFinding)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected findings in metadata, got %v", rc.Metadata["secretscan.findings"])
	}
}

func TestSecretscan_AIRequestWithAWSKeyBlockModeBlocks(t *testing.T) {
	s := New(Config{BlockOnDetect: true}, discardLogger())
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"key: AKIAIOSFODNN7EXAMPLE here"}]}`
	rc := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Block {
		t.Fatalf("decision = %v, want Block", dec)
	}
}

func TestSecretscan_MediumOnlyDoesNotBlock(t *testing.T) {
	s := New(Config{BlockOnDetect: true}, discardLogger())
	// JWT is Medium severity.
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature_xyz_at_least_ten_chars"
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"my jwt: ` + jwt + `"}]}`
	rc := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Fatalf("decision = %v, want Continue (medium never blocks)", dec)
	}
}

func TestSecretscan_AnthropicSystemPromptScanned(t *testing.T) {
	s := New(Config{BlockOnDetect: true}, discardLogger())
	body := `{"model":"claude-opus-4-7","system":"github: ghp_abcdefghijklmnopqrstuvwxyz0123456789","messages":[{"role":"user","content":"hi"}]}`
	rc := newRC(t, "api.anthropic.com", body, http.MethodPost, "/v1/messages")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Block {
		t.Fatalf("decision = %v, want Block (system prompt contains GitHub PAT)", dec)
	}
}

func TestSecretscan_MalformedJSONContinues(t *testing.T) {
	s := New(Config{BlockOnDetect: true}, discardLogger())
	rc := newRC(t, "api.openai.com", `{not json`, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Fatalf("decision = %v, want Continue (fail-open on parser errors)", dec)
	}
}
```

- [ ] **Step 2: Run and confirm tests fail**

```bash
go test ./internal/stage/secretscan/...
```

Expected: compile error — `Config`, `New`, `EnrichedFinding` undefined.

- [ ] **Step 3: Implement `stage.go`**

Create `internal/stage/secretscan/stage.go`:

```go
// Package secretscan implements the pipeline.Stage that parses outgoing
// AI requests and scans extracted prompt content for secrets.
//
// It is the integration point between internal/parser, internal/detector,
// and internal/pipeline — and the only package that imports both parser
// and detector.
package secretscan

import (
	"context"
	"encoding/json"
	"log/slog"
	"unicode/utf8"

	"railcore/internal/detector"
	"railcore/internal/parser"
	"railcore/internal/pipeline"
)

// Config controls the stage's runtime behaviour.
type Config struct {
	// BlockOnDetect: when true, any High-severity finding produces Block.
	// Medium/Low never block. When false (default), all findings are
	// logged but the request still proceeds upstream.
	BlockOnDetect bool
}

// EnrichedFinding pairs a detector.Finding with the segment metadata
// (which message it came from). Stored in rc.Metadata for future audit
// logging by sub-project #6.
//
// MarshalJSON serializes to a flat public shape that the proxy uses
// directly when building the 403 body — no normalisation needed.
type EnrichedFinding struct {
	Finding      detector.Finding
	Role         string
	MessageIndex int
}

// MarshalJSON emits the public shape used in 403 responses and audit logs.
func (e EnrichedFinding) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Pattern      string `json:"pattern"`
		Severity     string `json:"severity"`
		Role         string `json:"role"`
		MessageIndex int    `json:"message_index"`
	}{
		Pattern:      e.Finding.Pattern,
		Severity:     e.Finding.Severity.String(),
		Role:         e.Role,
		MessageIndex: e.MessageIndex,
	})
}

// Stage is the secret-scanning pipeline stage.
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
func (s *Stage) Name() string { return "secret-scan" }

// Process implements pipeline.Stage.
//
// Steps:
//  1. Read the cached body from rc.Metadata["body"]. If absent, skip
//     (proxy didn't cache for some reason — fail-open).
//  2. Dispatch parser.ParseRequest. If (nil, nil), not an AI endpoint
//     we know — return Continue silently.
//  3. If parser returns an error, log at DEBUG and return Continue
//     (fail-open on malformed AI bodies).
//  4. For each TextSegment, run detector.Scan. Skip segments with
//     invalid UTF-8 to avoid runaway regex on binary blobs.
//  5. Enrich findings with role + message index, stash in metadata.
//  6. If High findings AND BlockOnDetect: log WARN, return Block.
//     Else if any findings: log INFO, return Continue.
//     Else: return Continue silently.
func (s *Stage) Process(ctx context.Context, rc *pipeline.RequestCtx) (pipeline.Decision, error) {
	body, ok := rc.Metadata["body"].([]byte)
	if !ok {
		return pipeline.Continue, nil
	}

	parsed, err := parser.ParseRequest(rc.Host, rc.Req, body)
	if err != nil {
		s.log.Debug("secretscan parser error",
			"host", rc.Host,
			"err", err.Error())
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
```

- [ ] **Step 4: Run tests and confirm pass**

```bash
go test -race -count=1 ./internal/stage/secretscan/...
```

Expected: 7 PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/stage/secretscan/
git commit -m "feat(secretscan): pipeline stage wiring parser + detector"
```

---

## Task 12: Proxy — enrich Block 403 body with findings

When the secretscan stage returns Block, the proxy returns 403. Today's 403 body says `"error": "blocked by railcore policy"` and nothing about *why*. This task threads findings from `rc.Metadata["secretscan.findings"]` into the response.

**Files:**
- Modify: `internal/proxy/upstream.go`
- Modify: `internal/proxy/server_test.go` (append)

- [ ] **Step 1: Append failing test**

Append to `internal/proxy/server_test.go`:

```go

// awsKeyBlockStage simulates secretscan: registers a finding in metadata
// and returns Block. Lets us test the proxy's 403 body shaping without
// pulling in the real secretscan package (avoids test cycle).
type awsKeyBlockStage struct{}

func (awsKeyBlockStage) Name() string { return "test-block-with-findings" }
func (awsKeyBlockStage) Process(_ context.Context, rc *pipeline.RequestCtx) (pipeline.Decision, error) {
	rc.Metadata["secretscan.findings"] = []map[string]any{
		{"pattern": "aws_access_key_id", "severity": "high", "role": "user", "message_index": 0},
	}
	return pipeline.Block, nil
}

func TestProxy_BlockBodyIncludesFindings(t *testing.T) {
	srv, addr := newTestServer(t)
	srv.cfg.Pipeline.Register(awsKeyBlockStage{})

	caPool := x509.NewCertPool()
	caPool.AddCert(srv.cfg.CA.RootCert())
	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
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
	// Verify matched bytes are NOT in the body — security invariant.
	if strings.Contains(string(body), "AKIA") {
		t.Errorf("403 body contains matched bytes: %s", string(body))
	}
}
```

Add `"encoding/json"` to the test file's imports if not already there.

- [ ] **Step 2: Run and confirm test fails**

```bash
go test -race -count=1 -run TestProxy_BlockBodyIncludesFindings ./internal/proxy/...
```

Expected: FAIL — current 403 body has only `error` field, no `findings`.

- [ ] **Step 3: Modify `upstream.go` to thread findings into the 403**

In `internal/proxy/upstream.go`, find the Block path in `newHandler`. The current code is:

```go
		if dec == pipeline.Block {
			http.Error(w, "blocked by railcore policy", http.StatusForbidden)
			return
		}
```

(or it may use `writeJSONResp` from a previous task — verify by reading the file.) Replace it with:

```go
		if dec == pipeline.Block {
			findings, _ := rc.Metadata["secretscan.findings"]
			writeBlockResp(w, requestID, findings)
			return
		}
```

Then add the helper near the other helpers at the bottom of `upstream.go`:

```go
// writeBlockResp writes a 403 with a JSON body listing the findings (if
// any). The findings value comes from rc.Metadata["secretscan.findings"]
// and may be []secretscan.EnrichedFinding (production) or a slice of
// maps with the same public keys (tests). Both shapes serialize to the
// same JSON because EnrichedFinding implements MarshalJSON.
//
// Matched bytes are deliberately never echoed in this body.
func writeBlockResp(w http.ResponseWriter, requestID string, findings any) {
	body := map[string]any{
		"error":      "blocked by railcore policy",
		"request_id": requestID,
		"detector":   "secret-scan",
	}
	if findings != nil {
		body["findings"] = findings
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}
```

Add `"encoding/json"` to upstream.go's imports if it's not already there.

- [ ] **Step 4: Run all proxy tests and confirm pass**

```bash
go test -race -count=1 ./internal/proxy/...
```

Expected: all proxy tests pass (existing 7 + new 1).

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/upstream.go internal/proxy/server_test.go
git commit -m "feat(proxy): include secret-scan findings in Block 403 JSON body"
```

---

## Task 13: Wire secretscan into the binary

**Files:**
- Modify: `cmd/railcore/main.go`

- [ ] **Step 1: Replace `cmd/railcore/main.go`**

Replace the file contents with:

```go
// Package main is the Railcore proxy entrypoint.
//
// Sub-project #1: this binary supports `railcore proxy [--port N]
// [--data-dir PATH]`.
//
// Sub-project #2: this binary additionally supports `--block-on-detect`
// (or the RAILCORE_BLOCK_ON_DETECT=1 env var). When set, the secret-scan
// stage returns Block on any High-severity finding.
package main

import (
	"context"
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
	"railcore/internal/proxy"
	"railcore/internal/stage/secretscan"
	"railcore/internal/trust"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "proxy" {
		fmt.Fprintln(os.Stderr, "usage: railcore proxy [--port N] [--data-dir PATH] [--block-on-detect]")
		os.Exit(2)
	}

	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	port := fs.Int("port", defaultPort(), "TCP port to listen on (overrides RAILCORE_PORT)")
	dataDir := fs.String("data-dir", defaultDataDir(), "directory for CA + state")
	blockOnDetect := fs.Bool("block-on-detect", false, "return 403 on High-severity secret findings (default WARN only)")
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

	// Effective BlockOnDetect: CLI flag wins, env var is fallback.
	effectiveBlock := *blockOnDetect || os.Getenv("RAILCORE_BLOCK_ON_DETECT") == "1"

	chain := pipeline.NewChain().WithLogger(logger)
	chain.Register(secretscan.New(secretscan.Config{
		BlockOnDetect: effectiveBlock,
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
	logger.Info("railcore proxy listening",
		"addr", addr,
		"ca_path", caInst.RootPath(),
		"block_on_detect", effectiveBlock)

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

Changes from sub-project #1:
- `forwardStage` type and registration are GONE (it was a no-op).
- New flag `--block-on-detect`.
- `secretscan.New(...)` registration replaces `forwardStage`.
- Startup log line now reports `block_on_detect`.

- [ ] **Step 2: Build and smoke-test**

```bash
make build
./railcore proxy --port 19443 --data-dir /tmp/railcore-smoke-2 --block-on-detect &
sleep 1
kill %1 2>/dev/null
rm -rf /tmp/railcore-smoke-2
```

Expected: the proxy starts, logs `block_on_detect=true`, and shuts down cleanly.

- [ ] **Step 3: Run the full test suite to ensure nothing regressed**

```bash
go test -race -count=1 ./...
go vet ./...
```

Expected: all tests pass, vet clean.

- [ ] **Step 4: Commit**

```bash
git add cmd/railcore/main.go
git commit -m "feat(cmd): register secretscan stage and --block-on-detect flag; drop no-op forwardStage"
```

---

## Task 14: End-to-end integration tests

**Files:**
- Create: `test/integration/secretscan_test.go`

- [ ] **Step 1: Write the integration test**

Create `test/integration/secretscan_test.go`:

```go
// End-to-end tests for sub-project #2: a real http.Client driving real
// JSON request bodies through a real proxy with the secretscan stage
// registered, against a fake httptest upstream.
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
	"railcore/internal/proxy"
	"railcore/internal/stage/secretscan"
)

func setupSecretscan(t *testing.T, blockOnDetect bool) (client *http.Client, upstreamHits *int32, cleanup func()) {
	t.Helper()

	var hits int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	caInst, err := ca.GenerateOrLoad(t.TempDir())
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	chain := pipeline.NewChain()
	chain.Register(secretscan.New(secretscan.Config{BlockOnDetect: blockOnDetect}, nil))

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

func TestSecretscan_E2E_BlockOnAWSKey(t *testing.T) {
	client, upstreamHits, cleanup := setupSecretscan(t, true)
	defer cleanup()

	body := `{
		"model": "gpt-4o",
		"messages": [
			{"role": "user", "content": "review:\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
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
		t.Fatalf("upstream dialed %d times; want 0", got)
	}

	respBody, _ := io.ReadAll(resp.Body)
	var parsed struct {
		Error    string                   `json:"error"`
		Detector string                   `json:"detector"`
		Findings []map[string]interface{} `json:"findings"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		t.Fatalf("response not JSON: %v, body=%s", err, string(respBody))
	}
	if parsed.Detector != "secret-scan" {
		t.Errorf("detector = %q, want secret-scan", parsed.Detector)
	}
	if len(parsed.Findings) < 1 {
		t.Fatalf("expected >=1 finding, got %d; body=%s", len(parsed.Findings), string(respBody))
	}
	// Security invariant: matched secret bytes must not appear in the response.
	if strings.Contains(string(respBody), "AKIA") {
		t.Errorf("response body contains matched secret bytes: %s", string(respBody))
	}
}

func TestSecretscan_E2E_TestFixturePassesThrough(t *testing.T) {
	client, upstreamHits, cleanup := setupSecretscan(t, true)
	defer cleanup()

	// All-zeros suffix fails the entropy check; the AWS pattern must not fire.
	body := `{
		"model": "gpt-4o",
		"messages": [
			{"role": "user", "content": "fixture: AKIA0000000000000000"}
		]
	}`
	resp, err := client.Post("https://api.openai.com/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (test fixture should pass entropy filter)", resp.StatusCode)
	}
	if got := atomic.LoadInt32(upstreamHits); got != 1 {
		t.Fatalf("upstream dialed %d times; want 1", got)
	}
}

func TestSecretscan_E2E_WarnModeStillForwards(t *testing.T) {
	client, upstreamHits, cleanup := setupSecretscan(t, false /* warn mode */)
	defer cleanup()

	body := `{
		"model": "gpt-4o",
		"messages": [
			{"role": "user", "content": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}
		]
	}`
	resp, err := client.Post("https://api.openai.com/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (warn mode forwards)", resp.StatusCode)
	}
	if got := atomic.LoadInt32(upstreamHits); got != 1 {
		t.Fatalf("upstream dialed %d times; want 1", got)
	}
}
```

- [ ] **Step 2: Run the integration tests**

```bash
go test -race -count=1 ./test/integration/...
```

Expected: all four tests in the integration package pass (the original 2 from sub-project #1 plus the 3 new ones).

If `TestSecretscan_E2E_BlockOnAWSKey` fails with "want 0 upstream hits, got 1", check that the secretscan stage is registered BEFORE the proxy's request handler runs. The chain registration in `setupSecretscan` is correct; the issue would be the order of registration in `setupSecretscan` vs how the proxy invokes the chain.

- [ ] **Step 3: Commit**

```bash
git add test/integration/secretscan_test.go
git commit -m "test(integration): end-to-end secret-scan block + warn + fixture scenarios"
```

---

## Task 15: Manual acceptance test (real Claude Code)

**Files:** none modified; record result in spec at the end.

- [ ] **Step 1: Build the binary**

```bash
make build
```

- [ ] **Step 2: Start the proxy with --block-on-detect**

```bash
./railcore proxy --port 9443 --block-on-detect
```

Verify the startup log includes `block_on_detect=true`.

- [ ] **Step 3: Launch Claude Code through the proxy**

In a new terminal:

```bash
HTTPS_PROXY=http://127.0.0.1:9443 \
NODE_EXTRA_CA_CERTS=$HOME/.railcore/ca/ca.crt \
  claude
```

- [ ] **Step 4: Verify warn-style traffic works first**

Ask Claude Code an innocent question (`"what is 2+2"`). Confirm the proxy log shows `host=api.anthropic.com decision=continue status=200`.

- [ ] **Step 5: Trigger a block**

Paste a synthetic AWS key into a Claude Code prompt:

```
review this:
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

Expected:
- Claude Code receives a 403 response (visible as a request error in the UI).
- Proxy log contains a `WARN secretscan blocked` line with `patterns=[aws_access_key_id,...]` and the per-request completion line shows `decision=block status=403`.
- The matched bytes (`AKIAIOSFODNN7EXAMPLE`, etc.) appear in the proxy's stderr ONLY as part of the request body slog never directly — verify by grep'ing the proxy log for "AKIA" and confirming it doesn't appear in railcore's own log lines.

- [ ] **Step 6: Confirm warn mode works**

Stop the proxy. Restart without `--block-on-detect`:

```bash
./railcore proxy --port 9443
```

Re-trigger the same Claude Code prompt with the AWS key. Expected:
- Claude Code completes the request normally (Anthropic may refuse to echo the key in its response, but the request succeeds — that's Anthropic's policy, not ours).
- Proxy log shows `INFO secretscan findings high=2 ...` plus `decision=continue status=200`.

- [ ] **Step 7: Record the result in the spec doc**

Append a §11 Acceptance Result section to `docs/superpowers/specs/2026-05-17-request-parsing-and-secret-detection-design.md`:

```markdown
---

## 11. Acceptance Result

**Date:** YYYY-MM-DD (fill in)
**Tool exercised:** Claude Code via HTTPS_PROXY + NODE_EXTRA_CA_CERTS

**Block mode (`--block-on-detect`):**
- Synthetic AWS key in prompt → 403 returned to Claude Code.
- Proxy log: `WARN secretscan blocked patterns=[aws_access_key_id,aws_secret_access_key] decision=block status=403`.
- Matched bytes do not appear in any Railcore-generated log line.

**Warn mode (default):**
- Same prompt → 200 returned, request forwarded to Anthropic.
- Proxy log: `INFO secretscan findings high=2 medium=0 low=0 decision=continue status=200`.

**Status:** Pass. Sub-project #2 done definition §10 satisfied.
```

- [ ] **Step 8: Commit the acceptance record**

```bash
git add docs/superpowers/specs/2026-05-17-request-parsing-and-secret-detection-design.md
git commit -m "docs(spec): record sub-project #2 acceptance result"
```

---

## Self-Review Notes

After completing all tasks above:

1. **Spec coverage**:
   - §3 Repo Layout → Tasks 1 (detector pkg start), 7 (parser pkg), 11 (secretscan pkg)
   - §4.1 Parser → Tasks 7, 8, 9
   - §4.2 Detector → Tasks 1, 2, 3, 4, 5
   - §4.3 Secretscan stage → Task 11
   - §4.4 Proxy body caching → Task 10
   - §5 Data flow → Task 12 (403 body shape)
   - §6 Error handling → Tasks 11 (fail-open paths in stage), 12 (matched bytes not echoed)
   - §7.1 Unit tests → Tasks 1–11
   - §7.2 In-process integration → Tasks 10, 12
   - §7.3 End-to-end integration → Task 14
   - §7.4 Corpus FP test → Task 6
   - §7.5 Acceptance test → Task 15
   - §8 Pattern catalog → Task 4
   - §9 Configuration → Task 13
   - §10 Done definition → Tasks 13 (build+test), 14 (integration), 15 (acceptance)

2. **Placeholders:** none. All steps contain complete code or exact commands.

3. **Type consistency:**
   - `Severity` constants: `SeverityLow`/`SeverityMedium`/`SeverityHigh` used consistently across detector, secretscan, and proxy.
   - `Finding` fields: `Pattern string`, `Severity Severity`, `Offset int`, `Length int` — no `Match` field (intentional, per spec §4.2).
   - `Pattern` fields: `Name`, `Severity`, `Regex`, `EntropyThreshold`, `EntropySpan` — used in patterns.go and AddPattern test.
   - `ParsedRequest.Vendor` is `"openai"` / `"anthropic"`; `Endpoint` is `"chat.completions"` / `"messages"` — consistent across parser and secretscan.
   - `TextSegment.Index` is `-1` for Anthropic system prompts, `0..N` for messages array entries. Documented in §4.1 of the spec.
   - `pipeline.RequestCtx.Metadata` keys: `"request_id"` (from sub-project #1), `"body"` (Task 10), `"secretscan.findings"` (Task 11) — namespaced to avoid collisions.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-17-request-parsing-and-secret-detection.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
