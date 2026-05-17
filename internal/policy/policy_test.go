package policy

import (
	"os"
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
		{"aws_", true},
		{"awsx_y", false},
		{"AWS_ACCESS_KEY_ID", false},
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
	p := mustPolicy(t, Rule{
		Name:   "block-high-aws",
		Match:  Match{Pattern: mustGlob(t, "aws_*"), Severity: sevPtr(detector.SeverityHigh)},
		Action: ActionBlock,
	})
	a, _ := p.Decide(detector.Finding{Pattern: "aws_access_key_id", Severity: detector.SeverityHigh})
	if a != ActionBlock {
		t.Errorf("aws+high → %v, want ActionBlock", a)
	}
	a, _ = p.Decide(detector.Finding{Pattern: "aws_access_key_id", Severity: detector.SeverityLow})
	if a != ActionWarn {
		t.Errorf("aws+low → %v, want ActionWarn", a)
	}
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

func TestLoadFromBytes_UnknownField(t *testing.T) {
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
		{"payments_old/x", false},
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
