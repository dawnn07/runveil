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
