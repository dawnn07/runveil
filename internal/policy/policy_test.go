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
