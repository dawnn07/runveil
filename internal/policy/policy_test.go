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
