package policy

import "testing"

func TestParseAction_Redact(t *testing.T) {
	a, err := parseAction("redact")
	if err != nil {
		t.Fatalf("parseAction(redact) err = %v", err)
	}
	if a != ActionRedact {
		t.Errorf("parseAction(redact) = %v, want ActionRedact", a)
	}
}
