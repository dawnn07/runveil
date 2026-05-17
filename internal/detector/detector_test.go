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
