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
