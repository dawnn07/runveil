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
