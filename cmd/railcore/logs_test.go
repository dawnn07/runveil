package main

import (
	"strings"
	"testing"
	"time"

	"railcore/internal/audit"
)

func TestFormatRecord_Continue(t *testing.T) {
	r := audit.Record{
		Time:       time.Date(2026, 5, 17, 16, 33, 12, 0, time.UTC),
		RequestID:  "x",
		Host:       "api.openai.com",
		Method:     "POST",
		Path:       "/v1/chat/completions",
		Status:     200,
		DurationMs: 42,
		Decision:   "continue",
	}
	got := formatRecord(r)
	for _, want := range []string{"16:33:12", "✓", "POST", "api.openai.com", "/v1/chat/completions", "200", "42ms", "continue"} {
		if !strings.Contains(got, want) {
			t.Errorf("formatRecord output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "findings=") {
		t.Errorf("findings should be absent when none present; got %s", got)
	}
}

func TestFormatRecord_Block(t *testing.T) {
	r := audit.Record{
		Time:       time.Date(2026, 5, 17, 16, 33, 12, 0, time.UTC),
		RequestID:  "x",
		Host:       "api.anthropic.com",
		Method:     "POST",
		Path:       "/v1/messages",
		Status:     403,
		DurationMs: 38,
		Decision:   "block",
		Findings: []any{
			map[string]any{"detector": "path-scan", "rule": "block-payments"},
			map[string]any{"detector": "secret-scan", "rule": "block-aws"},
		},
	}
	got := formatRecord(r)
	for _, want := range []string{"✗", "block", "findings=2", "block-payments", "block-aws"} {
		if !strings.Contains(got, want) {
			t.Errorf("formatRecord output missing %q:\n%s", want, got)
		}
	}
}

func TestFormatRecord_NoVendor(t *testing.T) {
	r := audit.Record{
		Time:     time.Now(),
		Host:     "example.com",
		Method:   "GET",
		Path:     "/",
		Status:   200,
		Decision: "continue",
	}
	got := formatRecord(r)
	if got == "" {
		t.Error("formatRecord returned empty string")
	}
}

func TestParseAuditFile_SkipsMalformed(t *testing.T) {
	content := []byte(`{"time":"2026-05-17T16:33:12Z","request_id":"a","host":"h","method":"GET","path":"/","status":200,"bytes_in":0,"bytes_out":0,"duration_ms":1,"decision":"continue"}
not json
{"time":"2026-05-17T16:33:13Z","request_id":"b","host":"h","method":"GET","path":"/","status":200,"bytes_in":0,"bytes_out":0,"duration_ms":1,"decision":"continue"}
`)
	records, skipped := parseAuditBytes(content)
	if len(records) != 2 {
		t.Errorf("got %d records, want 2", len(records))
	}
	if skipped != 1 {
		t.Errorf("got %d skipped, want 1", skipped)
	}
}

func TestFormatEvent_PolicyReloadAccepted(t *testing.T) {
	line := []byte(`{"time":"2026-05-19T10:01:23Z","kind":"policy_reload","policy_path":"/x/policy.yaml","outcome":"accepted","rules_before":2,"rules_after":3}`)
	got := formatEvent(line)
	for _, want := range []string{"10:01:23", "⟳", "policy_reload", "/x/policy.yaml", "accepted", "2→3 rules"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestFormatEvent_PolicyReloadRejected(t *testing.T) {
	line := []byte(`{"time":"2026-05-19T10:01:45Z","kind":"policy_reload","policy_path":"/x/policy.yaml","outcome":"rejected","rules_before":3,"error":"bad glob"}`)
	got := formatEvent(line)
	for _, want := range []string{"⚠", "rejected", "rules_before=3", "err='bad glob'"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestLineIsEvent(t *testing.T) {
	cases := []struct {
		name string
		line string
		want bool
	}{
		{"request record (no kind)", `{"time":"2026-05-19T10:00:00Z","request_id":"r","host":"h"}`, false},
		{"policy_reload event", `{"time":"2026-05-19T10:00:00Z","kind":"policy_reload","outcome":"accepted"}`, true},
		{"empty kind value", `{"time":"2026-05-19T10:00:00Z","kind":""}`, false},
		{"malformed", `not json`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := lineIsEvent([]byte(tc.line)); got != tc.want {
				t.Errorf("lineIsEvent(%q) = %v, want %v", tc.line, got, tc.want)
			}
		})
	}
}
