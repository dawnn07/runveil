package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"railcore/internal/audit"
)

// scrape renders the Collector's /metrics output as a string.
func scrape(t *testing.T, c *Collector) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	c.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

func TestCollector_LogIncrementsRequests(t *testing.T) {
	c := NewCollector()
	c.Log(audit.Record{Decision: "continue"})
	c.Log(audit.Record{Decision: "block"})
	body := scrape(t, c)
	for _, want := range []string{
		`railcore_requests_total{decision="continue"} 1`,
		`railcore_requests_total{decision="block"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestCollector_LogObservesDuration(t *testing.T) {
	c := NewCollector()
	c.Log(audit.Record{Decision: "continue", DurationMs: 1500})
	body := scrape(t, c)
	for _, want := range []string{
		"railcore_request_duration_seconds_count 1",
		"railcore_request_duration_seconds_sum 1.5",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestCollector_LogCountsBytes(t *testing.T) {
	c := NewCollector()
	c.Log(audit.Record{Decision: "continue", BytesIn: 100, BytesOut: 200})
	body := scrape(t, c)
	for _, want := range []string{
		"railcore_request_bytes_in_total 100",
		"railcore_request_bytes_out_total 200",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestCollector_LogCountsFindings(t *testing.T) {
	c := NewCollector()
	c.Log(audit.Record{
		Decision: "block",
		Findings: []any{
			map[string]any{"detector": "path-scan", "rule": "block-payments"},
			map[string]any{"detector": "secret-scan", "rule": "block-aws"},
		},
	})
	body := scrape(t, c)
	for _, want := range []string{
		`railcore_findings_total{detector="path-scan"} 1`,
		`railcore_findings_total{detector="secret-scan"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestCollector_LogSkipsMalformedFindings(t *testing.T) {
	c := NewCollector()
	c.Log(audit.Record{
		Decision: "block",
		Findings: []any{
			"not-a-map",
			map[string]any{"rule": "no-detector-key"},
		},
	})
	body := scrape(t, c)
	if strings.Contains(body, "railcore_findings_total{") {
		t.Errorf("malformed findings should produce no findings series; got:\n%s", body)
	}
}

func TestCollector_EventCountsPolicyReloads(t *testing.T) {
	c := NewCollector()
	c.Event(audit.Event{Kind: "policy_reload", Outcome: "accepted"})
	c.Event(audit.Event{Kind: "policy_reload", Outcome: "rejected"})
	body := scrape(t, c)
	for _, want := range []string{
		`railcore_policy_reloads_total{outcome="accepted"} 1`,
		`railcore_policy_reloads_total{outcome="rejected"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestCollector_EventIgnoresOtherKinds(t *testing.T) {
	c := NewCollector()
	c.Event(audit.Event{Kind: "something_else", Outcome: "accepted"})
	body := scrape(t, c)
	if strings.Contains(body, "railcore_policy_reloads_total{") {
		t.Errorf("non-policy_reload event must not increment reloads; got:\n%s", body)
	}
}

func TestCollector_HandlerServesGoMetrics(t *testing.T) {
	c := NewCollector()
	body := scrape(t, c)
	if !strings.Contains(body, "go_goroutines") {
		t.Errorf("expected go_goroutines (Go collector) in output:\n%s", body)
	}
}
