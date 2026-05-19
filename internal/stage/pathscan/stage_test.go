package pathscan

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"railcore/internal/pipeline"
	"railcore/internal/policy"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newRC(t *testing.T, host, body, method, path string) *pipeline.RequestCtx {
	t.Helper()
	req := httptest.NewRequest(method, "https://"+host+path, strings.NewReader(body))
	req.Body = io.NopCloser(strings.NewReader(body))
	return &pipeline.RequestCtx{
		Req:       req,
		Host:      host,
		Metadata:  map[string]any{"request_id": "req-1", "body": []byte(body)},
		StartedAt: time.Now(),
	}
}

func mkPolicy(t *testing.T, yamlText string) *policy.Policy {
	t.Helper()
	p, err := policy.LoadFromBytes([]byte(yamlText))
	if err != nil {
		t.Fatalf("policy.LoadFromBytes: %v", err)
	}
	return p
}

func TestPathscan_NonAnthropicHostPassesThrough(t *testing.T) {
	pol := mkPolicy(t, `
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
`)
	s := New(Config{Policies: policy.NewProvider(pol)}, discardLogger())
	rc := newRC(t, "example.com", `{}`, http.MethodPost, "/anything")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Errorf("decision = %v, want Continue", dec)
	}
	if _, ok := rc.Metadata["pathscan.findings"]; ok {
		t.Errorf("expected no metadata for non-Anthropic")
	}
}

func TestPathscan_AnthropicWithNoToolUsePassesThrough(t *testing.T) {
	pol := mkPolicy(t, `
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
`)
	s := New(Config{Policies: policy.NewProvider(pol)}, discardLogger())
	body := `{"messages":[{"role":"user","content":"hello"}]}`
	rc := newRC(t, "api.anthropic.com", body, http.MethodPost, "/v1/messages")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Errorf("decision = %v, want Continue", dec)
	}
}

func TestPathscan_ReadToolBlockedByPolicy(t *testing.T) {
	pol := mkPolicy(t, `
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
`)
	s := New(Config{Policies: policy.NewProvider(pol)}, discardLogger())
	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/src/payments/charge.go"}}
			]}
		]
	}`
	rc := newRC(t, "api.anthropic.com", body, http.MethodPost, "/v1/messages")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Block {
		t.Fatalf("decision = %v, want Block", dec)
	}
	findings, ok := rc.Metadata["pathscan.findings"].([]PathFinding)
	if !ok || len(findings) != 1 {
		t.Fatalf("expected 1 finding in metadata, got %v", rc.Metadata["pathscan.findings"])
	}
	if findings[0].Tool != "Read" || findings[0].Path != "/src/payments/charge.go" || findings[0].Rule != "block-payments" {
		t.Errorf("finding = %+v", findings[0])
	}
}

func TestPathscan_ReadToolAllowedSuppressesFinding(t *testing.T) {
	pol := mkPolicy(t, `
version: 1
rules:
  - name: allow-payments-tests
    match: {path: "**/payments/test/**"}
    action: allow
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
`)
	s := New(Config{Policies: policy.NewProvider(pol)}, discardLogger())
	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/src/payments/test/fixture.go"}}
			]}
		]
	}`
	rc := newRC(t, "api.anthropic.com", body, http.MethodPost, "/v1/messages")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Errorf("decision = %v, want Continue (allowed)", dec)
	}
	findings, _ := rc.Metadata["pathscan.findings"].([]PathFinding)
	for _, f := range findings {
		if f.Path == "/src/payments/test/fixture.go" {
			t.Errorf("allowed path leaked into metadata: %+v", f)
		}
	}
}

func TestPathscan_NilPolicyContinues(t *testing.T) {
	s := New(Config{Policies: nil}, discardLogger())
	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/src/payments/x.go"}}
			]}
		]
	}`
	rc := newRC(t, "api.anthropic.com", body, http.MethodPost, "/v1/messages")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Errorf("decision = %v, want Continue (nil policy)", dec)
	}
	if _, ok := rc.Metadata["pathscan.findings"]; ok {
		t.Errorf("expected no metadata with nil policy")
	}
}

func TestPathFinding_MarshalJSON(t *testing.T) {
	f := PathFinding{
		Tool:         "Read",
		Path:         "/src/payments/charge.go",
		MessageIndex: 1,
		Rule:         "block-payments",
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(data)
	for _, want := range []string{
		`"detector":"path-scan"`,
		`"tool":"Read"`,
		`"path":"/src/payments/charge.go"`,
		`"message_index":1`,
		`"rule":"block-payments"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("expected %s in output; got %s", want, s)
		}
	}
}

func TestPathFinding_MarshalJSON_RuleOmittedWhenEmpty(t *testing.T) {
	f := PathFinding{
		Tool:         "Read",
		Path:         "/x",
		MessageIndex: 0,
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(data), `"rule"`) {
		t.Errorf("rule field should be omitted when empty; got %s", string(data))
	}
}

func TestPathscan_ReadToolWarnedStoresFinding(t *testing.T) {
	pol := mkPolicy(t, `
version: 1
rules:
  - name: warn-payments
    match: {path: "**/payments/**"}
    action: warn
`)
	s := New(Config{Policies: policy.NewProvider(pol)}, discardLogger())
	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "t1", "name": "Read",
				 "input": {"file_path": "/src/payments/x.go"}}
			]}
		]
	}`
	rc := newRC(t, "api.anthropic.com", body, http.MethodPost, "/v1/messages")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Fatalf("decision = %v, want Continue (warn never blocks)", dec)
	}
	findings, ok := rc.Metadata["pathscan.findings"].([]PathFinding)
	if !ok || len(findings) != 1 {
		t.Fatalf("expected 1 finding in metadata, got %v", rc.Metadata["pathscan.findings"])
	}
	if findings[0].Rule != "warn-payments" {
		t.Errorf("Rule = %q, want warn-payments", findings[0].Rule)
	}
}

func TestPathscan_MixedActionsBlockWins(t *testing.T) {
	// Two tool_use events: one matches allow, one matches block.
	// Expect Block decision; allowed event suppressed from metadata.
	pol := mkPolicy(t, `
version: 1
rules:
  - name: allow-tests
    match: {path: "**/test/**"}
    action: allow
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
`)
	s := New(Config{Policies: policy.NewProvider(pol)}, discardLogger())
	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "a", "name": "Read",
				 "input": {"file_path": "/src/test/fixture.go"}},
				{"type": "tool_use", "id": "b", "name": "Read",
				 "input": {"file_path": "/src/payments/charge.go"}}
			]}
		]
	}`
	rc := newRC(t, "api.anthropic.com", body, http.MethodPost, "/v1/messages")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Block {
		t.Fatalf("decision = %v, want Block (one event blocks)", dec)
	}
	findings, _ := rc.Metadata["pathscan.findings"].([]PathFinding)
	sawTest, sawPayments := false, false
	for _, f := range findings {
		if f.Path == "/src/test/fixture.go" {
			sawTest = true
		}
		if f.Path == "/src/payments/charge.go" {
			sawPayments = true
			if f.Rule != "block-payments" {
				t.Errorf("payments rule = %q, want block-payments", f.Rule)
			}
		}
	}
	if sawTest {
		t.Error("allowed test path should be suppressed from metadata")
	}
	if !sawPayments {
		t.Error("expected payments path in metadata")
	}
}

func TestStage_LiveSwapPicksUpNewPolicy(t *testing.T) {
	allowPolicy := mkPolicy(t, `
version: 1
rules:
  - name: warn-all
    match: {all: true}
    action: warn
`)
	blockPolicy := mkPolicy(t, `
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
`)

	provider := policy.NewProvider(allowPolicy)
	s := New(Config{Policies: provider}, discardLogger())

	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "name": "Read", "id": "x",
				 "input": {"file_path": "/src/payments/charge.go"}}
			]}
		]
	}`
	rc := newRC(t, "api.anthropic.com", body, http.MethodPost, "/v1/messages")

	dec, _ := s.Process(context.Background(), rc)
	if dec != pipeline.Continue {
		t.Errorf("first Process with allow policy: dec = %v, want Continue", dec)
	}

	// Live swap.
	provider.Set(blockPolicy)

	rc2 := newRC(t, "api.anthropic.com", body, http.MethodPost, "/v1/messages")
	dec2, _ := s.Process(context.Background(), rc2)
	if dec2 != pipeline.Block {
		t.Errorf("second Process with block policy: dec = %v, want Block", dec2)
	}
}
