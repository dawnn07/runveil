package secretscan

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

	"runveil/internal/detector"
	"runveil/internal/pipeline"
	"runveil/internal/policy"
)

func newRC(t *testing.T, host string, body string, method, path string) *pipeline.RequestCtx {
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

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestSecretscan_NonAIHostPassesThrough(t *testing.T) {
	s := New(Config{}, discardLogger())
	rc := newRC(t, "example.com", `{"x":1}`, http.MethodPost, "/anything")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Fatalf("decision = %v, want Continue", dec)
	}
	if _, ok := rc.Metadata["secretscan.findings"]; ok {
		t.Fatalf("expected no findings metadata for non-AI host")
	}
}

func TestSecretscan_AIRequestNoFindingsContinues(t *testing.T) {
	s := New(Config{}, discardLogger())
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hello world"}]}`
	rc := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Fatalf("decision = %v, want Continue", dec)
	}
}

func TestSecretscan_AIRequestWithAWSKeyWarnModeContinues(t *testing.T) {
	s := New(Config{BlockOnDetect: false}, discardLogger())
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"key: AKIAIOSFODNN7EXAMPLE here"}]}`
	rc := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Fatalf("decision = %v, want Continue (warn mode)", dec)
	}
	findings, ok := rc.Metadata["secretscan.findings"].([]EnrichedFinding)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected findings in metadata, got %v", rc.Metadata["secretscan.findings"])
	}
}

func TestSecretscan_AIRequestWithAWSKeyBlockModeBlocks(t *testing.T) {
	s := New(Config{BlockOnDetect: true}, discardLogger())
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"key: AKIAIOSFODNN7EXAMPLE here"}]}`
	rc := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Block {
		t.Fatalf("decision = %v, want Block", dec)
	}
}

func TestSecretscan_MediumOnlyDoesNotBlock(t *testing.T) {
	s := New(Config{BlockOnDetect: true}, discardLogger())
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature_xyz_at_least_ten_chars"
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"my jwt: ` + jwt + `"}]}`
	rc := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Fatalf("decision = %v, want Continue (medium never blocks)", dec)
	}
}

func TestSecretscan_AnthropicSystemPromptScanned(t *testing.T) {
	s := New(Config{BlockOnDetect: true}, discardLogger())
	body := `{"model":"claude-opus-4-7","system":"github: ghp_abcdefghijklmnopqrstuvwxyz0123456789","messages":[{"role":"user","content":"hi"}]}`
	rc := newRC(t, "api.anthropic.com", body, http.MethodPost, "/v1/messages")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Block {
		t.Fatalf("decision = %v, want Block (system prompt contains GitHub PAT)", dec)
	}
}

func TestSecretscan_MalformedJSONContinues(t *testing.T) {
	s := New(Config{BlockOnDetect: true}, discardLogger())
	rc := newRC(t, "api.openai.com", `{not json`, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Fatalf("decision = %v, want Continue (fail-open on parser errors)", dec)
	}
}

func TestEnrichedFinding_MarshalJSON_RuleIncludedWhenSet(t *testing.T) {
	ef := EnrichedFinding{
		Finding:      detector.Finding{Pattern: "aws_access_key_id", Severity: detector.SeverityHigh},
		Role:         "user",
		MessageIndex: 0,
		Rule:         "block-aws",
	}
	data, err := json.Marshal(ef)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), `"rule":"block-aws"`) {
		t.Errorf("expected rule field in output; got %s", string(data))
	}
}

func TestEnrichedFinding_MarshalJSON_RuleOmittedWhenEmpty(t *testing.T) {
	ef := EnrichedFinding{
		Finding:      detector.Finding{Pattern: "aws_access_key_id", Severity: detector.SeverityHigh},
		Role:         "user",
		MessageIndex: 0,
	}
	data, err := json.Marshal(ef)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(data), `"rule"`) {
		t.Errorf("rule field should be omitted when empty; got %s", string(data))
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

func TestSecretscan_PolicyBlockOnAWS(t *testing.T) {
	pol := mkPolicy(t, `
version: 1
rules:
  - name: block-aws
    match: {pattern: aws_*}
    action: block
  - name: default
    match: {all: true}
    action: warn
`)
	s := New(Config{Policies: policy.NewProvider(pol)}, discardLogger())
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"key: AKIAIOSFODNN7EXAMPLE"}]}`
	rc := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Block {
		t.Fatalf("decision = %v, want Block", dec)
	}
	findings, ok := rc.Metadata["secretscan.findings"].([]EnrichedFinding)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected findings in metadata, got %v", rc.Metadata["secretscan.findings"])
	}
	if findings[0].Rule != "block-aws" {
		t.Errorf("Rule = %q, want block-aws", findings[0].Rule)
	}
}

func TestSecretscan_PolicyAllowSuppressesBlock(t *testing.T) {
	pol := mkPolicy(t, `
version: 1
rules:
  - name: allow-example
    match: {pattern: aws_access_key_id}
    action: allow
  - name: block-aws
    match: {pattern: aws_*}
    action: block
`)
	s := New(Config{BlockOnDetect: true, Policies: policy.NewProvider(pol)}, discardLogger())
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"key: AKIAIOSFODNN7EXAMPLE"}]}`
	rc := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Fatalf("decision = %v, want Continue (allow precedes block)", dec)
	}
	findings, _ := rc.Metadata["secretscan.findings"].([]EnrichedFinding)
	for _, f := range findings {
		if f.Finding.Pattern == "aws_access_key_id" {
			t.Errorf("allowed finding leaked into metadata: %+v", f)
		}
	}
}

func TestSecretscan_PolicyWarnDoesNotBlock(t *testing.T) {
	pol := mkPolicy(t, `
version: 1
rules:
  - name: warn-all
    match: {all: true}
    action: warn
`)
	s := New(Config{Policies: policy.NewProvider(pol)}, discardLogger())
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"key: AKIAIOSFODNN7EXAMPLE"}]}`
	rc := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Fatalf("decision = %v, want Continue (warn never blocks)", dec)
	}
	findings, ok := rc.Metadata["secretscan.findings"].([]EnrichedFinding)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected findings, got %v", rc.Metadata["secretscan.findings"])
	}
	if findings[0].Rule != "warn-all" {
		t.Errorf("Rule = %q, want warn-all", findings[0].Rule)
	}
}

func TestSecretscan_PolicyMixedActions(t *testing.T) {
	pol := mkPolicy(t, `
version: 1
rules:
  - name: allow-aws
    match: {pattern: aws_*}
    action: allow
  - name: block-github
    match: {pattern: github_*}
    action: block
`)
	s := New(Config{Policies: policy.NewProvider(pol)}, discardLogger())
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"AKIAIOSFODNN7EXAMPLE and ghp_abcdefghijklmnopqrstuvwxyz0123456789"}]}`
	rc := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Block {
		t.Fatalf("decision = %v, want Block (github blocks even though aws allowed)", dec)
	}
	findings, _ := rc.Metadata["secretscan.findings"].([]EnrichedFinding)
	sawGithub, sawAWS := false, false
	for _, f := range findings {
		if f.Finding.Pattern == "github_pat_classic" {
			sawGithub = true
			if f.Rule != "block-github" {
				t.Errorf("github rule = %q, want block-github", f.Rule)
			}
		}
		if f.Finding.Pattern == "aws_access_key_id" {
			sawAWS = true
		}
	}
	if !sawGithub {
		t.Error("expected github finding in metadata")
	}
	if sawAWS {
		t.Error("allowed aws finding should be absent from metadata")
	}
}

func TestSecretscan_EmptyPolicyDefaultsToWarn(t *testing.T) {
	pol := &policy.Policy{Version: 1}
	s := New(Config{Policies: policy.NewProvider(pol)}, discardLogger())
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"key: AKIAIOSFODNN7EXAMPLE"}]}`
	rc := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")
	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec != pipeline.Continue {
		t.Fatalf("decision = %v, want Continue (empty rules → warn default)", dec)
	}
}

func TestStage_LiveSwapPicksUpNewPolicy(t *testing.T) {
	warnPolicy := mkPolicy(t, `
version: 1
rules:
  - name: warn-aws
    match: {pattern: aws_*}
    action: warn
`)
	blockPolicy := mkPolicy(t, `
version: 1
rules:
  - name: block-aws
    match: {pattern: aws_*}
    action: block
`)

	provider := policy.NewProvider(warnPolicy)
	s := New(Config{Policies: provider}, discardLogger())

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"key: AKIAIOSFODNN7EXAMPLE"}]}`
	rc := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")

	dec, _ := s.Process(context.Background(), rc)
	if dec != pipeline.Continue {
		t.Errorf("warn policy: dec = %v, want Continue", dec)
	}

	provider.Set(blockPolicy)

	rc2 := newRC(t, "api.openai.com", body, http.MethodPost, "/v1/chat/completions")
	dec2, _ := s.Process(context.Background(), rc2)
	if dec2 != pipeline.Block {
		t.Errorf("block policy: dec = %v, want Block", dec2)
	}
}

func TestEnrichedFinding_MarshalJSON_IncludesDetector(t *testing.T) {
	ef := EnrichedFinding{
		Finding:      detector.Finding{Pattern: "aws_access_key_id", Severity: detector.SeverityHigh},
		Role:         "user",
		MessageIndex: 0,
	}
	data, err := json.Marshal(ef)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), `"detector":"secret-scan"`) {
		t.Errorf("expected detector field in output; got %s", string(data))
	}
}

func TestProcess_RedactModifiesBody(t *testing.T) {
	pol, err := policy.LoadFromBytes([]byte(`
version: 1
rules:
  - name: redact-aws
    match: {pattern: aws_*}
    action: redact
`))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	s := New(Config{Policies: policy.NewProvider(pol)}, discardLogger())

	body := `{"messages":[{"role":"user","content":"key AKIAIOSFODNN7EXAMPLE end"}]}`
	rc := newRC(t, "api.anthropic.com", body, http.MethodPost, "/v1/messages")

	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process err = %v", err)
	}
	if dec != pipeline.Modify {
		t.Fatalf("decision = %v, want Modify", dec)
	}
	got, _ := rc.Metadata["body"].([]byte)
	if strings.Contains(string(got), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret not redacted from metadata body: %s", got)
	}
	if !strings.Contains(string(got), "[REDACTED]") {
		t.Errorf("mask missing: %s", got)
	}
}

func TestProcess_RedactToolUseModifies(t *testing.T) {
	pol, err := policy.LoadFromBytes([]byte(`
version: 1
rules:
  - name: redact-aws
    match: {pattern: aws_*}
    action: redact
`))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	s := New(Config{Policies: policy.NewProvider(pol)}, discardLogger())

	// A secret inside a tool_use input is now redacted (not blocked).
	body := `{"messages":[{"role":"assistant","content":[{"type":"tool_use","name":"Read","input":{"k":"AKIAIOSFODNN7EXAMPLE"}}]}]}`
	rc := newRC(t, "api.anthropic.com", body, http.MethodPost, "/v1/messages")

	dec, err := s.Process(context.Background(), rc)
	if err != nil {
		t.Fatalf("Process err = %v", err)
	}
	if dec != pipeline.Modify {
		t.Fatalf("decision = %v, want Modify", dec)
	}
	got, _ := rc.Metadata["body"].([]byte)
	if strings.Contains(string(got), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret not redacted from tool_use input: %s", got)
	}
	if !strings.Contains(string(got), "[REDACTED]") {
		t.Errorf("mask missing: %s", got)
	}
}
