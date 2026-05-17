package secretscan

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"railcore/internal/pipeline"
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
