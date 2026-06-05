package parser

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func anthReq() (string, string) { return "api.anthropic.com", "/v1/messages" }

// red builds a single-span Redaction over a slice of content.
func red(role string, idx int, content string, off, ln int) Redaction {
	return Redaction{Role: role, Index: idx, Content: content, Spans: []Span{{Offset: off, Length: ln}}}
}

func TestRedact_StringContent(t *testing.T) {
	host, path := anthReq()
	body := []byte(`{"model":"claude-3","max_tokens":1024,"messages":[{"role":"user","content":"key AKIAIOSFODNN7EXAMPLE here"}]}`)
	out, err := RedactRequest(host, path, body, []Redaction{red("user", 0, "key AKIAIOSFODNN7EXAMPLE here", 4, 20)})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(string(out), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret still present: %s", out)
	}
	if !strings.Contains(string(out), "[REDACTED]") {
		t.Errorf("mask missing: %s", out)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if string(m["max_tokens"]) != "1024" {
		t.Errorf("max_tokens corrupted: %s", m["max_tokens"])
	}
	if string(m["model"]) != `"claude-3"` {
		t.Errorf("model corrupted: %s", m["model"])
	}
}

func TestRedact_TextBlockArray(t *testing.T) {
	host, path := anthReq()
	body := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"tok AKIAIOSFODNN7EXAMPLE"},{"type":"text","text":"safe"}]}]}`)
	out, err := RedactRequest(host, path, body, []Redaction{red("user", 0, "tok AKIAIOSFODNN7EXAMPLE", 4, 20)})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(string(out), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret still present: %s", out)
	}
	if !strings.Contains(string(out), `"safe"`) {
		t.Errorf("sibling text block lost: %s", out)
	}
}

func TestRedact_System(t *testing.T) {
	host, path := anthReq()
	body := []byte(`{"system":"sys AKIAIOSFODNN7EXAMPLE","messages":[{"role":"user","content":"hi"}]}`)
	out, err := RedactRequest(host, path, body, []Redaction{red("system", -1, "sys AKIAIOSFODNN7EXAMPLE", 4, 20)})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(string(out), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret still in system: %s", out)
	}
}

func TestRedact_MultiSpanNoDrift(t *testing.T) {
	host, path := anthReq()
	body := []byte(`{"messages":[{"role":"user","content":"AKIAIOSFODNN7EXAMPLE and AKIAIOSFODNN7EXAMPLE"}]}`)
	r := Redaction{Role: "user", Index: 0, Content: "AKIAIOSFODNN7EXAMPLE and AKIAIOSFODNN7EXAMPLE",
		Spans: []Span{{Offset: 0, Length: 20}, {Offset: 25, Length: 20}}}
	out, err := RedactRequest(host, path, body, []Redaction{r})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(string(out), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("a secret survived: %s", out)
	}
	if strings.Count(string(out), "[REDACTED]") != 2 {
		t.Errorf("want 2 masks, got: %s", out)
	}
}

func TestRedact_UnmatchedIsError(t *testing.T) {
	host, path := anthReq()
	body := []byte(`{"messages":[{"role":"user","content":"clean"}]}`)
	_, err := RedactRequest(host, path, body, []Redaction{red("user", 0, "not present here", 0, 3)})
	if err == nil {
		t.Error("expected error when a redaction matches nothing")
	}
}

func TestRedact_ToolUseTargetIsError(t *testing.T) {
	host, path := anthReq()
	body := []byte(`{"messages":[{"role":"assistant","content":[{"type":"tool_use","name":"Read","input":{"k":"AKIAIOSFODNN7EXAMPLE"}}]}]}`)
	content := `{"k":"AKIAIOSFODNN7EXAMPLE"}`
	_, err := RedactRequest(host, path, body, []Redaction{red("assistant", 0, content, 6, 20)})
	if err == nil {
		t.Error("expected error: tool_use input is not redactable in v1")
	}
}

func TestRedact_NonAnthropicIsError(t *testing.T) {
	r := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", nil)
	_, err := RedactRequest("api.openai.com", r.URL.Path, []byte(`{"messages":[]}`), []Redaction{red("user", 0, "x", 0, 1)})
	if err == nil {
		t.Error("expected error for non-Anthropic endpoint in v1")
	}
}
