package parser

import (
	"encoding/json"
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

func TestRedact_ToolUseInput(t *testing.T) {
	host, path := "api.anthropic.com", "/v1/messages"
	body := []byte(`{"messages":[{"role":"assistant","content":[{"type":"tool_use","name":"Read","input":{"k":"AKIAIOSFODNN7EXAMPLE"}}]}]}`)
	content := `{"k":"AKIAIOSFODNN7EXAMPLE"}`
	out, err := RedactRequest(host, path, body, []Redaction{red("assistant", 0, content, 6, 20)})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(string(out), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret survived in tool_use input: %s", out)
	}
	if !strings.Contains(string(out), "[REDACTED]") {
		t.Errorf("mask missing: %s", out)
	}
	if !json.Valid(out) {
		t.Errorf("output not valid JSON: %s", out)
	}
	if !strings.Contains(string(out), `"Read"`) {
		t.Errorf("tool name lost: %s", out)
	}
}

func TestRedact_ToolUseInvalidJSONIsError(t *testing.T) {
	host, path := "api.anthropic.com", "/v1/messages"
	body := []byte(`{"messages":[{"role":"assistant","content":[{"type":"tool_use","name":"f","input":{"k":"SECRET"}}]}]}`)
	content := `{"k":"SECRET"}`
	_, err := RedactRequest(host, path, body, []Redaction{red("assistant", 0, content, 5, 8)})
	if err == nil {
		t.Error("expected error: masking broke tool_use input JSON validity")
	}
}

func TestRedact_ToolResultNestedText(t *testing.T) {
	host, path := "api.anthropic.com", "/v1/messages"
	body := []byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","content":[{"type":"text","text":"out AKIAIOSFODNN7EXAMPLE"}]}]}]}`)
	out, err := RedactRequest(host, path, body, []Redaction{red("user", 0, "out AKIAIOSFODNN7EXAMPLE", 4, 20)})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(string(out), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret survived in nested tool_result text: %s", out)
	}
}

func TestRedact_ToolResultStringContent(t *testing.T) {
	host, path := "api.anthropic.com", "/v1/messages"
	body := []byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","content":"res AKIAIOSFODNN7EXAMPLE end"}]}]}`)
	out, err := RedactRequest(host, path, body, []Redaction{red("user", 0, "res AKIAIOSFODNN7EXAMPLE end", 4, 20)})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(string(out), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret survived in tool_result string content: %s", out)
	}
}

func TestRedact_NonAnthropicIsError(t *testing.T) {
	_, err := RedactRequest("api.openai.com", "/v1/embeddings", []byte(`{"input":"x"}`), []Redaction{red("user", 0, "x", 0, 1)})
	if err == nil {
		t.Error("expected error for an unsupported endpoint")
	}
}

func TestRedact_OpenAIChat_StringContent(t *testing.T) {
	host, path := "api.openai.com", "/v1/chat/completions"
	body := []byte(`{"model":"gpt-4o","temperature":0.7,"messages":[{"role":"user","content":"key AKIAIOSFODNN7EXAMPLE end"}]}`)
	out, err := RedactRequest(host, path, body, []Redaction{red("user", 0, "key AKIAIOSFODNN7EXAMPLE end", 4, 20)})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(string(out), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret survived: %s", out)
	}
	if !strings.Contains(string(out), "[REDACTED]") {
		t.Errorf("mask missing: %s", out)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if string(m["temperature"]) != "0.7" {
		t.Errorf("temperature corrupted: %s", m["temperature"])
	}
}

func TestRedact_OpenAIChat_InputTextPart(t *testing.T) {
	host, path := "api.openai.com", "/v1/chat/completions"
	body := []byte(`{"messages":[{"role":"user","content":[{"type":"input_text","text":"tok AKIAIOSFODNN7EXAMPLE"},{"type":"image_url","image_url":{"url":"http://x"}}]}]}`)
	out, err := RedactRequest(host, path, body, []Redaction{red("user", 0, "tok AKIAIOSFODNN7EXAMPLE", 4, 20)})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(string(out), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret survived: %s", out)
	}
	if !strings.Contains(string(out), "image_url") {
		t.Errorf("non-text part lost: %s", out)
	}
}

func TestRedact_OpenAIChat_ToolArgsTargetIsError(t *testing.T) {
	host, path := "api.openai.com", "/v1/chat/completions"
	body := []byte(`{"messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{\"k\":\"AKIAIOSFODNN7EXAMPLE\"}"}}]}]}`)
	_, err := RedactRequest(host, path, body, []Redaction{red("assistant", 0, `{"k":"AKIAIOSFODNN7EXAMPLE"}`, 6, 20)})
	if err == nil {
		t.Error("expected fail-closed error: tool_calls arguments not redactable here")
	}
}

func TestRedact_OpenAIResponses_Instructions(t *testing.T) {
	host, path := "api.openai.com", "/v1/responses"
	body := []byte(`{"instructions":"sys AKIAIOSFODNN7EXAMPLE","input":"hello"}`)
	out, err := RedactRequest(host, path, body, []Redaction{red("system", -1, "sys AKIAIOSFODNN7EXAMPLE", 4, 20)})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(string(out), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret survived in instructions: %s", out)
	}
}

func TestRedact_OpenAIResponses_InputString(t *testing.T) {
	host, path := "api.openai.com", "/v1/responses"
	body := []byte(`{"input":"key AKIAIOSFODNN7EXAMPLE end"}`)
	out, err := RedactRequest(host, path, body, []Redaction{red("user", 0, "key AKIAIOSFODNN7EXAMPLE end", 4, 20)})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(string(out), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret survived in input: %s", out)
	}
}

func TestRedact_OpenAIResponses_InputArrayItem(t *testing.T) {
	host, path := "api.openai.com", "/v1/responses"
	body := []byte(`{"input":[{"role":"user","content":[{"type":"input_text","text":"tok AKIAIOSFODNN7EXAMPLE"}]}]}`)
	out, err := RedactRequest(host, path, body, []Redaction{red("user", 0, "tok AKIAIOSFODNN7EXAMPLE", 4, 20)})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(string(out), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret survived in input item: %s", out)
	}
}

func TestRedact_OpenAIResponses_FunctionCallOutput(t *testing.T) {
	host, path := "api.openai.com", "/v1/responses"
	body := []byte(`{"input":[{"type":"function_call_output","output":"res AKIAIOSFODNN7EXAMPLE done"}]}`)
	out, err := RedactRequest(host, path, body, []Redaction{red("tool", 0, "res AKIAIOSFODNN7EXAMPLE done", 4, 20)})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(string(out), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret survived in function_call_output: %s", out)
	}
}
