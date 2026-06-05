package parser

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func postReq(t *testing.T, path string) *http.Request {
	t.Helper()
	return httptest.NewRequest(http.MethodPost, "https://api.openai.com"+path, nil)
}

func TestOpenAIChat_ExtractsToolCallArguments(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "user", "content": "fix the bug"},
			{"role": "assistant", "tool_calls": [
				{"id": "call_1", "type": "function",
				 "function": {"name": "read_file",
				              "arguments": "{\"path\":\"/src/payments/charge.go\"}"}}
			]}
		]
	}`)
	parsed, err := parseOpenAIChat(body)
	if err != nil {
		t.Fatalf("parseOpenAIChat: %v", err)
	}
	if len(parsed.Texts) != 2 {
		t.Fatalf("Texts len = %d, want 2; got %+v", len(parsed.Texts), parsed.Texts)
	}
	if parsed.Texts[0].Role != "user" || parsed.Texts[0].Content != "fix the bug" || parsed.Texts[0].Index != 0 {
		t.Errorf("Texts[0] = %+v; want user/0/'fix the bug'", parsed.Texts[0])
	}
	if parsed.Texts[1].Role != "assistant" || parsed.Texts[1].Content != `{"path":"/src/payments/charge.go"}` || parsed.Texts[1].Index != 1 {
		t.Errorf("Texts[1] = %+v; want assistant/1/'{\"path\":\"/src/payments/charge.go\"}'", parsed.Texts[1])
	}
	tus := ExtractToolUses("api.openai.com", "/v1/chat/completions", body)
	if len(tus) != 1 {
		t.Fatalf("ExtractToolUses len = %d, want 1", len(tus))
	}
	if tus[0].Tool != "read_file" {
		t.Errorf("Tool = %q, want read_file", tus[0].Tool)
	}
	var got map[string]any
	if err := json.Unmarshal(tus[0].Input, &got); err != nil {
		t.Fatalf("Input not valid JSON: %v; raw=%s", err, string(tus[0].Input))
	}
	if got["path"] != "/src/payments/charge.go" {
		t.Errorf("Input.path = %v, want /src/payments/charge.go", got["path"])
	}
}

func TestOpenAIChat_ToolCallMalformedArgumentsPreservedRaw(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "assistant", "tool_calls": [
				{"id": "x", "type": "function",
				 "function": {"name": "read_file", "arguments": "not valid json"}}
			]}
		]
	}`)
	tus := ExtractToolUses("api.openai.com", "/v1/chat/completions", body)
	if len(tus) != 1 {
		t.Fatalf("len = %d, want 1 (we still emit the call with raw Input bytes)", len(tus))
	}
	if string(tus[0].Input) != "not valid json" {
		t.Errorf("Input = %q, want raw bytes", string(tus[0].Input))
	}
}

func TestOpenAIChat_ToolRoleMessageWithContentArray(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "tool", "tool_call_id": "x", "content": [
				{"type": "text", "text": "file contents here"}
			]}
		]
	}`)
	parsed, err := parseOpenAIChat(body)
	if err != nil {
		t.Fatalf("parseOpenAIChat: %v", err)
	}
	if len(parsed.Texts) != 1 {
		t.Fatalf("Texts len = %d, want 1", len(parsed.Texts))
	}
	if parsed.Texts[0].Role != "tool" || parsed.Texts[0].Content != "file contents here" {
		t.Errorf("Texts[0] = %+v; want role=tool content='file contents here'", parsed.Texts[0])
	}
}

func TestOpenAIChat_MultipleToolCallsInOneMessage(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "assistant", "tool_calls": [
				{"id": "a", "type": "function",
				 "function": {"name": "read_file", "arguments": "{\"path\":\"/a\"}"}},
				{"id": "b", "type": "function",
				 "function": {"name": "read_file", "arguments": "{\"path\":\"/b\"}"}}
			]}
		]
	}`)
	tus := ExtractToolUses("api.openai.com", "/v1/chat/completions", body)
	if len(tus) != 2 {
		t.Fatalf("len = %d, want 2", len(tus))
	}
}

func TestOpenAIChat_InlineObjectArgumentsHandled(t *testing.T) {
	// Non-standard client sends arguments as an inline JSON object.
	// Pre-fix this dropped ALL tool calls in the request due to typed
	// string Unmarshal failure. Post-fix the call is preserved with
	// Input holding the inline JSON.
	body := []byte(`{
		"messages": [
			{"role": "assistant", "tool_calls": [
				{"id": "x", "type": "function",
				 "function": {"name": "read_file",
				              "arguments": {"path": "/a"}}}
			]}
		]
	}`)
	tus := ExtractToolUses("api.openai.com", "/v1/chat/completions", body)
	if len(tus) != 1 {
		t.Fatalf("len = %d, want 1", len(tus))
	}
	var got map[string]any
	if err := json.Unmarshal(tus[0].Input, &got); err != nil {
		t.Fatalf("Input not valid JSON: %v; raw=%s", err, string(tus[0].Input))
	}
	if got["path"] != "/a" {
		t.Errorf("Input.path = %v, want /a", got["path"])
	}
}

func TestOpenAIChat_MixedTextAndToolCalls(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "assistant", "content": "thinking…",
			 "tool_calls": [
				{"id": "x", "type": "function",
				 "function": {"name": "read_file", "arguments": "{\"path\":\"/x\"}"}}
			]}
		]
	}`)
	parsed, err := parseOpenAIChat(body)
	if err != nil {
		t.Fatalf("parseOpenAIChat: %v", err)
	}
	if len(parsed.Texts) != 2 {
		t.Fatalf("Texts len = %d, want 2; got %+v", len(parsed.Texts), parsed.Texts)
	}
	if parsed.Texts[0].Role != "assistant" || parsed.Texts[0].Content != "thinking…" || parsed.Texts[0].Index != 0 {
		t.Errorf("Texts[0] = %+v; want assistant/0/'thinking…'", parsed.Texts[0])
	}
	if parsed.Texts[1].Role != "assistant" || parsed.Texts[1].Content != `{"path":"/x"}` || parsed.Texts[1].Index != 0 {
		t.Errorf("Texts[1] = %+v; want assistant/0/'{\"path\":\"/x\"}'", parsed.Texts[1])
	}
	tus := ExtractToolUses("api.openai.com", "/v1/chat/completions", body)
	if len(tus) != 1 {
		t.Fatalf("ExtractToolUses len = %d, want 1", len(tus))
	}
}

func TestOpenAIChat_ToolCallArgumentsScanned(t *testing.T) {
	body := []byte(`{"messages":[{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{\"token\":\"AKIAIOSFODNN7EXAMPLE\"}"}}]}]}`)
	parsed, err := ParseRequest("api.openai.com", postReq(t, "/v1/chat/completions"), body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var found *TextSegment
	for i := range parsed.Texts {
		if parsed.Texts[i].Content == `{"token":"AKIAIOSFODNN7EXAMPLE"}` {
			found = &parsed.Texts[i]
		}
	}
	if found == nil {
		t.Fatalf("decoded tool-call arguments not emitted as a segment; got %+v", parsed.Texts)
	}
	if found.Role != "assistant" || found.Index != 0 {
		t.Errorf("segment role/index = %s/%d, want assistant/0", found.Role, found.Index)
	}
}
