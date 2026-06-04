package pathscan

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"runveil/internal/parser"
)

func mustParse(t *testing.T, host, body string) *parser.ParsedRequest {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "https://"+host+"/v1/messages", nil)
	parsed, err := parser.ParseRequest(host, req, []byte(body))
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	return parsed
}

func TestExtractPathEvents_UnknownVendorReturnsNil(t *testing.T) {
	body := `{"messages":[{"role":"user","content":"hello"}]}`
	parsed := &parser.ParsedRequest{
		Vendor: "some-future-vendor",
		Raw:    []byte(body),
	}
	got := ExtractPathEvents(parsed, []byte(body), "/v1/messages")
	if got != nil {
		t.Errorf("expected nil for unknown vendor, got %+v", got)
	}
}

func TestExtractPathEvents_NoToolUseReturnsEmpty(t *testing.T) {
	body := `{"model":"claude-opus-4-7","messages":[{"role":"user","content":"hello"}]}`
	parsed := mustParse(t, "api.anthropic.com", body)
	got := ExtractPathEvents(parsed, []byte(body), "/v1/messages")
	if len(got) != 0 {
		t.Errorf("expected empty for no tool_use, got %+v", got)
	}
}

func TestExtractPathEvents_ReadTool(t *testing.T) {
	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/src/payments/x.go"}}
			]}
		]
	}`
	parsed := mustParse(t, "api.anthropic.com", body)
	got := ExtractPathEvents(parsed, []byte(body), "/v1/messages")
	if len(got) != 1 {
		t.Fatalf("got %d, want 1: %+v", len(got), got)
	}
	if got[0].Tool != "Read" || got[0].Path != "/src/payments/x.go" || got[0].MessageIndex != 0 {
		t.Errorf("event = %+v", got[0])
	}
}

func TestExtractPathEvents_AllFourTools(t *testing.T) {
	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "a", "name": "Read", "input": {"file_path": "/a"}},
				{"type": "tool_use", "id": "b", "name": "Write", "input": {"file_path": "/b"}},
				{"type": "tool_use", "id": "c", "name": "Edit", "input": {"file_path": "/c"}},
				{"type": "tool_use", "id": "d", "name": "MultiEdit", "input": {"file_path": "/d"}}
			]}
		]
	}`
	parsed := mustParse(t, "api.anthropic.com", body)
	got := ExtractPathEvents(parsed, []byte(body), "/v1/messages")
	if len(got) != 4 {
		t.Fatalf("expected 4 events, got %d: %+v", len(got), got)
	}
	expectedTools := []string{"Read", "Write", "Edit", "MultiEdit"}
	expectedPaths := []string{"/a", "/b", "/c", "/d"}
	for i, want := range expectedTools {
		if got[i].Tool != want || got[i].Path != expectedPaths[i] {
			t.Errorf("[%d] = %+v, want tool=%s path=%s", i, got[i], want, expectedPaths[i])
		}
	}
}

func TestExtractPathEvents_IgnoresOtherTools(t *testing.T) {
	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "a", "name": "Bash", "input": {"command": "ls"}},
				{"type": "tool_use", "id": "b", "name": "Glob", "input": {"pattern": "**/*.go"}},
				{"type": "tool_use", "id": "c", "name": "Grep", "input": {"path": "/x", "pattern": "TODO"}},
				{"type": "tool_use", "id": "d", "name": "WebFetch", "input": {"url": "https://x"}},
				{"type": "tool_use", "id": "e", "name": "Task", "input": {"description": "do thing"}}
			]}
		]
	}`
	parsed := mustParse(t, "api.anthropic.com", body)
	got := ExtractPathEvents(parsed, []byte(body), "/v1/messages")
	if len(got) != 0 {
		t.Errorf("expected 0 events (unsupported tools), got %+v", got)
	}
}

func TestExtractPathEvents_MissingFilePathSkipped(t *testing.T) {
	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "a", "name": "Read", "input": {}},
				{"type": "tool_use", "id": "b", "name": "Read", "input": {"file_path": ""}},
				{"type": "tool_use", "id": "c", "name": "Read", "input": {"file_path": "/ok"}}
			]}
		]
	}`
	parsed := mustParse(t, "api.anthropic.com", body)
	got := ExtractPathEvents(parsed, []byte(body), "/v1/messages")
	if len(got) != 1 || got[0].Path != "/ok" {
		t.Errorf("got %+v, want one event with path=/ok", got)
	}
}

func TestExtractPathEvents_MessageIndexPreserved(t *testing.T) {
	body := `{
		"messages": [
			{"role": "user", "content": "hi"},
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "a", "name": "Read", "input": {"file_path": "/a"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "a", "content": "..."}
			]},
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "b", "name": "Write", "input": {"file_path": "/b"}}
			]}
		]
	}`
	parsed := mustParse(t, "api.anthropic.com", body)
	got := ExtractPathEvents(parsed, []byte(body), "/v1/messages")
	if len(got) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(got), got)
	}
	if got[0].MessageIndex != 1 {
		t.Errorf("[0].MessageIndex = %d, want 1", got[0].MessageIndex)
	}
	if got[1].MessageIndex != 3 {
		t.Errorf("[1].MessageIndex = %d, want 3", got[1].MessageIndex)
	}
}

func TestExtractPathEvents_OpenAIChatToolCalls(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "assistant", "tool_calls": [
				{"id": "x", "type": "function",
				 "function": {"name": "read_file",
				              "arguments": "{\"path\":\"/src/payments/x.go\"}"}}
			]}
		]
	}`)
	parsed := &parser.ParsedRequest{
		Vendor:   "openai",
		Endpoint: "chat.completions",
		Raw:      body,
	}
	events := ExtractPathEvents(parsed, body, "/v1/chat/completions")
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	if events[0].Path != "/src/payments/x.go" {
		t.Errorf("Path = %q, want /src/payments/x.go", events[0].Path)
	}
	if events[0].Tool != "read_file" {
		t.Errorf("Tool = %q, want read_file", events[0].Tool)
	}
}

func TestExtractPathEvents_OpenAIResponsesFunctionCall(t *testing.T) {
	body := []byte(`{
		"input": [
			{"type": "function_call", "name": "read_file",
			 "arguments": "{\"file_path\":\"/etc/passwd\"}"}
		]
	}`)
	parsed := &parser.ParsedRequest{
		Vendor:   "openai",
		Endpoint: "responses",
		Raw:      body,
	}
	events := ExtractPathEvents(parsed, body, "/v1/responses")
	if len(events) != 1 || events[0].Path != "/etc/passwd" {
		t.Errorf("events = %+v, want one path=/etc/passwd", events)
	}
}

func TestExtractPathEvents_OpenAIFilenameField(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "assistant", "tool_calls": [
				{"id": "x", "type": "function",
				 "function": {"name": "write_file",
				              "arguments": "{\"filename\":\"/tmp/o\",\"content\":\"x\"}"}}
			]}
		]
	}`)
	parsed := &parser.ParsedRequest{Vendor: "openai", Endpoint: "chat.completions", Raw: body}
	events := ExtractPathEvents(parsed, body, "/v1/chat/completions")
	if len(events) != 1 || events[0].Path != "/tmp/o" {
		t.Errorf("events = %+v, want one path=/tmp/o", events)
	}
}

func TestExtractPathEvents_OpenAIUnknownToolSkipped(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "assistant", "tool_calls": [
				{"id": "x", "type": "function",
				 "function": {"name": "unknown_tool",
				              "arguments": "{\"path\":\"/a\"}"}}
			]}
		]
	}`)
	parsed := &parser.ParsedRequest{Vendor: "openai", Endpoint: "chat.completions", Raw: body}
	events := ExtractPathEvents(parsed, body, "/v1/chat/completions")
	if len(events) != 0 {
		t.Errorf("events = %+v, want empty (unknown tool)", events)
	}
}
