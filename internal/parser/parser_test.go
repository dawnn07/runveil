package parser

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseRequest_UnknownHost(t *testing.T) {
	req := httptest.NewRequest("POST", "https://example.com/foo", nil)
	parsed, err := ParseRequest("example.com", req, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed != nil {
		t.Fatalf("expected nil for unknown host, got %+v", parsed)
	}
}

func TestParseRequest_UnknownPathOnKnownHost(t *testing.T) {
	req := httptest.NewRequest("POST", "https://api.openai.com/v1/embeddings", nil)
	parsed, err := ParseRequest("api.openai.com", req, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed != nil {
		t.Fatalf("expected nil for unknown path, got %+v", parsed)
	}
}

func TestParseRequest_NonPostMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "https://api.openai.com/v1/chat/completions", nil)
	parsed, err := ParseRequest("api.openai.com", req, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed != nil {
		t.Fatalf("expected nil for GET on chat.completions, got %+v", parsed)
	}
}

var _ = http.MethodPost

func TestParseOpenAI_BasicChat(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4o",
		"messages": [
			{"role": "system", "content": "you are helpful"},
			{"role": "user",   "content": "hello"},
			{"role": "assistant", "content": "hi"}
		]
	}`)
	req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", nil)
	parsed, err := ParseRequest("api.openai.com", req, body)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if parsed == nil {
		t.Fatal("parsed is nil; expected non-nil for OpenAI chat.completions")
	}
	if parsed.Vendor != "openai" || parsed.Endpoint != "chat.completions" {
		t.Fatalf("vendor/endpoint = %q/%q, want openai/chat.completions", parsed.Vendor, parsed.Endpoint)
	}
	if len(parsed.Texts) != 3 {
		t.Fatalf("Texts len = %d, want 3", len(parsed.Texts))
	}
	checks := []struct {
		i       int
		role    string
		content string
	}{
		{0, "system", "you are helpful"},
		{1, "user", "hello"},
		{2, "assistant", "hi"},
	}
	for _, c := range checks {
		seg := parsed.Texts[c.i]
		if seg.Role != c.role || seg.Content != c.content || seg.Index != c.i {
			t.Errorf("Texts[%d] = %+v, want role=%s content=%q index=%d",
				c.i, seg, c.role, c.content, c.i)
		}
	}
}

func TestParseOpenAI_MissingMessages(t *testing.T) {
	body := []byte(`{"model": "gpt-4o"}`)
	req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", nil)
	parsed, err := ParseRequest("api.openai.com", req, body)
	if err == nil {
		t.Fatalf("expected error for missing messages, got parsed=%+v", parsed)
	}
}

func TestParseOpenAI_MalformedJSON(t *testing.T) {
	body := []byte(`{`)
	req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", nil)
	parsed, err := ParseRequest("api.openai.com", req, body)
	if err == nil {
		t.Fatalf("expected error for malformed JSON, got parsed=%+v", parsed)
	}
}

func TestParseAnthropic_StringContent(t *testing.T) {
	body := []byte(`{
		"model": "claude-opus-4-7",
		"system": "you are a code reviewer",
		"messages": [
			{"role": "user", "content": "review this"}
		]
	}`)
	req := httptest.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	parsed, err := ParseRequest("api.anthropic.com", req, body)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if parsed == nil {
		t.Fatal("parsed is nil")
	}
	if parsed.Vendor != "anthropic" || parsed.Endpoint != "messages" {
		t.Fatalf("vendor/endpoint = %q/%q", parsed.Vendor, parsed.Endpoint)
	}
	if len(parsed.Texts) != 2 {
		t.Fatalf("Texts len = %d, want 2", len(parsed.Texts))
	}
	if parsed.Texts[0].Role != "system" || parsed.Texts[0].Content != "you are a code reviewer" || parsed.Texts[0].Index != -1 {
		t.Errorf("system seg = %+v", parsed.Texts[0])
	}
	if parsed.Texts[1].Role != "user" || parsed.Texts[1].Content != "review this" || parsed.Texts[1].Index != 0 {
		t.Errorf("user seg = %+v", parsed.Texts[1])
	}
}

func TestParseAnthropic_ContentBlocksArray(t *testing.T) {
	body := []byte(`{
		"model": "claude-opus-4-7",
		"messages": [
			{"role": "user", "content": [
				{"type": "text", "text": "first chunk"},
				{"type": "text", "text": "second chunk"}
			]}
		]
	}`)
	req := httptest.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	parsed, err := ParseRequest("api.anthropic.com", req, body)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if parsed == nil {
		t.Fatal("parsed is nil")
	}
	if len(parsed.Texts) != 2 {
		t.Fatalf("Texts len = %d, want 2", len(parsed.Texts))
	}
	if parsed.Texts[0].Content != "first chunk" || parsed.Texts[1].Content != "second chunk" {
		t.Errorf("flattened content = %+v", parsed.Texts)
	}
	if parsed.Texts[0].Role != "user" || parsed.Texts[1].Role != "user" {
		t.Errorf("expected both segments to inherit role=user; got %+v", parsed.Texts)
	}
}

func TestParseAnthropic_NoSystemNoMessages(t *testing.T) {
	body := []byte(`{"model": "claude-opus-4-7"}`)
	req := httptest.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	parsed, err := ParseRequest("api.anthropic.com", req, body)
	if err == nil {
		t.Fatalf("expected error for missing messages, got parsed=%+v", parsed)
	}
}

func TestParseAnthropic_MalformedJSON(t *testing.T) {
	body := []byte(`{not json`)
	req := httptest.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	parsed, err := ParseRequest("api.anthropic.com", req, body)
	if err == nil {
		t.Fatalf("expected error for malformed JSON, got parsed=%+v", parsed)
	}
}

func TestParseAnthropic_SystemAsArray(t *testing.T) {
	// Newer Anthropic API form: system is an array of content blocks.
	body := []byte(`{
		"model": "claude-opus-4-7",
		"system": [
			{"type": "text", "text": "you are a code reviewer"},
			{"type": "text", "text": "be terse"}
		],
		"messages": [
			{"role": "user", "content": "hello"}
		]
	}`)
	req := httptest.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	parsed, err := ParseRequest("api.anthropic.com", req, body)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if parsed == nil {
		t.Fatal("parsed is nil")
	}
	if len(parsed.Texts) != 3 {
		t.Fatalf("Texts len = %d, want 3; got %+v", len(parsed.Texts), parsed.Texts)
	}
	if parsed.Texts[0].Role != "system" || parsed.Texts[0].Content != "you are a code reviewer" {
		t.Errorf("first system seg = %+v", parsed.Texts[0])
	}
	if parsed.Texts[1].Role != "system" || parsed.Texts[1].Content != "be terse" {
		t.Errorf("second system seg = %+v", parsed.Texts[1])
	}
	if parsed.Texts[2].Role != "user" || parsed.Texts[2].Content != "hello" {
		t.Errorf("user seg = %+v", parsed.Texts[2])
	}
}

func TestParseAnthropic_ToolResultStringContent(t *testing.T) {
	body := []byte(`{
		"model": "claude-opus-4-7",
		"messages": [
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "abc", "content": "AKIAIOSFODNN7EXAMPLE"}
			]}
		]
	}`)
	req := httptest.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	parsed, err := ParseRequest("api.anthropic.com", req, body)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if len(parsed.Texts) != 1 || parsed.Texts[0].Content != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("tool_result string content not flattened: %+v", parsed.Texts)
	}
}

func TestParseAnthropic_ToolResultArrayContent(t *testing.T) {
	body := []byte(`{
		"model": "claude-opus-4-7",
		"messages": [
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "abc", "content": [
					{"type": "text", "text": "nested secret"}
				]}
			]}
		]
	}`)
	req := httptest.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	parsed, err := ParseRequest("api.anthropic.com", req, body)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if len(parsed.Texts) != 1 || parsed.Texts[0].Content != "nested secret" {
		t.Fatalf("tool_result array content not flattened: %+v", parsed.Texts)
	}
}
