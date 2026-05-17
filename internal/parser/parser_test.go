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
