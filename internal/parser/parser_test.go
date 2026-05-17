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
