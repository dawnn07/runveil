// Package parser extracts the prose payload from AI vendor request
// bodies into a normalized form (ParsedRequest). It is a leaf package:
// it must not import any other internal/ package.
//
// Each vendor file (openai.go, anthropic.go) handles one host's request
// schemas. The exported ParseRequest function dispatches by host + path.
package parser

import "net/http"

// ParsedRequest is the normalized view of an AI-vendor request.
type ParsedRequest struct {
	Vendor   string        // "openai" | "anthropic"
	Endpoint string        // "chat.completions" | "messages"
	Texts    []TextSegment // all scannable prose extracted from the body
	Raw      []byte        // original request body (kept for future redact action)
}

// TextSegment is one piece of prose pulled out of the request — a user
// message, system prompt, assistant turn, or tool result.
type TextSegment struct {
	Role    string // "user" | "assistant" | "system" | "tool"
	Index   int    // position in the original messages array (0-based)
	Content string // raw text content
}

// ParseRequest dispatches by host + method + path. Returns (nil, nil)
// when the request is not a known AI endpoint — callers should treat
// that as "nothing to scan" and pass through.
//
// Returns (nil, err) when a known endpoint has a malformed JSON body.
// Callers should fail-open on such errors.
func ParseRequest(host string, req *http.Request, body []byte) (*ParsedRequest, error) {
	if req.Method != http.MethodPost {
		return nil, nil
	}
	switch host {
	case "api.openai.com":
		switch req.URL.Path {
		case "/v1/chat/completions":
			return parseOpenAIChat(body)
		case "/v1/responses":
			return parseOpenAIResponses(body)
		}
	case "api.anthropic.com":
		if req.URL.Path == "/v1/messages" {
			return parseAnthropicMessages(body)
		}
	}
	return nil, nil
}

// parseOpenAIChat is implemented in openai.go.
// parseAnthropicMessages is implemented in anthropic.go.
