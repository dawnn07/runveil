package parser

import (
	"encoding/json"
	"fmt"
)

type openAIChatRequest struct {
	Messages []openAIMessage `json:"messages"`
}

type openAIMessage struct {
	Role      string           `json:"role"`
	Content   json.RawMessage  `json:"content"`
	ToolCalls []openAIToolCall `json:"tool_calls"`
}

type openAIToolCall struct {
	ID       string             `json:"id"`
	Type     string             `json:"type"`
	Function openAIFunctionCall `json:"function"`
}

type openAIFunctionCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func parseOpenAIChat(body []byte) (*ParsedRequest, error) {
	var req openAIChatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("openai chat: %w", err)
	}
	if req.Messages == nil {
		return nil, fmt.Errorf("openai chat: missing messages field")
	}

	var texts []TextSegment
	for i, m := range req.Messages {
		for _, seg := range flattenOpenAIContent(m.Content) {
			if seg == "" {
				continue
			}
			texts = append(texts, TextSegment{
				Role:    m.Role,
				Index:   i,
				Content: seg,
			})
		}
	}

	return &ParsedRequest{
		Vendor:   "openai",
		Endpoint: "chat.completions",
		Texts:    texts,
		Raw:      body,
	}, nil
}

// flattenOpenAIContent accepts a raw JSON value that may be:
//   - empty/null (returns nil)
//   - a JSON string (returns [string])
//   - a JSON array of typed parts; emits .text for parts where type is
//     "text", "input_text", or "output_text". Unknown part types are
//     skipped.
//
// Anything else returns nil.
func flattenOpenAIContent(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}

	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return []string{asString}
	}

	var parts []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &parts); err != nil {
		return nil
	}

	var out []string
	for _, p := range parts {
		typeRaw, hasType := p["type"]
		if !hasType {
			continue
		}
		var t string
		if err := json.Unmarshal(typeRaw, &t); err != nil {
			continue
		}
		switch t {
		case "text", "input_text", "output_text":
			if textRaw, ok := p["text"]; ok {
				var s string
				if err := json.Unmarshal(textRaw, &s); err == nil && s != "" {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

// extractOpenAIChatToolUses walks messages[].tool_calls and returns one
// ToolUse per type=="function" entry. Arguments is OpenAI's wire format:
// a JSON-encoded string whose decoded value is an object. We store that
// decoded string as raw JSON bytes in ToolUse.Input.
func extractOpenAIChatToolUses(body []byte) []ToolUse {
	var req openAIChatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}
	var out []ToolUse
	for i, m := range req.Messages {
		for _, tc := range m.ToolCalls {
			if tc.Type != "function" || tc.Function.Name == "" {
				continue
			}
			out = append(out, ToolUse{
				Tool:         tc.Function.Name,
				Input:        decodeOpenAIArguments(tc.Function.Arguments),
				MessageIndex: i,
			})
		}
	}
	return out
}

// decodeOpenAIArguments normalizes OpenAI's tool-call arguments field
// into raw JSON bytes. The wire format is officially a JSON-encoded
// string (e.g., "{\"path\":\"x\"}"); some clients send the inline object
// directly. This probes the string form first, falls back to the raw
// bytes. Malformed JSON is still passed through as-is so downstream
// consumers (policy engine, audit) can decide how to handle it.
func decodeOpenAIArguments(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var asStr string
	if err := json.Unmarshal(raw, &asStr); err == nil {
		return json.RawMessage(asStr)
	}
	return raw
}
