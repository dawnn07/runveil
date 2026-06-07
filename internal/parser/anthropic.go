package parser

import (
	"encoding/json"
	"fmt"
)

type anthropicMessagesRequest struct {
	System   json.RawMessage    `json:"system"`
	Messages []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

func parseAnthropicMessages(body []byte) (*ParsedRequest, error) {
	var req anthropicMessagesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("anthropic messages: %w", err)
	}
	if req.Messages == nil {
		return nil, fmt.Errorf("anthropic messages: missing messages field")
	}

	var texts []TextSegment

	// system can be a string OR an array of content blocks.
	for _, seg := range flattenAnthropicContent(req.System) {
		if seg == "" {
			continue
		}
		texts = append(texts, TextSegment{
			Role:    "system",
			Index:   -1,
			Content: seg,
		})
	}

	for i, m := range req.Messages {
		for _, seg := range flattenAnthropicContent(m.Content) {
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
		Vendor:   "anthropic",
		Endpoint: "messages",
		Texts:    texts,
		Raw:      body,
	}, nil
}

// flattenAnthropicContent accepts a raw JSON value that may be:
//   - a JSON null or empty (returns nil)
//   - a JSON string (returns [string])
//   - a JSON array of content blocks (returns the text from each `{type:"text",text:"..."}`
//     block; non-text blocks are ignored, nested arrays inside tool_result
//     `content` are flattened recursively)
//
// Anything else returns nil.
func flattenAnthropicContent(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}

	// Try string form first.
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return []string{asString}
	}

	// Try array of generic blocks. We use map[string]any so we can pick
	// up `text` from text blocks and `content` from tool_result blocks
	// (which itself may be a string or array).
	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return nil
	}

	var out []string
	for _, b := range blocks {
		typeRaw, hasType := b["type"]
		var blockType string
		if hasType {
			_ = json.Unmarshal(typeRaw, &blockType)
		}

		switch blockType {
		case "text":
			if textRaw, ok := b["text"]; ok {
				var t string
				if err := json.Unmarshal(textRaw, &t); err == nil && t != "" {
					out = append(out, t)
				}
			}
		case "tool_result":
			// tool_result.content can be a string or a nested array of
			// content blocks. Flatten recursively.
			if contentRaw, ok := b["content"]; ok {
				out = append(out, flattenAnthropicContent(contentRaw)...)
			}
		case "tool_use":
			// tool_use has input as JSON object — scan its bytes as a
			// single segment so secret patterns can fire on tool inputs.
			if inputRaw, ok := b["input"]; ok && len(inputRaw) > 0 {
				out = append(out, string(inputRaw))
			}
		}
	}
	return out
}

// ToolUse is one structured tool_use block from an Anthropic messages
// request. Returned by ExtractToolUses for callers that need typed
// access to tool names alongside raw input JSON.
type ToolUse struct {
	Tool         string          // tool name (e.g., "Read", "Write")
	Input        json.RawMessage // raw input JSON; caller decodes per tool schema
	MessageIndex int             // position of the originating message in messages[]
}

// ExtractToolUses dispatches to vendor-specific extractors based on
// host + path. Returns nil for unknown hosts/paths.
func ExtractToolUses(host, path string, body []byte) []ToolUse {
	switch host {
	case "api.anthropic.com":
		if path != "/v1/messages" {
			return nil
		}
		return extractAnthropicToolUses(body)
	case "api.openai.com":
		switch path {
		case "/v1/chat/completions":
			return extractOpenAIChatToolUses(body)
		case "/v1/responses":
			return extractOpenAIResponsesToolUses(body)
		}
	}
	return nil
}

// extractAnthropicToolUses returns the tool_use content blocks from an
// Anthropic /v1/messages request body. Silently skips malformed blocks.
func extractAnthropicToolUses(body []byte) []ToolUse {
	var req anthropicMessagesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}

	var out []ToolUse
	for i, m := range req.Messages {
		var blocks []map[string]json.RawMessage
		if err := json.Unmarshal(m.Content, &blocks); err != nil {
			continue
		}
		for _, b := range blocks {
			typeRaw, ok := b["type"]
			if !ok {
				continue
			}
			var blockType string
			if err := json.Unmarshal(typeRaw, &blockType); err != nil {
				continue
			}
			if blockType != "tool_use" {
				continue
			}
			var name string
			if nameRaw, ok := b["name"]; ok {
				_ = json.Unmarshal(nameRaw, &name)
			}
			if name == "" {
				continue
			}
			inputRaw := b["input"]
			out = append(out, ToolUse{
				Tool:         name,
				Input:        inputRaw,
				MessageIndex: i,
			})
		}
	}
	return out
}
