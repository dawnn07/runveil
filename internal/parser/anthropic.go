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

type anthropicContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
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
