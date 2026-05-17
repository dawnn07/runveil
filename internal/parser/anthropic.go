package parser

import (
	"encoding/json"
	"fmt"
)

type anthropicMessagesRequest struct {
	System   string             `json:"system"`
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

	if req.System != "" {
		texts = append(texts, TextSegment{
			Role:    "system",
			Index:   -1,
			Content: req.System,
		})
	}

	for i, m := range req.Messages {
		var asString string
		if err := json.Unmarshal(m.Content, &asString); err == nil {
			if asString != "" {
				texts = append(texts, TextSegment{
					Role:    m.Role,
					Index:   i,
					Content: asString,
				})
			}
			continue
		}
		var blocks []anthropicContentBlock
		if err := json.Unmarshal(m.Content, &blocks); err != nil {
			return nil, fmt.Errorf("anthropic messages[%d]: content not string or array: %w", i, err)
		}
		for _, b := range blocks {
			if b.Type == "text" && b.Text != "" {
				texts = append(texts, TextSegment{
					Role:    m.Role,
					Index:   i,
					Content: b.Text,
				})
			}
		}
	}

	return &ParsedRequest{
		Vendor:   "anthropic",
		Endpoint: "messages",
		Texts:    texts,
		Raw:      body,
	}, nil
}
