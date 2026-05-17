package parser

import (
	"encoding/json"
	"fmt"
)

type openAIChatRequest struct {
	Messages []openAIMessage `json:"messages"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func parseOpenAIChat(body []byte) (*ParsedRequest, error) {
	var req openAIChatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("openai chat: %w", err)
	}
	if req.Messages == nil {
		return nil, fmt.Errorf("openai chat: missing messages field")
	}

	texts := make([]TextSegment, 0, len(req.Messages))
	for i, m := range req.Messages {
		if m.Content == "" {
			continue
		}
		texts = append(texts, TextSegment{
			Role:    m.Role,
			Index:   i,
			Content: m.Content,
		})
	}

	return &ParsedRequest{
		Vendor:   "openai",
		Endpoint: "chat.completions",
		Texts:    texts,
		Raw:      body,
	}, nil
}
