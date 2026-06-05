package parser

import (
	"encoding/json"
	"fmt"
)

type openAIResponsesRequest struct {
	Instructions string          `json:"instructions"`
	Input        json.RawMessage `json:"input"`
}

func parseOpenAIResponses(body []byte) (*ParsedRequest, error) {
	var req openAIResponsesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("openai responses: %w", err)
	}

	var texts []TextSegment
	if req.Instructions != "" {
		texts = append(texts, TextSegment{
			Role:    "system",
			Index:   -1,
			Content: req.Instructions,
		})
	}

	// Input can be a string or an array.
	var inputStr string
	if err := json.Unmarshal(req.Input, &inputStr); err == nil {
		if inputStr != "" {
			texts = append(texts, TextSegment{
				Role:    "user",
				Index:   0,
				Content: inputStr,
			})
		}
	} else {
		var items []map[string]json.RawMessage
		if err := json.Unmarshal(req.Input, &items); err == nil {
			for i, item := range items {
				if roleRaw, ok := item["role"]; ok {
					var role string
					if err := json.Unmarshal(roleRaw, &role); err != nil || role == "" {
						continue
					}
					contentRaw, hasContent := item["content"]
					if !hasContent {
						continue
					}
					for _, seg := range flattenOpenAIContent(contentRaw) {
						if seg == "" {
							continue
						}
						texts = append(texts, TextSegment{
							Role:    role,
							Index:   i,
							Content: seg,
						})
					}
					continue
				}
				typeRaw, ok := item["type"]
				if !ok {
					continue
				}
				var itemType string
				if err := json.Unmarshal(typeRaw, &itemType); err != nil {
					continue
				}
				if itemType == "function_call_output" {
					if outRaw, ok := item["output"]; ok {
						var s string
						if err := json.Unmarshal(outRaw, &s); err == nil && s != "" {
							texts = append(texts, TextSegment{
								Role:    "tool",
								Index:   i,
								Content: s,
							})
						}
					}
				}
				if itemType == "function_call" {
					args := decodeOpenAIArguments(item["arguments"])
					if len(args) > 0 {
						texts = append(texts, TextSegment{
							Role:    "assistant",
							Index:   i,
							Content: string(args),
						})
					}
				}
			}
		}
	}

	return &ParsedRequest{
		Vendor:   "openai",
		Endpoint: "responses",
		Texts:    texts,
		Raw:      body,
	}, nil
}

// extractOpenAIResponsesToolUses walks input[] for type=="function_call"
// items. Same wire-format convention as chat completions: arguments is
// a JSON-encoded string whose decoded value is an object; we store the
// decoded raw bytes in ToolUse.Input.
func extractOpenAIResponsesToolUses(body []byte) []ToolUse {
	var req openAIResponsesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(req.Input, &items); err != nil {
		return nil
	}
	var out []ToolUse
	for i, item := range items {
		typeRaw, ok := item["type"]
		if !ok {
			continue
		}
		var itemType string
		if err := json.Unmarshal(typeRaw, &itemType); err != nil {
			continue
		}
		if itemType != "function_call" {
			continue
		}
		var name string
		if nameRaw, ok := item["name"]; ok {
			_ = json.Unmarshal(nameRaw, &name)
		}
		if name == "" {
			continue
		}
		out = append(out, ToolUse{
			Tool:         name,
			Input:        decodeOpenAIArguments(item["arguments"]),
			MessageIndex: i,
		})
	}
	return out
}
