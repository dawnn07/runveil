package parser

import (
	"encoding/json"
	"testing"
)

func TestResponses_StringInput(t *testing.T) {
	body := []byte(`{"model":"gpt-4.1","input":"hello world"}`)
	parsed, err := parseOpenAIResponses(body)
	if err != nil {
		t.Fatalf("parseOpenAIResponses: %v", err)
	}
	if parsed.Vendor != "openai" || parsed.Endpoint != "responses" {
		t.Fatalf("Vendor/Endpoint = %q/%q", parsed.Vendor, parsed.Endpoint)
	}
	if len(parsed.Texts) != 1 || parsed.Texts[0].Role != "user" || parsed.Texts[0].Content != "hello world" {
		t.Fatalf("Texts = %+v; want one user='hello world'", parsed.Texts)
	}
}

func TestResponses_ArrayInputBasic(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4.1",
		"input": [
			{"role": "user", "content": "fix the bug"},
			{"type": "function_call", "name": "read_file",
			 "arguments": "{\"path\":\"/src/payments/charge.go\"}",
			 "call_id": "fc_1"},
			{"type": "function_call_output", "call_id": "fc_1",
			 "output": "file body contents"}
		]
	}`)
	parsed, err := parseOpenAIResponses(body)
	if err != nil {
		t.Fatalf("parseOpenAIResponses: %v", err)
	}
	if len(parsed.Texts) != 2 {
		t.Fatalf("Texts len = %d, want 2; got %+v", len(parsed.Texts), parsed.Texts)
	}
	if parsed.Texts[0].Role != "user" || parsed.Texts[0].Content != "fix the bug" {
		t.Errorf("Texts[0] = %+v; want user 'fix the bug'", parsed.Texts[0])
	}
	if parsed.Texts[1].Role != "tool" || parsed.Texts[1].Content != "file body contents" {
		t.Errorf("Texts[1] = %+v; want tool 'file body contents'", parsed.Texts[1])
	}
	tus := extractOpenAIResponsesToolUses(body)
	if len(tus) != 1 {
		t.Fatalf("ToolUses len = %d, want 1", len(tus))
	}
	if tus[0].Tool != "read_file" {
		t.Errorf("Tool = %q, want read_file", tus[0].Tool)
	}
	var got map[string]any
	if err := json.Unmarshal(tus[0].Input, &got); err != nil {
		t.Errorf("Input not valid JSON: %v", err)
	} else if got["path"] != "/src/payments/charge.go" {
		t.Errorf("Input.path = %v, want /src/payments/charge.go", got["path"])
	}
}

func TestResponses_Instructions(t *testing.T) {
	body := []byte(`{"model":"gpt-4.1","instructions":"You are helpful.","input":"hi"}`)
	parsed, err := parseOpenAIResponses(body)
	if err != nil {
		t.Fatalf("parseOpenAIResponses: %v", err)
	}
	if len(parsed.Texts) != 2 {
		t.Fatalf("Texts len = %d, want 2 (system + user); got %+v", len(parsed.Texts), parsed.Texts)
	}
	if parsed.Texts[0].Role != "system" || parsed.Texts[0].Content != "You are helpful." {
		t.Errorf("Texts[0] = %+v; want system 'You are helpful.'", parsed.Texts[0])
	}
}

func TestResponses_ContentArrayInputText(t *testing.T) {
	body := []byte(`{
		"input": [
			{"role": "user", "content": [{"type": "input_text", "text": "hello"}]}
		]
	}`)
	parsed, err := parseOpenAIResponses(body)
	if err != nil {
		t.Fatalf("parseOpenAIResponses: %v", err)
	}
	if len(parsed.Texts) != 1 || parsed.Texts[0].Content != "hello" {
		t.Fatalf("Texts = %+v; want one TS 'hello'", parsed.Texts)
	}
}

func TestResponses_UnknownItemTypeIgnored(t *testing.T) {
	body := []byte(`{
		"input": [
			{"role": "user", "content": "hi"},
			{"type": "some_future_type", "foo": "bar"}
		]
	}`)
	parsed, err := parseOpenAIResponses(body)
	if err != nil {
		t.Fatalf("parseOpenAIResponses: %v", err)
	}
	if len(parsed.Texts) != 1 {
		t.Fatalf("Texts len = %d, want 1 (unknown item skipped)", len(parsed.Texts))
	}
}

func TestResponses_MalformedFunctionCallArguments(t *testing.T) {
	body := []byte(`{
		"input": [
			{"type": "function_call", "name": "read_file",
			 "arguments": "not valid json"}
		]
	}`)
	tus := extractOpenAIResponsesToolUses(body)
	if len(tus) != 1 {
		t.Fatalf("ToolUses len = %d, want 1", len(tus))
	}
	if string(tus[0].Input) != "not valid json" {
		t.Errorf("Input = %q, want raw bytes", string(tus[0].Input))
	}
}
