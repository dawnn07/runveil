# Cursor BYOK + OpenAI tool_calls Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Cursor (BYOK mode) work end-to-end through Railcore with policy parity between OpenAI and Anthropic backends.

**Architecture:** Add `tool_calls` extraction + content-array handling to the existing OpenAI chat parser; add a new parser for OpenAI `/v1/responses`; widen `ExtractToolUses` signature to `(host, path, body)` and propagate; widen pathscan to allow OpenAI vendors, multiple file-path field names, and OpenAI tool name conventions. No new dependencies. Documentation file `docs/cursor-setup.md` covers the user-facing config.

**Tech Stack:** Go 1.25 stdlib (`encoding/json`). Existing internal packages: `internal/parser/`, `internal/pathscan/`. New doc file. No changes to `internal/proxy/`, `internal/audit/`, `internal/policy/`, `cmd/railcore/`.

**Spec:** [`docs/superpowers/specs/2026-05-18-cursor-byok-and-openai-tool-calls-design.md`](../specs/2026-05-18-cursor-byok-and-openai-tool-calls-design.md)

---

## File Map

| File | Purpose |
|---|---|
| `internal/parser/openai.go` | **Modify:** widen `openAIMessage` content to `json.RawMessage`, surface `tool_calls`, add OpenAI extractor helpers, share `flattenOpenAIContent`. |
| `internal/parser/openai_responses.go` | **Create:** `parseOpenAIResponses` + `extractOpenAIResponsesToolUses` covering `instructions`, string-or-array `input`, `function_call` / `function_call_output` items. |
| `internal/parser/parser.go` | **Modify:** dispatch `/v1/responses`; widen `ExtractToolUses` signature to `(host, path, body)`. |
| `internal/parser/anthropic.go` | **Modify:** update `ExtractToolUses` signature; logic unchanged. |
| `internal/parser/openai_test.go` | **Modify:** append 5 tests for new chat-completions behavior. |
| `internal/parser/openai_responses_test.go` | **Create:** 6 tests for the new endpoint. |
| `internal/parser/parser_test.go` | **Modify:** append dispatcher coverage for `/v1/responses`. |
| `internal/pathscan/pathscan.go` | **Modify:** vendor gate, field-name candidates, OpenAI tool allowlist. |
| `internal/pathscan/pathscan_test.go` | **Modify:** append OpenAI-shaped fixtures. |
| `internal/stage/pathscan/*` (callers if any) | **Modify if needed:** thread `path` through to `ExtractToolUses`. |
| `test/integration/cursor_test.go` | **Create:** one end-to-end test simulating Cursor BYOK + OpenAI Composer reading a blocked path. |
| `docs/cursor-setup.md` | **Create:** ≈80-line user-facing setup guide. |
| `docs/superpowers/specs/2026-05-18-cursor-byok-and-openai-tool-calls-design.md` | **Modify (Task 8 only):** append §11 Acceptance Result. |

**Dependency direction:** unchanged. `internal/parser` stays a leaf. `internal/pathscan` already depends on `internal/parser`. No new edges.

---

## Task 1: OpenAI chat completions — `tool_calls` + content arrays

**Files:**
- Modify: `internal/parser/openai.go`
- Modify: `internal/parser/openai_test.go`

- [ ] **Step 1: Read the current openai.go and openai_test.go to confirm starting state**

```bash
sed -n '1,50p' internal/parser/openai.go
wc -l internal/parser/openai_test.go
```

Expected: openai.go ends around line 44; openai_test.go is the existing test file (sub-project #2 vintage). You'll be appending tests, not rewriting.

- [ ] **Step 2: Append the failing tests to `internal/parser/openai_test.go`**

```go

func TestOpenAIChat_ExtractsToolCallArguments(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "user", "content": "fix the bug"},
			{"role": "assistant", "tool_calls": [
				{"id": "call_1", "type": "function",
				 "function": {"name": "read_file",
				              "arguments": "{\"path\":\"/src/payments/charge.go\"}"}}
			]}
		]
	}`)
	parsed, err := parseOpenAIChat(body)
	if err != nil {
		t.Fatalf("parseOpenAIChat: %v", err)
	}
	// Text segments: only the user "fix the bug" string.
	if len(parsed.Texts) != 1 || parsed.Texts[0].Content != "fix the bug" {
		t.Fatalf("Texts = %+v; want [user='fix the bug']", parsed.Texts)
	}
	// Tool uses come from ExtractToolUses.
	tus := ExtractToolUses("api.openai.com", "/v1/chat/completions", body)
	if len(tus) != 1 {
		t.Fatalf("ExtractToolUses len = %d, want 1", len(tus))
	}
	if tus[0].Tool != "read_file" {
		t.Errorf("Tool = %q, want read_file", tus[0].Tool)
	}
	// Arguments was a JSON-encoded string of an object. Input should be
	// the decoded inner JSON.
	var got map[string]any
	if err := json.Unmarshal(tus[0].Input, &got); err != nil {
		t.Fatalf("Input not valid JSON: %v; raw=%s", err, string(tus[0].Input))
	}
	if got["path"] != "/src/payments/charge.go" {
		t.Errorf("Input.path = %v, want /src/payments/charge.go", got["path"])
	}
}

func TestOpenAIChat_ToolCallMalformedArgumentsSkipped(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "assistant", "tool_calls": [
				{"id": "x", "type": "function",
				 "function": {"name": "read_file", "arguments": "not valid json"}}
			]}
		]
	}`)
	tus := ExtractToolUses("api.openai.com", "/v1/chat/completions", body)
	if len(tus) != 1 {
		t.Fatalf("len = %d, want 1 (we still emit the call with raw Input bytes)", len(tus))
	}
	// Input should hold the raw arguments bytes; downstream Unmarshal fails
	// gracefully in pathscan.
	if string(tus[0].Input) != "not valid json" {
		t.Errorf("Input = %q, want raw bytes", string(tus[0].Input))
	}
}

func TestOpenAIChat_ToolRoleMessageWithContentArray(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "tool", "tool_call_id": "x", "content": [
				{"type": "text", "text": "file contents here"}
			]}
		]
	}`)
	parsed, err := parseOpenAIChat(body)
	if err != nil {
		t.Fatalf("parseOpenAIChat: %v", err)
	}
	if len(parsed.Texts) != 1 {
		t.Fatalf("Texts len = %d, want 1", len(parsed.Texts))
	}
	if parsed.Texts[0].Role != "tool" || parsed.Texts[0].Content != "file contents here" {
		t.Errorf("Texts[0] = %+v; want role=tool content='file contents here'", parsed.Texts[0])
	}
}

func TestOpenAIChat_MultipleToolCallsInOneMessage(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "assistant", "tool_calls": [
				{"id": "a", "type": "function",
				 "function": {"name": "read_file", "arguments": "{\"path\":\"/a\"}"}},
				{"id": "b", "type": "function",
				 "function": {"name": "read_file", "arguments": "{\"path\":\"/b\"}"}}
			]}
		]
	}`)
	tus := ExtractToolUses("api.openai.com", "/v1/chat/completions", body)
	if len(tus) != 2 {
		t.Fatalf("len = %d, want 2", len(tus))
	}
}

func TestOpenAIChat_MixedTextAndToolCalls(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "assistant", "content": "thinking…",
			 "tool_calls": [
				{"id": "x", "type": "function",
				 "function": {"name": "read_file", "arguments": "{\"path\":\"/x\"}"}}
			]}
		]
	}`)
	parsed, err := parseOpenAIChat(body)
	if err != nil {
		t.Fatalf("parseOpenAIChat: %v", err)
	}
	if len(parsed.Texts) != 1 || parsed.Texts[0].Content != "thinking…" {
		t.Fatalf("Texts = %+v; want one segment 'thinking…'", parsed.Texts)
	}
	tus := ExtractToolUses("api.openai.com", "/v1/chat/completions", body)
	if len(tus) != 1 {
		t.Fatalf("ExtractToolUses len = %d, want 1", len(tus))
	}
}
```

Add `"encoding/json"` to the test file's imports if not already present.

- [ ] **Step 3: Run, confirm compile failure**

```bash
go test ./internal/parser/...
```

Expected: compile errors — `ExtractToolUses` signature mismatch (current is `(host, body)`, new tests call `(host, path, body)`).

- [ ] **Step 4: Update `openAIMessage` and add tool_calls types in `internal/parser/openai.go`**

Replace the file contents with:

```go
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
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
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
				Input:        json.RawMessage(tc.Function.Arguments),
				MessageIndex: i,
			})
		}
	}
	return out
}
```

- [ ] **Step 5: Widen `ExtractToolUses` signature in `internal/parser/parser.go` and update Anthropic caller**

Open `internal/parser/parser.go` — there's a comment at the bottom but the function lives in `anthropic.go`. The change goes in `anthropic.go`:

Open `internal/parser/anthropic.go`, line 139, change:

```go
func ExtractToolUses(host string, body []byte) []ToolUse {
	if host != "api.anthropic.com" {
		return nil
	}
```

to:

```go
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

// extractAnthropicToolUses is the original Anthropic extraction logic,
// moved out of ExtractToolUses to make the dispatcher cleaner.
func extractAnthropicToolUses(body []byte) []ToolUse {
```

Then replace the existing function body's opening lines (from `var req anthropicMessagesRequest` onward) — they stay as-is, just under a new function name. Close the `extractAnthropicToolUses` function.

The result is: `ExtractToolUses(host, path, body)` dispatches; `extractAnthropicToolUses(body)` holds the old logic.

NOTE: `extractOpenAIResponsesToolUses` is declared in Task 2. Until Task 2 lands, this file won't compile. That's fine — sequential tasks are allowed to lean on each other within the same plan, and Step 6 below runs a compile check after Task 2.

- [ ] **Step 6: Compile check (will fail until Task 2 adds extractOpenAIResponsesToolUses)**

```bash
go build ./internal/parser/...
```

Expected: `undefined: extractOpenAIResponsesToolUses`. That's the bridge to Task 2. Do NOT try to satisfy it with a stub now — Task 2 will add the real function.

- [ ] **Step 7: Defer this task's commit to the end of Task 2 (since they form a single compile-unit)**

We'll combine Task 1 + Task 2 into one commit at the end of Task 2 to keep the tree compilable at every committed SHA.

---

## Task 2: OpenAI `/v1/responses` parser

**Files:**
- Create: `internal/parser/openai_responses.go`
- Create: `internal/parser/openai_responses_test.go`

- [ ] **Step 1: Write the failing tests — create `internal/parser/openai_responses_test.go`**

```go
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
	// Expect: user TS, then tool TS (function_call_output). function_call
	// itself is NOT a text segment.
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
```

- [ ] **Step 2: Create `internal/parser/openai_responses.go`**

```go
package parser

import (
	"encoding/json"
	"fmt"
)

type openAIResponsesRequest struct {
	Instructions string            `json:"instructions"`
	Input        json.RawMessage   `json:"input"`
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
				// Chat-style item if it has a "role" field.
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
				// Typed item.
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
				// function_call items contribute no text; ExtractToolUses
				// picks them up separately.
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
		var argsStr string
		if argsRaw, ok := item["arguments"]; ok {
			_ = json.Unmarshal(argsRaw, &argsStr)
		}
		out = append(out, ToolUse{
			Tool:         name,
			Input:        json.RawMessage(argsStr),
			MessageIndex: i,
		})
	}
	return out
}
```

- [ ] **Step 3: Run tests, confirm pass**

```bash
go test -race -count=1 ./internal/parser/...
```

Expected: all tests pass (Task 1 tests + 6 new Task 2 tests + existing tests).

- [ ] **Step 4: Run vet + gofmt**

```bash
go vet ./...
gofmt -l internal/parser/
```

Both clean.

- [ ] **Step 5: Commit Tasks 1 + 2 together**

```bash
git add internal/parser/openai.go internal/parser/openai_test.go \
        internal/parser/openai_responses.go internal/parser/openai_responses_test.go \
        internal/parser/anthropic.go
git -c user.email=haidangdavid123@gmail.com -c user.name=dawn commit -m "feat(parser): OpenAI tool_calls + /v1/responses endpoint"
```

---

## Task 3: Parser dispatcher — `/v1/responses` route + dispatcher tests

**Files:**
- Modify: `internal/parser/parser.go`
- Modify: `internal/parser/parser_test.go`

- [ ] **Step 1: Update the dispatcher in `internal/parser/parser.go`**

Replace the switch in `ParseRequest`:

```go
	switch host {
	case "api.openai.com":
		if req.URL.Path == "/v1/chat/completions" {
			return parseOpenAIChat(body)
		}
	case "api.anthropic.com":
		if req.URL.Path == "/v1/messages" {
			return parseAnthropicMessages(body)
		}
	}
	return nil, nil
```

with:

```go
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
```

- [ ] **Step 2: Append dispatcher tests to `internal/parser/parser_test.go`**

```go

func TestParseRequest_OpenAIResponsesEndpoint(t *testing.T) {
	body := []byte(`{"model":"gpt-4.1","input":"hi"}`)
	req := httptest.NewRequest("POST", "/v1/responses", nil)
	parsed, err := ParseRequest("api.openai.com", req, body)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if parsed == nil {
		t.Fatal("parsed is nil")
	}
	if parsed.Vendor != "openai" || parsed.Endpoint != "responses" {
		t.Errorf("Vendor/Endpoint = %q/%q", parsed.Vendor, parsed.Endpoint)
	}
}

func TestExtractToolUses_OpenAIResponses(t *testing.T) {
	body := []byte(`{
		"input": [
			{"type": "function_call", "name": "read_file",
			 "arguments": "{\"path\":\"/x\"}"}
		]
	}`)
	tus := ExtractToolUses("api.openai.com", "/v1/responses", body)
	if len(tus) != 1 || tus[0].Tool != "read_file" {
		t.Errorf("got %+v, want one Tool=read_file", tus)
	}
}

func TestExtractToolUses_AnthropicSignatureStillWorks(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "name": "Read", "id": "x",
				 "input": {"file_path": "/a"}}
			]}
		]
	}`)
	tus := ExtractToolUses("api.anthropic.com", "/v1/messages", body)
	if len(tus) != 1 || tus[0].Tool != "Read" {
		t.Errorf("got %+v, want one Tool=Read", tus)
	}
}

func TestExtractToolUses_UnknownHostReturnsNil(t *testing.T) {
	if tus := ExtractToolUses("example.com", "/", nil); tus != nil {
		t.Errorf("got %+v, want nil", tus)
	}
}
```

Add `"net/http/httptest"` to the test file's imports if not already present.

- [ ] **Step 3: Run tests**

```bash
go test -race -count=1 ./internal/parser/...
go vet ./...
gofmt -l internal/parser/
```

All clean.

- [ ] **Step 4: Commit**

```bash
git add internal/parser/parser.go internal/parser/parser_test.go
git -c user.email=haidangdavid123@gmail.com -c user.name=dawn commit -m "feat(parser): dispatch /v1/responses + ExtractToolUses(host, path, body)"
```

---

## Task 4: Widen pathscan — vendor gate + field-name candidates + OpenAI tool allowlist

**Files:**
- Modify: `internal/pathscan/pathscan.go`
- Modify: `internal/pathscan/pathscan_test.go`

- [ ] **Step 1: Read the current pathscan.go**

```bash
sed -n '1,80p' internal/pathscan/pathscan.go
```

Confirm the supportedTools map (Anthropic conventions: `Read`, `Write`, `Edit`, etc.) and the typed `file_path` field decoding around lines 50-65. Note the caller of `ExtractToolUses` at line 45 — needs to receive a `path` argument.

- [ ] **Step 2: Append failing tests to `internal/pathscan/pathscan_test.go`**

```go

func TestExtractPathEvents_OpenAIChatToolCalls(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "assistant", "tool_calls": [
				{"id": "x", "type": "function",
				 "function": {"name": "read_file",
				              "arguments": "{\"path\":\"/src/payments/x.go\"}"}}
			]}
		]
	}`)
	parsed := &parser.ParsedRequest{
		Vendor:   "openai",
		Endpoint: "chat.completions",
		Raw:      body,
	}
	events := ExtractPathEvents(parsed, body, "/v1/chat/completions")
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	if events[0].Path != "/src/payments/x.go" {
		t.Errorf("Path = %q, want /src/payments/x.go", events[0].Path)
	}
	if events[0].Tool != "read_file" {
		t.Errorf("Tool = %q, want read_file", events[0].Tool)
	}
}

func TestExtractPathEvents_OpenAIResponsesFunctionCall(t *testing.T) {
	body := []byte(`{
		"input": [
			{"type": "function_call", "name": "read_file",
			 "arguments": "{\"file_path\":\"/etc/passwd\"}"}
		]
	}`)
	parsed := &parser.ParsedRequest{
		Vendor:   "openai",
		Endpoint: "responses",
		Raw:      body,
	}
	events := ExtractPathEvents(parsed, body, "/v1/responses")
	if len(events) != 1 || events[0].Path != "/etc/passwd" {
		t.Errorf("events = %+v, want one path=/etc/passwd", events)
	}
}

func TestExtractPathEvents_OpenAIFilenameField(t *testing.T) {
	// Some OpenAI tool definitions use "filename" instead of "path"/"file_path".
	body := []byte(`{
		"messages": [
			{"role": "assistant", "tool_calls": [
				{"id": "x", "type": "function",
				 "function": {"name": "write_file",
				              "arguments": "{\"filename\":\"/tmp/o\",\"content\":\"x\"}"}}
			]}
		]
	}`)
	parsed := &parser.ParsedRequest{Vendor: "openai", Endpoint: "chat.completions", Raw: body}
	events := ExtractPathEvents(parsed, body, "/v1/chat/completions")
	if len(events) != 1 || events[0].Path != "/tmp/o" {
		t.Errorf("events = %+v, want one path=/tmp/o", events)
	}
}

func TestExtractPathEvents_AnthropicStillWorks(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "name": "Read", "id": "x",
				 "input": {"file_path": "/a/b.txt"}}
			]}
		]
	}`)
	parsed := &parser.ParsedRequest{Vendor: "anthropic", Endpoint: "messages", Raw: body}
	events := ExtractPathEvents(parsed, body, "/v1/messages")
	if len(events) != 1 || events[0].Path != "/a/b.txt" {
		t.Errorf("events = %+v, want /a/b.txt", events)
	}
}

func TestExtractPathEvents_UnknownToolSkipped(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "assistant", "tool_calls": [
				{"id": "x", "type": "function",
				 "function": {"name": "unknown_tool",
				              "arguments": "{\"path\":\"/a\"}"}}
			]}
		]
	}`)
	parsed := &parser.ParsedRequest{Vendor: "openai", Endpoint: "chat.completions", Raw: body}
	events := ExtractPathEvents(parsed, body, "/v1/chat/completions")
	if len(events) != 0 {
		t.Errorf("events = %+v, want empty (unknown tool)", events)
	}
}
```

- [ ] **Step 3: Run, confirm compile failure (signature mismatch)**

```bash
go test ./internal/pathscan/...
```

Expected: `ExtractPathEvents` signature `(parsed, body)` doesn't match the new calls passing `path` as a 3rd arg.

- [ ] **Step 4: Rewrite `ExtractPathEvents` and `supportedTools` in `internal/pathscan/pathscan.go`**

Find the existing `supportedTools` map and add OpenAI variants:

```go
var supportedTools = map[string]bool{
	// Anthropic / Claude Code conventions
	"Read":   true,
	"Write":  true,
	"Edit":   true,
	"Glob":   true,
	"Grep":   true,
	// OpenAI tool_calls conventions (Cursor BYOK + custom tool definitions)
	"read_file":  true,
	"write_file": true,
	"edit_file":  true,
	"apply_diff": true,
}
```

(If the map doesn't contain `Glob`/`Grep` today, adjust to whatever is currently there — but DO add the four lowercase OpenAI names.)

Replace `ExtractPathEvents` with:

```go
// ExtractPathEvents returns all PathEvents extracted from the parsed
// request body. It supports Anthropic tool_use blocks AND OpenAI
// tool_calls / function_call items. Unsupported tool names are skipped.
//
// path is the HTTP request path (used by parser.ExtractToolUses to
// dispatch by endpoint).
func ExtractPathEvents(parsed *parser.ParsedRequest, body []byte, path string) []PathEvent {
	if parsed == nil {
		return nil
	}
	var host string
	switch parsed.Vendor {
	case "anthropic":
		host = "api.anthropic.com"
	case "openai":
		host = "api.openai.com"
	default:
		return nil
	}
	tools := parser.ExtractToolUses(host, path, body)
	if len(tools) == 0 {
		return nil
	}
	var out []PathEvent
	for _, tu := range tools {
		if !supportedTools[tu.Tool] {
			continue
		}
		p := extractPath(tu.Input)
		if p == "" {
			continue
		}
		out = append(out, PathEvent{
			Tool:         tu.Tool,
			Path:         p,
			MessageIndex: tu.MessageIndex,
		})
	}
	return out
}

// extractPath probes a tool's input JSON for any of the common file-path
// field names. First non-empty wins. Returns "" if none present.
func extractPath(input []byte) string {
	var probe struct {
		FilePath string `json:"file_path"`
		Path     string `json:"path"`
		Filename string `json:"filename"`
		Filepath string `json:"filepath"`
	}
	if err := json.Unmarshal(input, &probe); err != nil {
		return ""
	}
	for _, p := range []string{probe.FilePath, probe.Path, probe.Filename, probe.Filepath} {
		if p != "" {
			return p
		}
	}
	return ""
}
```

- [ ] **Step 5: Update callers of `ExtractPathEvents` to pass `path`**

```bash
grep -rn "ExtractPathEvents" --include="*.go" .
```

Identify the stage caller (probably `internal/stage/pathscan/`) and any tests. For each caller, thread `rc.Req.URL.Path` (or equivalent) through to the new third argument.

Specifically inspect `internal/stage/pathscan/pathscan.go` (or whichever file holds the stage Run method) and update the line that calls `pathscan.ExtractPathEvents(parsed, body)` to `pathscan.ExtractPathEvents(parsed, body, rc.Req.URL.Path)`.

- [ ] **Step 6: Run tests**

```bash
go test -race -count=1 ./...
go vet ./...
gofmt -l ./internal/pathscan/ ./internal/stage/
```

All must pass. If `gofmt -l` reports anything, run `gofmt -w` on the listed files.

- [ ] **Step 7: Commit**

```bash
git add internal/pathscan/pathscan.go internal/pathscan/pathscan_test.go internal/stage/pathscan/
git -c user.email=haidangdavid123@gmail.com -c user.name=dawn commit -m "feat(pathscan): support OpenAI tool_calls + multiple file-path field names"
```

---

## Task 5: End-to-end integration test — Cursor-like flow against OpenAI

**Files:**
- Create: `test/integration/cursor_test.go`

- [ ] **Step 1: Create `test/integration/cursor_test.go`**

```go
// End-to-end test for sub-project #7: a real http.Client through a real
// proxy with a path-blocking policy. Sends an OpenAI /v1/responses
// request matching the shape Cursor produces in BYOK + Composer mode,
// and verifies the proxy returns 403 with a path-scan finding.
package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"railcore/internal/ca"
	"railcore/internal/pipeline"
	"railcore/internal/policy"
	"railcore/internal/proxy"
	pathscanstage "railcore/internal/stage/pathscan"
)

func TestCursor_BYOK_OpenAIResponses_BlocksPayments(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	tmpDir := t.TempDir()
	caInst, err := ca.GenerateOrLoad(tmpDir + "/ca")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}

	yaml := `
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
`
	pol, err := policy.LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("policy.LoadFromBytes: %v", err)
	}

	chain := pipeline.NewChain()
	chain.Register(pathscanstage.New(pathscanstage.Config{Policy: pol}, nil))

	srv := proxy.New(proxy.Config{
		Addr:             "127.0.0.1:0",
		CA:               caInst,
		Pipeline:         chain,
		UpstreamTLS:      &tls.Config{RootCAs: upstreamPool, ServerName: upstreamURL.Hostname()},
		UpstreamResolver: func(_ string) (string, error) { return upstreamURL.Host, nil },
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, ln)

	caPool := x509.NewCertPool()
	caPool.AddCert(caInst.RootCert())
	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "api.openai.com"},
		},
		Timeout: 10 * time.Second,
	}

	// /v1/responses body with a function_call referencing a blocked path.
	body := `{
		"model": "gpt-4.1",
		"input": [
			{"role": "user", "content": "open the charge file"},
			{"type": "function_call", "name": "read_file",
			 "arguments": "{\"path\":\"/src/payments/charge.go\"}",
			 "call_id": "fc_1"}
		]
	}`
	resp, err := client.Post("https://api.openai.com/v1/responses", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Status = %d, want 403", resp.StatusCode)
	}
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["error"] != "blocked by railcore policy" {
		t.Errorf("error = %v, want 'blocked by railcore policy'", got["error"])
	}
	findings, ok := got["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("findings missing or empty: %v", got)
	}
}
```

- [ ] **Step 2: Run the integration test**

```bash
go test -race -count=1 -run TestCursor ./test/integration/...
```

Expected: PASS.

- [ ] **Step 3: Run the full suite**

```bash
go test -race -count=1 ./...
go vet ./...
gofmt -l test/integration/
```

All clean.

- [ ] **Step 4: Commit**

```bash
git add test/integration/cursor_test.go
git -c user.email=haidangdavid123@gmail.com -c user.name=dawn commit -m "test(integration): Cursor-like OpenAI /v1/responses blocks on path policy"
```

---

## Task 6: User-facing setup documentation — `docs/cursor-setup.md`

**Files:**
- Create: `docs/cursor-setup.md`

- [ ] **Step 1: Write `docs/cursor-setup.md`**

```markdown
# Using Railcore with Cursor

Railcore inspects every AI request your tools make through it. Cursor in **BYOK** (Bring Your Own Key) mode sends prompts directly to OpenAI or Anthropic — Railcore sits in front, applies your policy, and writes an audit record per request.

This guide gets you wired up in five minutes.

> **What about non-BYOK?**
> When BYOK is off, Cursor routes prompts through `api2.cursor.sh` (its own backend). Railcore still sees that traffic at the host level (audit logs `host=api2.cursor.sh decision=continue`) but cannot decrypt the payload — Cursor pins its certificate. To get full policy enforcement, use BYOK.

---

## 1. Start Railcore

```bash
railcore init                          # first run only
railcore proxy --port 9443
```

Leave it running. In another terminal:

```bash
railcore logs --follow
```

This streams audit records live so you can watch what Cursor sends.

## 2. Switch Cursor to BYOK

1. Open Cursor → **Settings** (gear icon).
2. **Models** tab → toggle on **"Use your own API key"**.
3. Paste an **OpenAI key**, an **Anthropic key**, or both. (Cursor lets you switch the active provider per chat.)

If your provider is missing from the UI, update Cursor to the latest release — older builds hide BYOK behind a feature flag.

## 3. Point Cursor at the proxy

Cursor does **not** honor the `HTTPS_PROXY` environment variable. The proxy URL must be set in-app:

1. Cursor → **Settings** → **Beta** → **Custom Proxy URL**.
2. Set the value to `http://127.0.0.1:9443`.
3. Save and restart Cursor.

(If the **Beta** section doesn't show **Custom Proxy URL**, check **Settings → Network**. The label has moved between Cursor releases. Search the settings dialog for "proxy".)

## 4. Trust the Railcore CA

Cursor is an Electron app and uses Chromium's certificate store. On most Linux distros, `railcore init` already trusts the CA system-wide. If you see TLS errors in Cursor:

**Linux (Debian/Ubuntu):**
```bash
sudo cp ~/.railcore/ca/ca.crt /usr/local/share/ca-certificates/railcore.crt
sudo update-ca-certificates
```

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.railcore/ca/ca.crt
```

**Windows:**
```powershell
certutil -addstore "Root" "$env:USERPROFILE\.railcore\ca\ca.crt"
```

Restart Cursor after installing the cert.

## 5. Verify

In Cursor, open chat and ask a benign question ("explain a binary search"). In your `railcore logs --follow` terminal you should see a record like:

```
HH:MM:SS  ✓  POST  api.openai.com        /v1/chat/completions          200  240ms  continue
```

Now try something policy should block. With this rule in `~/.railcore/policy.yaml`:

```yaml
version: 1
rules:
  - name: block-payments
    match: { path: "**/payments/**" }
    action: block
  - name: default-warn
    match: { all: true }
    action: warn
```

(Note: specific blocks must come **before** the catch-all warn — first match wins.)

Restart `railcore proxy` to pick up the change. In Cursor's Composer, ask it to read a file at `~/anywhere/payments/anything.txt`. Cursor's tool call should fail with a 403 error from the proxy, and the audit line shows:

```
HH:MM:SS  ✗  POST  api.openai.com        /v1/chat/completions          403  18ms   block    findings=1 [block-payments]
```

That's it. Cursor + Railcore is now governing every prompt your IDE sends.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Cursor shows "tunnel connection failed" | Railcore not running or wrong port. Check `railcore status`. |
| Cursor shows certificate errors | CA not trusted by system store. Re-run step 4 and restart Cursor. |
| Audit log empty | Cursor still using its own backend. Confirm BYOK is on AND the Custom Proxy URL is set. |
| Records appear with `vendor=""` | Cursor hit an endpoint Railcore doesn't have a parser for. File an issue with the host + path from the audit record. |
```

- [ ] **Step 2: Verify the document renders cleanly**

```bash
wc -l docs/cursor-setup.md
```

Expected: ~80-100 lines.

- [ ] **Step 3: Commit**

```bash
git add docs/cursor-setup.md
git -c user.email=haidangdavid123@gmail.com -c user.name=dawn commit -m "docs: Cursor BYOK setup guide"
```

---

## Task 7: Manual acceptance test + record §11

**Files:** none modified during testing; spec gets §11 appended at the end.

- [ ] **Step 1: Build**

```bash
make build || go build -o railcore ./cmd/railcore
```

- [ ] **Step 2: Reset state, ensure CA is trusted system-wide**

```bash
./railcore init --force
```

- [ ] **Step 3: Set up Cursor per `docs/cursor-setup.md`**

1. Cursor BYOK on, OpenAI key set.
2. Custom Proxy URL: `http://127.0.0.1:9443`.
3. Restart Cursor.

- [ ] **Step 4: Run the proxy + log follower**

Terminal A: `./railcore proxy --port 9443`
Terminal B: `./railcore logs --follow`

- [ ] **Step 5: Run scenarios 1–4 from spec §7.7**

**Scenario 1** — Cursor BYOK→OpenAI, ask "explain bubble sort".
Expected audit record: `vendor=openai endpoint=chat.completions decision=continue`.

**Scenario 2** — Same. Open Composer, ask it to read `/tmp/safe/foo.txt` (create this file first).
Expected audit: `decision=continue` with `findings` containing a `default-warn` finding for the path.
(If your policy doesn't include `default-warn`, add it temporarily.)

**Scenario 3** — Add this policy to `~/.railcore/policy.yaml`:
```yaml
version: 1
rules:
  - name: block-payments
    match: { path: "**/payments/**" }
    action: block
  - name: default-warn
    match: { all: true }
    action: warn
```
Restart the proxy. In Cursor Composer, ask it to read `/src/payments/charge.go` (or any path matching the glob — `mkdir -p` it if needed).
Expected: `decision=block` with `findings[0].rule=block-payments`. Cursor surfaces the 403 error to the user.

**Scenario 4** — In Cursor settings, switch BYOK to Anthropic. Repeat scenario 3.
Expected: Same `decision=block` outcome. Proves Cursor + Anthropic still works through Railcore.

- [ ] **Step 6: Optional Scenario 5 (informational only)**

Disable BYOK in Cursor. Send any prompt.
Expected: Either an audit record with `host=api2.cursor.sh decision=continue vendor=""` (no pinning), OR no audit record + `WARN intercept failed` in the proxy log (pinning fires). Either is acceptable. The proxy must not crash; subsequent BYOK requests must still work.

- [ ] **Step 7: Append §11 Acceptance Result to spec**

Open `docs/superpowers/specs/2026-05-18-cursor-byok-and-openai-tool-calls-design.md` and append:

```markdown

---

## 11. Acceptance Result

**Date:** YYYY-MM-DD (fill in real run date)

- **Scenario 1 (BYOK + OpenAI simple chat):** [Pass | Fail] — observed `vendor=…, endpoint=…, decision=continue`.
- **Scenario 2 (Composer reads safe path):** [Pass | Fail] — observed `findings=…, decision=continue`.
- **Scenario 3 (Composer reads blocked path):** [Pass | Fail] — observed `decision=block, findings[0].rule=block-payments`. Cursor surfaced 403.
- **Scenario 4 (BYOK + Anthropic, same block path):** [Pass | Fail] — same outcome as scenario 3.
- **Scenario 5 (non-BYOK passthrough):** [Pass observed: <which path>].

**Status:** [Pass | Fail]. Sub-project #7 done definition §8 satisfied.

**Notes:** [any UI label drift, Cursor version, anomalies worth recording]
```

Then commit:

```bash
git add docs/superpowers/specs/2026-05-18-cursor-byok-and-openai-tool-calls-design.md
git -c user.email=haidangdavid123@gmail.com -c user.name=dawn commit -m "docs(spec): record sub-project #7 acceptance result"
```

---

## Self-Review

1. **Spec coverage:**
   - §4.1 OpenAI chat completions tool_calls + content arrays → Task 1.
   - §4.2 `/v1/responses` parser → Task 2.
   - §4.3 Dispatcher widening (path arg) → Tasks 1, 2, 3 (combined: signature in Task 1, helpers in Task 2, dispatcher in Task 3).
   - §4.4 Audit/policy unchanged → no task needed.
   - §4.4 Pathscan widening (vendor gate + field names + tool allowlist) → Task 4.
   - §4.5 Cursor backend passthrough → covered by §4.5 acceptance scenario 5 (Task 7 step 6).
   - §4.6 docs/cursor-setup.md → Task 6.
   - §7.4 Integration test → Task 5.
   - §7.7 Manual acceptance → Task 7.
   - §11 Acceptance result → Task 7 step 7.

2. **Placeholder scan:** Acceptance result template in Task 7 step 7 has `YYYY-MM-DD` and `[Pass | Fail]` brackets — that's expected; the user fills them in at runtime. No "TBD"/"TODO" in source code paths.

3. **Type consistency:**
   - `ToolUse{Tool, Input json.RawMessage, MessageIndex}` consistent across Tasks 1–4 (matches existing anthropic.go).
   - `ExtractToolUses(host, path string, body []byte) []ToolUse` consistent across Tasks 1, 3, 4, 5.
   - `ExtractPathEvents(parsed, body, path string)` consistent across Task 4 and the caller updates in Task 4 Step 5.
   - `flattenOpenAIContent` referenced from both `parseOpenAIChat` (Task 1) and `parseOpenAIResponses` (Task 2) — defined once in Task 1.
   - `extractOpenAIResponsesToolUses` declared in Task 1 dispatcher, defined in Task 2 — bridged via a single commit at end of Task 2.

4. **Cross-task compile gates:** Task 1 + Task 2 commit together because Task 1's dispatcher references Task 2's helper. Documented explicitly in Task 1 Step 7 and Task 2 Step 5.
