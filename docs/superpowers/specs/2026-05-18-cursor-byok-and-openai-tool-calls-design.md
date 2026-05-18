# Sub-project #7 — Cursor BYOK + OpenAI tool_calls

**Status:** Design approved, pending spec review
**Date:** 2026-05-18
**Sub-project of:** Railcore MVP (see `part1.md`, `part2.md` in repo root)

---

## 1. Goal

Prove Railcore works end-to-end with **Cursor** in BYOK (Bring Your Own Key) mode, with parser parity between Anthropic `tool_use` and OpenAI `tool_calls`/`function_call` so path-scan blocks fire regardless of which provider Cursor's BYOK user selects.

**"Works end-to-end" means:**

- The user can configure Cursor to point at Railcore with one in-app setting.
- Every Cursor-originated HTTP request appears in the audit log.
- Existing policy rules (secret-scan, path-scan, block/warn actions) fire on Cursor traffic with the same semantics they fire on Claude Code traffic.
- A real manual acceptance test against live OpenAI + Anthropic APIs passes the scenarios in §7.7.

This is the seventh and final MVP sub-project. After this, the proxy supports two real-world AI coding tools (Claude Code from #1–6, Cursor from #7).

---

## 2. Non-goals

- **MITM of `api2.cursor.sh`** — Cursor's proprietary backend is almost certainly cert-pinned (Antigravity precedent, sub-project #1 documented this class of limitation). Even if pinning weren't an issue, the protobuf/Connect-RPC payload requires reverse engineering, ongoing proto-version tracking, and a non-trivial legal posture. Defer indefinitely.
- **Streaming response body scanning.** Currently the proxy only scans request bodies. Response-side secret/PII detection is a separate engineering project.
- **OpenAI legacy `/v1/completions`, embeddings, audio, image, batch endpoints.** Not used by Cursor for chat/agent loops.
- **Vision / multimodal content scanning.** When `content` parts include `input_image` or other non-text types, they are skipped — text-only scanning today.
- **Cursor in non-BYOK mode (Pro-plan routed traffic).** Gets host-level audit only. No payload inspection — see §4.5.
- **Refactoring `internal/parser/` package layout.** Files stay where they are. We only add `openai_responses.go` and extend `openai.go` and `parser.go`.

---

## 3. Module layout

```
internal/parser/                  (leaf package; stdlib + net/http only)
├── parser.go                     MODIFY: dispatch /v1/responses
├── openai.go                     MODIFY: tool_calls + content arrays
├── openai_responses.go           CREATE: /v1/responses parser
├── anthropic.go                  unchanged
├── openai_test.go                MODIFY: append 5 tests
├── openai_responses_test.go      CREATE
└── parser_test.go                unchanged (dispatcher already covered)
```

```
docs/
└── cursor-setup.md               CREATE: ~80-line user-facing setup guide
```

No changes to `internal/proxy/`, `internal/policy/`, `internal/pathscan/`, `internal/audit/`, `internal/stage/*`, or `cmd/railcore/`. The proxy already passes any request body to `parser.ParseRequest` and routes `ExtractToolUses` output into `rc.Metadata["pathscan.findings"]`. Vendor-shape changes are confined to the parser package.

**No new dependencies.** Stdlib `encoding/json` handles everything.

---

## 4. Detailed design

### 4.1 OpenAI Chat Completions — extend `openai.go`

Current `openAIMessage`:

```go
type openAIMessage struct {
    Role    string `json:"role"`
    Content string `json:"content"`
}
```

Replace with a shape that handles both string content and content arrays, and that surfaces `tool_calls`:

```go
type openAIMessage struct {
    Role      string           `json:"role"`
    Content   json.RawMessage  `json:"content"`   // string OR array of typed parts
    ToolCalls []openAIToolCall `json:"tool_calls"`
}

type openAIToolCall struct {
    ID       string             `json:"id"`
    Type     string             `json:"type"`       // "function"
    Function openAIFunctionCall `json:"function"`
}

type openAIFunctionCall struct {
    Name      string `json:"name"`
    Arguments string `json:"arguments"`             // JSON-encoded args string
}
```

**`parseOpenAIChat` changes:**

1. For each message, flatten `Content` into 0+ `TextSegment`s via a helper `flattenOpenAIContent(raw json.RawMessage) []string`:
   - If `Content` is a JSON string → emit that string.
   - If `Content` is a JSON array → for each part where `type=="text"` (assistant) or `type=="input_text"` (defensive — chat completions doesn't use these but we accept both for robustness) emit `.text`.
   - Else → skip silently.
2. `tool_calls` are NOT added to `Texts`. They are surfaced via `ExtractToolUses` only — path-scan walks them; secret-scan does not need them (the file path is the signal).

**`ExtractToolUses` for `host=="api.openai.com"`, path `/v1/chat/completions`:**

```go
// For each msg in messages:
//   For each tc in msg.tool_calls where tc.Type=="function":
//     in := map[string]any{}
//     json.Unmarshal([]byte(tc.Function.Arguments), &in)   // ignore err; in stays {}
//     out = append(out, ToolUse{Name: tc.Function.Name, Input: in})
```

Existing `ToolUse` struct:

```go
type ToolUse struct {
    Name  string         // e.g. "read_file"
    Input map[string]any
}
```

— unchanged. The path-scan stage already walks `Input` recursively for file-path-shaped strings.

### 4.2 OpenAI `/v1/responses` — new `openai_responses.go`

Request schema (relevant subset):

```json
{
  "model": "gpt-4.1",
  "instructions": "string, optional — replaces system message",
  "input": <string OR array>,
  "tools": [...]
}
```

When `input` is an array, items are one of:

- **Chat-style message:** `{"role": "user"|"assistant"|"system", "content": <string OR array of parts>}`
- **Typed item:** `{"type": "function_call", "name": ..., "arguments": <JSON-encoded string>, "call_id": ...}`
- **Typed item:** `{"type": "function_call_output", "call_id": ..., "output": <string>}`
- **Typed item:** unknown future types → skip silently

Content parts in the chat-style shape use `{"type": "input_text", "text": "..."}` or `{"type": "output_text", "text": "..."}` or `{"type": "input_image", ...}`. Only `input_text` and `output_text` produce TextSegments. Unknown part types are skipped.

**Function signature:**

```go
func parseOpenAIResponses(body []byte) (*ParsedRequest, error)
```

**Algorithm:**

1. Unmarshal into a typed struct with `Instructions string`, `Input json.RawMessage`, etc.
2. If `Instructions != ""` → emit `TextSegment{Role:"system", Index:0, Content:Instructions}`.
3. Probe `Input` as a string first; if that succeeds and the string is non-empty → emit `TextSegment{Role:"user", Index:0, Content:<the string>}`. Return.
4. Else unmarshal `Input` as a `[]json.RawMessage`. For each item, peek at `role` and `type`:
   - If `role` is set → chat-style. Flatten content like §4.1.
   - If `type=="function_call_output"` → emit `TextSegment{Role:"tool", Index:i, Content:output}`.
   - If `type=="function_call"` → no TextSegment (collected by `ExtractToolUses` instead).
   - Anything else → skip.
5. Return `ParsedRequest{Vendor:"openai", Endpoint:"responses", Texts:..., Raw:body}`.

**`ExtractToolUses` for `/v1/responses`:**

Walk `input[]` items where `type=="function_call"`, JSON-decode `arguments` into a `map[string]any`, emit one `ToolUse`. Same shape as §4.1.

### 4.3 Dispatcher — `parser.go`

Replace the OpenAI case in `ParseRequest`:

```go
case "api.openai.com":
    switch req.URL.Path {
    case "/v1/chat/completions":
        return parseOpenAIChat(body)
    case "/v1/responses":
        return parseOpenAIResponses(body)
    }
```

`ExtractToolUses` gets a parallel switch on `path`. Today it dispatches on `host` only; we widen it to `(host, path)`. The Anthropic case continues to handle `/v1/messages`.

### 4.4 Audit / policy / scanner impact

- **Audit:** `endpoint` becomes `"responses"` when Cursor hits the new endpoint. Open-string field, no schema migration.
- **Policy engine:** unchanged. Rules match on path strings inside ToolUse Input — the source endpoint is opaque.
- **Pathscan stage:** unchanged. Already walks `ToolUse.Input` recursively.
- **Secretscan stage:** unchanged. Walks `ParsedRequest.Texts`. Now also sees `function_call_output` content (file contents the model is reading) — gives us secret detection on file-read responses too. Not a goal but a free side-effect.

### 4.5 Cursor backend traffic (`api2.cursor.sh`)

When Cursor is in non-BYOK mode (its default), prompts flow to `api2.cursor.sh` via Connect-RPC. The proxy receives the CONNECT, attempts the TLS handshake, and either:

1. **Cert pinning rejects the MITM** → Cursor surfaces a connection error to the user. Railcore emits a `WARN intercept failed` log line. No audit record. Acceptable failure mode — user is informed, proxy is stable.
2. **No pinning** → Railcore intercepts, sees an unrecognized host, `parser.ParseRequest` returns `(nil, nil)`. The pipeline runs with no parsed body. Audit record is emitted with `host="api2.cursor.sh"`, `vendor=""`, `endpoint=""`, `decision="continue"`, `bytes_in=N`, `bytes_out=M`. Operator sees the traffic exists; no payload inspection happens.

Either way, the proxy does not crash and does not corrupt other traffic. Scenario 5 in §7.7 verifies this empirically.

### 4.6 Cursor setup documentation

New file: `docs/cursor-setup.md`, ≈80 lines, four sections:

1. **Switch Cursor to BYOK.** Cursor → Settings → Models → toggle "Use your own API key" → paste OpenAI or Anthropic key.
2. **Point Cursor at the proxy.** Cursor → Settings → Beta → "Custom Proxy URL" → `http://127.0.0.1:9443`. (Cursor does not honor the `HTTPS_PROXY` env var; the setting must be set in-app.)
3. **Trust the Railcore CA.** Most distros are auto-handled by `trust.Install()` from sub-project #1. Document the manual fallback (Linux: `sudo cp ~/.railcore/ca/ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`; macOS: Keychain Access import as trusted; Windows: `certutil`).
4. **Verify.** Make a prompt in Cursor. Run `railcore logs --follow` in another terminal. Expect at least one record with `host=api.openai.com` or `api.anthropic.com`, `decision=continue`.

Exact UI labels in steps 1–2 are verified live during implementation against the then-current Cursor build and snapshotted into the doc. If Cursor renames the setting in a later release, this is a doc-only follow-up.

---

## 5. Data flow (per request)

```
Cursor (BYOK + Anthropic mode, agent loop)
  └─ CONNECT api.anthropic.com:443
       └─ Railcore CONNECT handler (existing, sub-project #1)
            └─ TLS handshake with leaf cert from local CA (existing)
                 └─ http.Handler closure (existing, internal/proxy/upstream.go)
                      ├─ Read body to []byte (existing)
                      ├─ Build pipeline.RequestCtx (existing)
                      ├─ Stage: secretscan
                      │    └─ parser.ParseRequest(host, req, body)
                      │         └─ parseAnthropicMessages — unchanged
                      ├─ Stage: pathscan
                      │    └─ parser.ExtractToolUses(host, path, body)
                      │         └─ extractAnthropicToolUses — unchanged
                      ├─ Pipeline decision: Continue or Block
                      ├─ Forward upstream OR write 403 (existing)
                      └─ defer audit.Log(...) (existing, sub-project #6)
                            └─ vendor/endpoint via parser.ParseRequest (existing)
```

Cursor with BYOK + OpenAI Composer mode follows the same flow with `parseOpenAIChat` or `parseOpenAIResponses` in place of `parseAnthropicMessages` and the corresponding `extractOpenAIToolUses` variant in place of the Anthropic extractor.

For `api2.cursor.sh` (non-BYOK), the same flow runs but `parser.ParseRequest` returns `(nil, nil)`, the pipeline runs with empty parsed input, the audit record gets `vendor=""`/`endpoint=""`, and the request passes through.

---

## 6. Error handling

All new code in this sub-project fails open. Specifically:

| Failure | Handling |
|---|---|
| Malformed `tool_calls[].function.arguments` (not valid JSON) | Emit `ToolUse` with empty `Input{}`. Path-scan finds no file_path keys → no finding. |
| Malformed `content` array part (unknown `type`) | Skip that part. Other parts in the same message still emit TextSegments. |
| `/v1/responses` `input` is neither string nor array | Return `ParsedRequest` with empty `Texts`. No error. Audit record still emits with `vendor="openai" endpoint="responses"`. |
| Whole body is not valid JSON | Return `(nil, err)`. Caller (proxy upstream handler) already treats this as fail-open and forwards the request unchanged — same as today's behavior for malformed Anthropic bodies. |
| Cursor cert-pins `api2.cursor.sh` | TLS handshake fails. Existing `WARN intercept failed` log line. Cursor surfaces error to user. No audit record. |

No new error paths added beyond what the existing proxy already handles.

---

## 7. Testing

### 7.1 OpenAI chat completions — `internal/parser/openai_test.go` (append)

- `TestOpenAIChat_ExtractsToolCallArguments` — one assistant message with one tool_call → one ToolUse with parsed `Input`.
- `TestOpenAIChat_ToolCallMalformedArgumentsSkipped` — invalid JSON in arguments → ToolUse with empty Input, no error.
- `TestOpenAIChat_ToolRoleMessageWithContentArray` — `role:"tool" content:[{type:text,text:"..."}]` → TextSegment is emitted with role "tool".
- `TestOpenAIChat_MultipleToolCallsInOneMessage` — 2 tool_calls in one assistant message → 2 ToolUses.
- `TestOpenAIChat_MixedTextAndToolCalls` — assistant message with both string content AND tool_calls → text in `Texts`, calls in ToolUses.

### 7.2 OpenAI responses — `internal/parser/openai_responses_test.go` (new)

- `TestResponses_StringInput` — `input: "hello"` → 1 user TextSegment.
- `TestResponses_ArrayInputBasic` — user message + function_call + function_call_output → 1 user TS, 1 tool TS, 1 ToolUse.
- `TestResponses_Instructions` — top-level `instructions` field → system TextSegment.
- `TestResponses_ContentArrayInputText` — content as `[{type:input_text,text:"..."}]` → 1 TextSegment.
- `TestResponses_UnknownItemTypeIgnored` — `{type:"some_future_type"}` item is skipped silently.
- `TestResponses_MalformedFunctionCallArguments` — function_call with non-JSON args → ToolUse with empty Input.

### 7.3 Dispatcher — `internal/parser/parser_test.go` (append)

- `TestParseRequest_OpenAIResponsesEndpoint` — POST `api.openai.com /v1/responses` → routes to `parseOpenAIResponses`; vendor `openai`, endpoint `responses`.
- `TestExtractToolUses_OpenAIResponses` — same endpoint, body has function_call items → ToolUses extracted.

### 7.4 Integration (test/integration/cursor_test.go — new, optional)

A single integration test that puts Railcore in front of an httptest server pretending to be `api.openai.com`, sends a request matching the `/v1/responses` schema with a function_call referencing `/src/payments/x.go`, and verifies the policy stage emits a block under a `block-payments` rule. This proves the new endpoint participates end-to-end in the pipeline.

(Pattern: same scaffolding as `test/integration/audit_test.go` and `test/integration/pathscan_test.go`.)

### 7.5 Regressions

`go test -race -count=1 ./...` must remain green for all 256 existing tests. The parser changes are additive — existing OpenAI chat content (string-only `content`) must continue to parse correctly.

### 7.6 What's NOT tested automatically

- Real Cursor → real OpenAI / real Anthropic flow (covered by the manual acceptance test in §7.7).
- `api2.cursor.sh` cert-pinning behavior (depends on Cursor's current build).
- Cursor-specific UI quirks across OS/version.

### 7.7 Manual acceptance test

Run with real Cursor + real BYOK keys:

| # | Setup | Action | Expected audit record |
|---|---|---|---|
| 1 | Cursor BYOK→OpenAI | Ask "explain bubble sort" | `vendor=openai endpoint=chat.completions decision=continue` |
| 2 | Same | Composer reads `/tmp/safe/foo.txt` (a safe path) | `endpoint=chat.completions` (or `responses` if Cursor used the new endpoint), `default-warn` finding |
| 3 | Policy: `block-payments` above `default-warn`. Composer reads `/src/payments/charge.go` | | `decision=block`, `findings[0].rule=block-payments`, Cursor shows error |
| 4 | Switch BYOK to Anthropic, repeat scenario 3 | | Same `decision=block` outcome — proves Cursor-on-Anthropic still works |
| 5 | Disable BYOK (use Cursor's default backend) | Send any prompt | Audit either: `host=api2.cursor.sh decision=continue vendor="" endpoint=""` (if no cert pinning), OR no audit record + `WARN intercept failed` log line (if cert pinning fires) — both are acceptable; the proxy must not crash |

If scenarios 1–4 pass, sub-project #7 is done. Scenario 5 is informational.

---

## 8. Done definition

Sub-project #7 is complete when:

1. All unit tests in §7.1–7.3 pass under `-race -count=1`.
2. The optional integration test in §7.4 passes (or is explicitly skipped with rationale).
3. `go test -race -count=1 ./...` for the whole repo remains green (no regression in the 256 existing tests).
4. `docs/cursor-setup.md` is written, with UI labels verified against the actual Cursor build at implementation time.
5. Manual acceptance scenarios 1–4 in §7.7 pass against real Cursor + real BYOK keys.
6. The acceptance result is recorded in §11 of this spec.

When these six hold, the Railcore MVP is feature-complete for its two initial target tools (Claude Code, Cursor).

---

## 9. Open questions

None at the time of writing. Three items deliberately left unresolved:

- **Whether Cursor cert-pins `api2.cursor.sh`** — will be discovered during the manual acceptance test. Either outcome is acceptable per §4.5.
- **Whether Cursor uses `/v1/chat/completions` or `/v1/responses` by default** — implementation handles both. The acceptance test will show which the current Cursor build uses.
- **Whether Cursor's "Custom Proxy URL" setting still exists / has been renamed** — will be verified during step 1 of the documentation task. If renamed, the doc captures the current name.

---

## 10. Implementation order (preview)

(Detailed plan generated by the writing-plans skill after this spec is approved.)

1. Extend `openai.go` — `tool_calls` + content-array handling + tests.
2. Create `openai_responses.go` — new endpoint parser + tests.
3. Update `parser.go` dispatcher + `ExtractToolUses` dispatch + tests.
4. Optional integration test in `test/integration/cursor_test.go`.
5. Write `docs/cursor-setup.md`.
6. Manual acceptance test (§7.7).
7. Record acceptance result (§11).
