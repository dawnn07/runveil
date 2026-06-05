package parser

import (
	"encoding/json"
	"fmt"
	"sort"
)

const redactMask = "[REDACTED]"

// Span is a half-open [Offset, Offset+Length) range within a decoded
// content string to replace with the redaction mask.
type Span struct {
	Offset int
	Length int
}

// Redaction identifies one piece of prose to mask. Role+Index locate the
// owning content value (Index == -1 for the Anthropic system field);
// Content is the exact decoded text the spans index into. Matching is by
// content identity so it is robust to ordering.
type Redaction struct {
	Role    string
	Index   int
	Content string
	Spans   []Span
}

// RedactRequest returns body with every Redaction's spans masked. v1
// supports only Anthropic /v1/messages. It rebuilds losslessly: only the
// matched content strings are re-encoded; all other bytes pass through.
// Returns an error (caller must fail closed) when the endpoint is
// unsupported, the JSON is malformed, or any redaction cannot be applied
// (its content is not found as redactable prose).
func RedactRequest(host, path string, body []byte, reds []Redaction) ([]byte, error) {
	if host != "api.anthropic.com" || path != "/v1/messages" {
		return nil, fmt.Errorf("redact: unsupported endpoint %s%s", host, path)
	}
	if len(reds) == 0 {
		return body, nil
	}
	return redactAnthropic(body, reds)
}

// applySpans masks each span in content (right-to-left so offsets do not
// shift).
func applySpans(content string, spans []Span) (string, error) {
	ordered := append([]Span(nil), spans...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Offset > ordered[j].Offset })
	b := []byte(content)
	for _, s := range ordered {
		if s.Offset < 0 || s.Length < 0 || s.Offset+s.Length > len(b) {
			return "", fmt.Errorf("redact: span [%d,%d) out of range for content len %d", s.Offset, s.Offset+s.Length, len(b))
		}
		b = append(b[:s.Offset], append([]byte(redactMask), b[s.Offset+s.Length:]...)...)
	}
	return string(b), nil
}

// redactAnthropic rebuilds an Anthropic /v1/messages body with reds applied.
func redactAnthropic(body []byte, reds []Redaction) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, fmt.Errorf("redact: decode body: %w", err)
	}

	applied := make([]bool, len(reds))

	if sysRaw, ok := top["system"]; ok {
		newRaw, err := redactContent("system", -1, sysRaw, reds, applied)
		if err != nil {
			return nil, err
		}
		top["system"] = newRaw
	}

	if msgsRaw, ok := top["messages"]; ok {
		var msgs []json.RawMessage
		if err := json.Unmarshal(msgsRaw, &msgs); err != nil {
			return nil, fmt.Errorf("redact: decode messages: %w", err)
		}
		for i := range msgs {
			var msg map[string]json.RawMessage
			if err := json.Unmarshal(msgs[i], &msg); err != nil {
				return nil, fmt.Errorf("redact: decode message %d: %w", i, err)
			}
			role := ""
			if rRaw, ok := msg["role"]; ok {
				_ = json.Unmarshal(rRaw, &role)
			}
			cRaw, ok := msg["content"]
			if !ok {
				continue
			}
			newRaw, err := redactContent(role, i, cRaw, reds, applied)
			if err != nil {
				return nil, err
			}
			msg["content"] = newRaw
			remarshaled, err := json.Marshal(msg)
			if err != nil {
				return nil, fmt.Errorf("redact: re-encode message %d: %w", i, err)
			}
			msgs[i] = remarshaled
		}
		newMsgs, err := json.Marshal(msgs)
		if err != nil {
			return nil, fmt.Errorf("redact: re-encode messages: %w", err)
		}
		top["messages"] = newMsgs
	}

	for k, done := range applied {
		if !done {
			return nil, fmt.Errorf("redact: content for %s[%d] not found as redactable prose", reds[k].Role, reds[k].Index)
		}
	}
	return json.Marshal(top)
}

// redactContent masks redactions targeting (role, index) within one
// content value (a JSON string or an array of blocks). Only top-level
// string content and top-level {"type":"text"} blocks are redactable.
func redactContent(role string, index int, raw json.RawMessage, reds []Redaction, applied []bool) (json.RawMessage, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		newS, changed, err := maybeRedact(role, index, s, reds, applied)
		if err != nil {
			return nil, err
		}
		if !changed {
			return raw, nil
		}
		return json.Marshal(newS)
	}

	var blocks []json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return raw, nil
	}
	anyChange := false
	for bi := range blocks {
		var blk map[string]json.RawMessage
		if err := json.Unmarshal(blocks[bi], &blk); err != nil {
			continue
		}
		var bType string
		if tRaw, ok := blk["type"]; ok {
			_ = json.Unmarshal(tRaw, &bType)
		}
		if bType != "text" {
			continue
		}
		var txt string
		if tRaw, ok := blk["text"]; ok {
			_ = json.Unmarshal(tRaw, &txt)
		}
		newTxt, changed, err := maybeRedact(role, index, txt, reds, applied)
		if err != nil {
			return nil, err
		}
		if !changed {
			continue
		}
		enc, err := json.Marshal(newTxt)
		if err != nil {
			return nil, err
		}
		blk["text"] = enc
		reEnc, err := json.Marshal(blk)
		if err != nil {
			return nil, err
		}
		blocks[bi] = reEnc
		anyChange = true
	}
	if !anyChange {
		return raw, nil
	}
	return json.Marshal(blocks)
}

// maybeRedact applies every redaction whose (Role, Index, Content) equals
// (role, index, content), marking them applied.
func maybeRedact(role string, index int, content string, reds []Redaction, applied []bool) (string, bool, error) {
	out := content
	changed := false
	for k := range reds {
		if reds[k].Role != role || reds[k].Index != index || reds[k].Content != content {
			continue
		}
		masked, err := applySpans(out, reds[k].Spans)
		if err != nil {
			return "", false, err
		}
		out = masked
		applied[k] = true
		changed = true
	}
	return out, changed, nil
}
