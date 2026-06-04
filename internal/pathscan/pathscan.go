// Package pathscan extracts file-path tool_use events from parsed AI
// vendor request bodies.
//
// Supports Anthropic's tool_use schema AND OpenAI's tool_calls /
// function_call schemas. The supported tool names are file-access
// primitives covering both Claude Code conventions (Read, Write, Edit,
// MultiEdit) and OpenAI/Cursor conventions (read_file, write_file,
// edit_file, apply_diff). Other tools (Bash, Glob, Grep, WebFetch,
// Task, etc.) are intentionally ignored — their path semantics differ
// and policy enforcement is deferred.
//
// pathscan is a leaf package: depends only on stdlib + internal/parser.
package pathscan

import (
	"encoding/json"

	"runveil/internal/parser"
)

// PathEvent is one tool_use invocation that names a file path.
type PathEvent struct {
	Tool         string // tool name (vendor-defined, see supportedTools)
	Path         string // resolved file path (see extractPath)
	MessageIndex int    // position of the originating message in messages[]
}

// supportedTools is the hardcoded allowlist of tool names we extract
// paths from. Anthropic / Claude Code conventions on top; OpenAI /
// Cursor BYOK conventions on the bottom. Unknown tools are skipped.
var supportedTools = map[string]bool{
	// Anthropic / Claude Code
	"Read":      true,
	"Write":     true,
	"Edit":      true,
	"MultiEdit": true,
	// OpenAI / Cursor BYOK
	"read_file":  true,
	"write_file": true,
	"edit_file":  true,
	"apply_diff": true,
}

// ExtractPathEvents returns every file-path argument from supported
// file-access tool_use blocks in the request. Returns nil for unknown
// vendors. path is the HTTP request path, used to dispatch the right
// per-endpoint extractor in parser.ExtractToolUses.
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

// extractPath probes a tool's input JSON for any of the common
// file-path field names. First non-empty wins. Returns "" if none
// present or the input is not valid JSON.
//
// Field name order:
//   - file_path: Anthropic / Claude Code convention.
//   - path:      most common OpenAI tool-definition convention.
//   - filename:  some OpenAI write_file variants.
//   - filepath:  rare variant; included for resilience.
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
