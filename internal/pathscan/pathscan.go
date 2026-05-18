// Package pathscan extracts file-path tool_use events from parsed AI
// vendor request bodies.
//
// Currently supports Anthropic's tool_use schema. The supported tool
// names are file-access primitives: Read, Write, Edit, MultiEdit.
// Other tools (Bash, Glob, Grep, WebFetch, Task) are intentionally
// ignored — their path semantics are different and deferred.
//
// pathscan is a leaf package: depends only on stdlib + internal/parser.
package pathscan

import (
	"encoding/json"

	"railcore/internal/parser"
)

// PathEvent is one tool_use invocation that names a file path.
type PathEvent struct {
	Tool         string // "Read" | "Write" | "Edit" | "MultiEdit"
	Path         string // value of input.file_path
	MessageIndex int    // position of the originating message in messages[]
}

// supportedTools is the hardcoded list of tool names we extract paths
// from. Other tools are intentionally skipped.
var supportedTools = map[string]bool{
	"Read":      true,
	"Write":     true,
	"Edit":      true,
	"MultiEdit": true,
}

// ExtractPathEvents returns every file_path argument from supported
// file-access tool_use blocks in the request. Returns nil for
// non-Anthropic vendors. Returns empty (or nil) slice for Anthropic
// bodies with no recognized tool_use blocks.
//
// body is the raw request body — passed alongside parsed so we can use
// the typed parser.ExtractToolUses helper.
func ExtractPathEvents(parsed *parser.ParsedRequest, body []byte) []PathEvent {
	if parsed == nil || parsed.Vendor != "anthropic" {
		return nil
	}
	// TODO(sp7-task4): replace the "/v1/messages" literal with the real
	// request path so OpenAI requests are also scanned.
	tools := parser.ExtractToolUses("api.anthropic.com", "/v1/messages", body)
	if len(tools) == 0 {
		return nil
	}
	var out []PathEvent
	for _, tu := range tools {
		if !supportedTools[tu.Tool] {
			continue
		}
		var input struct {
			FilePath string `json:"file_path"`
		}
		if err := json.Unmarshal(tu.Input, &input); err != nil {
			continue
		}
		if input.FilePath == "" {
			continue
		}
		out = append(out, PathEvent{
			Tool:         tu.Tool,
			Path:         input.FilePath,
			MessageIndex: tu.MessageIndex,
		})
	}
	return out
}
