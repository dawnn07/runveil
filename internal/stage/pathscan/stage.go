// Package pathscan implements the pipeline.Stage that extracts file
// paths from Anthropic tool_use blocks and applies policy rules to them.
//
// It is the integration point between internal/pathscan (extraction),
// internal/policy (decision), and internal/pipeline.
package pathscan

import (
	"context"
	"encoding/json"
	"log/slog"

	"railcore/internal/parser"
	"railcore/internal/pathscan"
	"railcore/internal/pipeline"
	"railcore/internal/policy"
)

// Config controls the stage's runtime behavior.
type Config struct {
	// Policy drives all decisions. When nil, the stage is a silent no-op.
	Policy *policy.Policy
}

// PathFinding pairs an extracted PathEvent with the rule that decided
// its fate. Stored in rc.Metadata["pathscan.findings"] for the proxy's
// 403 body and the future audit logger.
type PathFinding struct {
	Tool         string
	Path         string
	MessageIndex int
	Rule         string
}

// MarshalJSON emits the public shape used in 403 bodies. The detector
// field identifies the stage; the rule field is omitted when empty.
func (p PathFinding) MarshalJSON() ([]byte, error) {
	type flat struct {
		Detector     string `json:"detector"`
		Tool         string `json:"tool"`
		Path         string `json:"path"`
		MessageIndex int    `json:"message_index"`
		Rule         string `json:"rule,omitempty"`
	}
	return json.Marshal(flat{
		Detector:     "path-scan",
		Tool:         p.Tool,
		Path:         p.Path,
		MessageIndex: p.MessageIndex,
		Rule:         p.Rule,
	})
}

// Stage is the path-scanning pipeline stage.
type Stage struct {
	cfg Config
	log *slog.Logger
}

// New returns a configured Stage. If log is nil, slog.Default() is used.
func New(cfg Config, log *slog.Logger) *Stage {
	if log == nil {
		log = slog.Default()
	}
	return &Stage{cfg: cfg, log: log}
}

// Name implements pipeline.Stage.
func (s *Stage) Name() string { return "path-scan" }

// Process implements pipeline.Stage.
func (s *Stage) Process(ctx context.Context, rc *pipeline.RequestCtx) (pipeline.Decision, error) {
	if s.cfg.Policy == nil {
		return pipeline.Continue, nil
	}

	body, ok := rc.Metadata["body"].([]byte)
	if !ok {
		return pipeline.Continue, nil
	}

	parsed, err := parser.ParseRequest(rc.Host, rc.Req, body)
	if err != nil || parsed == nil {
		return pipeline.Continue, nil
	}

	events := pathscan.ExtractPathEvents(parsed, body, rc.Req.URL.Path)
	if len(events) == 0 {
		return pipeline.Continue, nil
	}

	requestID, _ := rc.Metadata["request_id"].(string)
	var kept []PathFinding
	anyBlock := false

	for _, e := range events {
		action, rule := s.cfg.Policy.DecidePath(e.Path)
		ruleName := ""
		if rule != nil {
			ruleName = rule.Name
		}

		switch action {
		case policy.ActionAllow:
			s.log.Debug("policy allowed path",
				"request_id", requestID,
				"tool", e.Tool,
				"path", e.Path,
				"rule", ruleName)
			// Suppressed; not appended to kept.
		case policy.ActionBlock:
			kept = append(kept, PathFinding{
				Tool:         e.Tool,
				Path:         e.Path,
				MessageIndex: e.MessageIndex,
				Rule:         ruleName,
			})
			anyBlock = true
			s.log.Warn("pathscan blocked",
				"request_id", requestID,
				"tool", e.Tool,
				"path", e.Path,
				"rule", ruleName)
		case policy.ActionWarn:
			fallthrough
		default:
			kept = append(kept, PathFinding{
				Tool:         e.Tool,
				Path:         e.Path,
				MessageIndex: e.MessageIndex,
				Rule:         ruleName,
			})
			if ruleName != "" {
				s.log.Info("pathscan findings",
					"request_id", requestID,
					"tool", e.Tool,
					"path", e.Path,
					"rule", ruleName)
			}
		}
	}

	if len(kept) == 0 {
		return pipeline.Continue, nil
	}

	rc.Metadata["pathscan.findings"] = kept

	if anyBlock {
		return pipeline.Block, nil
	}
	return pipeline.Continue, nil
}
