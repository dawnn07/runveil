// Package secretscan implements the pipeline.Stage that parses outgoing
// AI requests and scans extracted prompt content for secrets.
//
// It is the integration point between internal/parser, internal/detector,
// and internal/pipeline — and the only package that imports both parser
// and detector.
package secretscan

import (
	"context"
	"encoding/json"
	"log/slog"
	"unicode/utf8"

	"railcore/internal/detector"
	"railcore/internal/parser"
	"railcore/internal/pipeline"
	"railcore/internal/policy"
)

// Config controls the stage's runtime behaviour.
type Config struct {
	// BlockOnDetect: when true, any High-severity finding produces Block.
	// Medium/Low never block. When false (default), all findings are
	// logged but the request still proceeds upstream.
	BlockOnDetect bool           // used when Policy is nil
	Policy        *policy.Policy // when non-nil, drives all decisions
}

// EnrichedFinding pairs a detector.Finding with the segment metadata
// (which message it came from). Stored in rc.Metadata for future audit
// logging by sub-project #6.
//
// MarshalJSON serializes to a flat public shape that the proxy uses
// directly when building the 403 body — no normalisation needed.
type EnrichedFinding struct {
	Finding      detector.Finding
	Role         string
	MessageIndex int
	Rule         string // name of the rule that decided this finding; "" if no policy in use
}

// MarshalJSON emits the public shape used in 403 responses and audit logs.
func (e EnrichedFinding) MarshalJSON() ([]byte, error) {
	type flat struct {
		Pattern      string `json:"pattern"`
		Severity     string `json:"severity"`
		Role         string `json:"role"`
		MessageIndex int    `json:"message_index"`
		Rule         string `json:"rule,omitempty"`
	}
	return json.Marshal(flat{
		Pattern:      e.Finding.Pattern,
		Severity:     e.Finding.Severity.String(),
		Role:         e.Role,
		MessageIndex: e.MessageIndex,
		Rule:         e.Rule,
	})
}

// Stage is the secret-scanning pipeline stage.
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
func (s *Stage) Name() string { return "secret-scan" }

// Process implements pipeline.Stage. See the package doc for behaviour.
func (s *Stage) Process(ctx context.Context, rc *pipeline.RequestCtx) (pipeline.Decision, error) {
	body, ok := rc.Metadata["body"].([]byte)
	if !ok {
		return pipeline.Continue, nil
	}

	parsed, err := parser.ParseRequest(rc.Host, rc.Req, body)
	if err != nil {
		s.log.Debug("secretscan parser error",
			"host", rc.Host,
			"err", err.Error())
		return pipeline.Continue, nil
	}
	if parsed == nil {
		return pipeline.Continue, nil
	}

	var enriched []EnrichedFinding
	var highCount, medCount, lowCount int
	var highPatterns []string

	for _, seg := range parsed.Texts {
		if !utf8.ValidString(seg.Content) {
			continue
		}
		for _, f := range detector.Scan(seg.Content) {
			enriched = append(enriched, EnrichedFinding{
				Finding:      f,
				Role:         seg.Role,
				MessageIndex: seg.Index,
			})
			switch f.Severity {
			case detector.SeverityHigh:
				highCount++
				highPatterns = append(highPatterns, f.Pattern)
			case detector.SeverityMedium:
				medCount++
			case detector.SeverityLow:
				lowCount++
			}
		}
	}

	if len(enriched) == 0 {
		return pipeline.Continue, nil
	}

	rc.Metadata["secretscan.findings"] = enriched

	requestID, _ := rc.Metadata["request_id"].(string)

	if highCount > 0 && s.cfg.BlockOnDetect {
		s.log.Warn("secretscan blocked",
			"request_id", requestID,
			"vendor", parsed.Vendor,
			"endpoint", parsed.Endpoint,
			"high", highCount,
			"medium", medCount,
			"low", lowCount,
			"patterns", highPatterns)
		return pipeline.Block, nil
	}

	s.log.Info("secretscan findings",
		"request_id", requestID,
		"vendor", parsed.Vendor,
		"endpoint", parsed.Endpoint,
		"high", highCount,
		"medium", medCount,
		"low", lowCount)
	return pipeline.Continue, nil
}
