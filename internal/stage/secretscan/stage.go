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
)

// Config controls the stage's runtime behaviour.
type Config struct {
	// BlockOnDetect: when true, any High-severity finding produces Block.
	// Medium/Low never block. When false (default), all findings are
	// logged but the request still proceeds upstream.
	BlockOnDetect bool
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
}

// MarshalJSON emits the public shape used in 403 responses and audit logs.
func (e EnrichedFinding) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Pattern      string `json:"pattern"`
		Severity     string `json:"severity"`
		Role         string `json:"role"`
		MessageIndex int    `json:"message_index"`
	}{
		Pattern:      e.Finding.Pattern,
		Severity:     e.Finding.Severity.String(),
		Role:         e.Role,
		MessageIndex: e.MessageIndex,
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

	// DIAGNOSTIC: dump first 200 bytes of body for AI hosts so we can
	// see what Claude Code etc. are actually sending. REMOVE BEFORE MERGE.
	if rc.Host == "api.anthropic.com" || rc.Host == "api.openai.com" {
		preview := body
		if len(preview) > 200 {
			preview = preview[:200]
		}
		s.log.Info("DIAG body preview",
			"host", rc.Host,
			"path", rc.Req.URL.Path,
			"content_encoding", rc.Req.Header.Get("Content-Encoding"),
			"body_len", len(body),
			"body_first_200_bytes", string(preview))
	}

	parsed, err := parser.ParseRequest(rc.Host, rc.Req, body)
	if err != nil {
		s.log.Info("DIAG parser error",
			"host", rc.Host,
			"err", err.Error())
		return pipeline.Continue, nil
	}
	if parsed == nil {
		s.log.Info("DIAG parser returned nil (unknown endpoint)",
			"host", rc.Host,
			"method", rc.Req.Method,
			"path", rc.Req.URL.Path)
		return pipeline.Continue, nil
	}

	// DIAGNOSTIC: dump segments extracted from the parsed request.
	// REMOVE BEFORE MERGE.
	for i, seg := range parsed.Texts {
		contentPreview := seg.Content
		if len(contentPreview) > 300 {
			contentPreview = contentPreview[:300]
		}
		s.log.Info("DIAG parsed segment",
			"seg_i", i,
			"role", seg.Role,
			"index", seg.Index,
			"content_len", len(seg.Content),
			"content_preview", contentPreview)
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
