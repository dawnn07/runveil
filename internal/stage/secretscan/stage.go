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
		s.log.Debug("secretscan parser error", "host", rc.Host, "err", err.Error())
		return pipeline.Continue, nil
	}
	if parsed == nil {
		return pipeline.Continue, nil
	}

	// Collect raw findings (one per detector.Scan hit per text segment).
	var raw []EnrichedFinding
	for _, seg := range parsed.Texts {
		if !utf8.ValidString(seg.Content) {
			continue
		}
		for _, f := range detector.Scan(seg.Content) {
			raw = append(raw, EnrichedFinding{
				Finding:      f,
				Role:         seg.Role,
				MessageIndex: seg.Index,
			})
		}
	}

	if len(raw) == 0 {
		return pipeline.Continue, nil
	}

	if s.cfg.Policy != nil {
		return s.decideWithPolicy(rc, parsed, raw)
	}
	return s.decideWithFlag(rc, parsed, raw)
}

// decideWithFlag implements the sub-project #2 semantics: WARN by default,
// BLOCK on any High finding when cfg.BlockOnDetect is true.
func (s *Stage) decideWithFlag(rc *pipeline.RequestCtx, parsed *parser.ParsedRequest, raw []EnrichedFinding) (pipeline.Decision, error) {
	var highCount, medCount, lowCount int
	var highPatterns []string
	for _, f := range raw {
		switch f.Finding.Severity {
		case detector.SeverityHigh:
			highCount++
			highPatterns = append(highPatterns, f.Finding.Pattern)
		case detector.SeverityMedium:
			medCount++
		case detector.SeverityLow:
			lowCount++
		}
	}

	rc.Metadata["secretscan.findings"] = raw
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

// decideWithPolicy applies the configured Policy rule-by-rule, suppresses
// allowed findings, blocks if any rule's action is Block, otherwise warns.
func (s *Stage) decideWithPolicy(rc *pipeline.RequestCtx, parsed *parser.ParsedRequest, raw []EnrichedFinding) (pipeline.Decision, error) {
	requestID, _ := rc.Metadata["request_id"].(string)

	var kept []EnrichedFinding
	var blockRules []string
	var ruleNames []string
	var blockPatterns []string
	var highCount, medCount, lowCount int
	anyBlock := false

	for _, f := range raw {
		action, rule := s.cfg.Policy.Decide(f.Finding)
		ruleName := ""
		if rule != nil {
			ruleName = rule.Name
		}

		switch action {
		case policy.ActionAllow:
			s.log.Debug("policy allowed",
				"request_id", requestID,
				"pattern", f.Finding.Pattern,
				"rule", ruleName)
			// Suppressed: do not keep, do not count.
		case policy.ActionBlock:
			f.Rule = ruleName
			kept = append(kept, f)
			anyBlock = true
			blockRules = append(blockRules, ruleName)
			blockPatterns = append(blockPatterns, f.Finding.Pattern)
			bumpCount(&highCount, &medCount, &lowCount, f.Finding.Severity)
		case policy.ActionWarn:
			fallthrough
		default:
			f.Rule = ruleName
			kept = append(kept, f)
			if ruleName != "" {
				ruleNames = append(ruleNames, ruleName)
			}
			bumpCount(&highCount, &medCount, &lowCount, f.Finding.Severity)
		}
	}

	if len(kept) == 0 {
		return pipeline.Continue, nil
	}

	rc.Metadata["secretscan.findings"] = kept

	if anyBlock {
		s.log.Warn("secretscan blocked",
			"request_id", requestID,
			"vendor", parsed.Vendor,
			"endpoint", parsed.Endpoint,
			"high", highCount,
			"medium", medCount,
			"low", lowCount,
			"block_rules", blockRules,
			"patterns", blockPatterns)
		return pipeline.Block, nil
	}

	s.log.Info("secretscan findings",
		"request_id", requestID,
		"vendor", parsed.Vendor,
		"endpoint", parsed.Endpoint,
		"high", highCount,
		"medium", medCount,
		"low", lowCount,
		"rules_fired", ruleNames)
	return pipeline.Continue, nil
}

func bumpCount(high, med, low *int, sev detector.Severity) {
	switch sev {
	case detector.SeverityHigh:
		*high++
	case detector.SeverityMedium:
		*med++
	case detector.SeverityLow:
		*low++
	}
}
