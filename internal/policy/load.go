package policy

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"railcore/internal/detector"
)

// yamlRoot is the on-wire schema of a policy file.
type yamlRoot struct {
	Version int        `yaml:"version"`
	Rules   []yamlRule `yaml:"rules"`
}

type yamlRule struct {
	Name   string    `yaml:"name"`
	Match  yamlMatch `yaml:"match"`
	Action string    `yaml:"action"`
	Note   string    `yaml:"note,omitempty"`
}

type yamlMatch struct {
	Pattern  string `yaml:"pattern,omitempty"`
	Severity string `yaml:"severity,omitempty"`
	All      bool   `yaml:"all,omitempty"`
}

// LoadFromFile reads, parses, validates, and compiles a policy YAML file.
func LoadFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	return LoadFromBytes(data)
}

// LoadFromBytes parses raw YAML bytes. Same validation as LoadFromFile.
func LoadFromBytes(data []byte) (*Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var root yamlRoot
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("policy parse: %w", err)
	}

	if root.Version == 0 {
		return nil, fmt.Errorf("policy: version is required (must be 1)")
	}
	if root.Version != 1 {
		return nil, fmt.Errorf("policy: unsupported version %d, this railcore build supports version 1", root.Version)
	}
	if len(root.Rules) == 0 {
		return nil, fmt.Errorf("policy: rules is required and must contain at least one rule")
	}

	policy := &Policy{Version: root.Version, Rules: make([]Rule, 0, len(root.Rules))}
	seen := make(map[string]bool, len(root.Rules))

	for i, yr := range root.Rules {
		if yr.Name == "" {
			return nil, fmt.Errorf("policy: rule #%d: name is required", i+1)
		}
		if seen[yr.Name] {
			return nil, fmt.Errorf("policy: duplicate rule name %q", yr.Name)
		}
		seen[yr.Name] = true

		rule, err := compileRule(yr)
		if err != nil {
			return nil, fmt.Errorf("policy: rule %q: %w", yr.Name, err)
		}
		policy.Rules = append(policy.Rules, rule)
	}

	return policy, nil
}

func compileRule(yr yamlRule) (Rule, error) {
	action, err := parseAction(yr.Action)
	if err != nil {
		return Rule{}, err
	}

	m, err := compileMatch(yr.Match)
	if err != nil {
		return Rule{}, err
	}

	return Rule{
		Name:   yr.Name,
		Match:  m,
		Action: action,
		Note:   yr.Note,
	}, nil
}

func parseAction(s string) (Action, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "allow":
		return ActionAllow, nil
	case "block":
		return ActionBlock, nil
	case "warn":
		return ActionWarn, nil
	case "":
		return 0, fmt.Errorf("action is required")
	default:
		return 0, fmt.Errorf("invalid action %q, must be one of: allow, block, warn", s)
	}
}

func compileMatch(ym yamlMatch) (Match, error) {
	hasPattern := ym.Pattern != ""
	hasSeverity := ym.Severity != ""
	hasAll := ym.All

	if !hasPattern && !hasSeverity && !hasAll {
		return Match{}, fmt.Errorf("match is required and must contain at least one condition")
	}
	if hasAll && (hasPattern || hasSeverity) {
		return Match{}, fmt.Errorf("match.all cannot be combined with other conditions")
	}

	m := Match{All: hasAll}

	if hasPattern {
		g, err := compileGlob(ym.Pattern)
		if err != nil {
			return Match{}, fmt.Errorf("invalid pattern %q: %w", ym.Pattern, err)
		}
		m.Pattern = g
	}

	if hasSeverity {
		s, err := parseSeverity(ym.Severity)
		if err != nil {
			return Match{}, err
		}
		m.Severity = &s
	}

	return m, nil
}

func parseSeverity(s string) (detector.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return detector.SeverityHigh, nil
	case "medium":
		return detector.SeverityMedium, nil
	case "low":
		return detector.SeverityLow, nil
	default:
		return 0, fmt.Errorf("invalid severity %q, must be one of: high, medium, low", s)
	}
}
