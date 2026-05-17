// Package policy parses and evaluates YAML-driven decision rules over
// detector findings. It is a leaf package: it depends only on stdlib
// and internal/detector (for the Severity enum).
//
// See internal/policy/load.go for the YAML schema and validation.
package policy

import (
	"railcore/internal/detector"
)

// Action is what a policy decides to do with a single finding.
//
// Only ActionBlock causes the proxy to return 403. ActionAllow suppresses
// the finding from logs and from the BLOCK count. ActionWarn is the
// "log but allow upstream" default.
type Action int

const (
	ActionWarn  Action = iota // default
	ActionAllow                // suppress this finding
	ActionBlock                // halt the request
)

// String returns a stable lowercase name for logs and JSON.
func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionBlock:
		return "block"
	case ActionWarn:
		return "warn"
	default:
		return "unknown"
	}
}

// Rule is one entry from the YAML rules list, post-compilation and
// validation. Rules are evaluated top-down; the first matching rule wins.
type Rule struct {
	Name   string
	Match  Match
	Action Action
	Note   string
}

// Match is the compiled match conditions for a Rule.
//
// At evaluation time the engine checks: if All is true, the match is
// unconditional. Otherwise, all non-nil/zero-valued fields are AND'd —
// e.g., Pattern!=nil AND Severity!=nil means both must match.
//
// The loader rejects a Match with no conditions at all, so at least one
// of {Pattern, Severity, All} is always meaningful.
type Match struct {
	Pattern  *globPattern        // nil = no pattern condition
	Severity *detector.Severity  // nil = no severity condition
	All      bool
}

// Policy is a loaded, validated, compiled policy ready for Decide.
// Read-only after loading. Concurrency-safe.
type Policy struct {
	Version int
	Rules   []Rule
}

// Decide returns the action and matching rule for a single finding.
// Rules are tried in order; the first match wins. Returns
// (ActionWarn, nil) if no rule matches or if p is nil/empty.
//
// Decide is safe for concurrent use after construction.
func (p *Policy) Decide(f detector.Finding) (Action, *Rule) {
	if p == nil {
		return ActionWarn, nil
	}
	for i := range p.Rules {
		if matches(&p.Rules[i].Match, f) {
			return p.Rules[i].Action, &p.Rules[i]
		}
	}
	return ActionWarn, nil
}

// matches reports whether m matches f. Defined here (not in match.go)
// so the rule-iteration logic and the match logic can be unit-tested
// independently. The actual glob compile machinery lives in match.go.
func matches(m *Match, f detector.Finding) bool {
	if m.All {
		return true
	}
	if m.Pattern != nil && !m.Pattern.match(f.Pattern) {
		return false
	}
	if m.Severity != nil && *m.Severity != f.Severity {
		return false
	}
	// At least one condition must have been present (loader validates this).
	// All present conditions matched.
	return m.Pattern != nil || m.Severity != nil
}
