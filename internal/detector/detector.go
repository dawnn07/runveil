// Package detector scans plain text for high-confidence secrets like API
// keys, tokens, and private keys. It is a leaf package: it must not
// import any other internal/ package.
//
// Pattern definitions live in patterns.go. Pattern provenance is
// documented in patterns.go's header — most patterns are derived from
// the open-source secretlint, trufflehog, and gitleaks catalogs.
package detector

import (
	"regexp"
	"sort"
	"sync"
)

// Severity is the confidence tier of a finding.
//
// Only High-severity findings are eligible for Block when the operator
// has enabled --block-on-detect. Medium and Low are WARN-only regardless
// of flag state.
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
)

func (s Severity) String() string {
	switch s {
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "unknown"
	}
}

// Finding describes one detected secret. The matched substring is
// deliberately NOT included — callers can compute it from text[Offset:Offset+Length]
// if they need it, but the Finding itself never carries secret bytes.
type Finding struct {
	Pattern  string
	Severity Severity
	Offset   int
	Length   int
}

// Pattern is one secret-detection rule.
type Pattern struct {
	Name             string
	Severity         Severity
	Regex            *regexp.Regexp
	EntropyThreshold float64 // 0 = no entropy filter
	// EntropySpan, if non-nil, returns the byte range within a match
	// whose entropy is measured. Defaults to the whole match.
	EntropySpan func(text string, match []int) (start, end int)
}

var (
	mu       sync.RWMutex
	patterns []Pattern
)

// AddPattern registers an additional pattern at runtime. Intended for
// sub-project #3's YAML policy loader. Not part of a stable API yet;
// behaviour may change.
func AddPattern(p Pattern) {
	mu.Lock()
	patterns = append(patterns, p)
	mu.Unlock()
}

// Scan runs all registered patterns over text and returns findings
// sorted by offset. Scan is pure: no I/O, no logging, no side effects.
// Safe for concurrent use.
func Scan(text string) []Finding {
	if text == "" {
		return nil
	}
	mu.RLock()
	defer mu.RUnlock()
	var out []Finding
	for _, p := range patterns {
		matches := p.Regex.FindAllStringIndex(text, -1)
		for _, m := range matches {
			if p.EntropyThreshold > 0 {
				start, end := m[0], m[1]
				if p.EntropySpan != nil {
					start, end = p.EntropySpan(text, m)
				}
				if end <= start || end > len(text) {
					continue
				}
				if shannonEntropy(text[start:end]) < p.EntropyThreshold {
					continue
				}
			}
			out = append(out, Finding{
				Pattern:  p.Name,
				Severity: p.Severity,
				Offset:   m[0],
				Length:   m[1] - m[0],
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	return out
}
