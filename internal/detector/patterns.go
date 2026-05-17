// Pattern provenance: patterns in this file are derived from public
// catalogs in secretlint (MIT), gitleaks (MIT), and trufflehog (various
// licenses; the regex strings themselves are facts and we cite for
// hygiene rather than legal necessity). Where patterns differ from
// upstream we have tightened them to reduce false positives.
//
// Each pattern entry: name, severity, regex, optional entropy threshold,
// optional entropy span. Add a corresponding positive + negative unit
// test in detector_test.go when adding a new pattern.

package detector

import "regexp"

func init() {
	// AWS Access Key ID: AKIA + 16 random base32-ish chars.
	// Entropy filter on the 16-char suffix rejects test fixtures like
	// AKIAEXAMPLEKEY or AKIA0000000000000000.
	register(Pattern{
		Name:             "aws_access_key_id",
		Severity:         SeverityHigh,
		Regex:            regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		EntropyThreshold: 3.0,
		EntropySpan: func(text string, m []int) (int, int) {
			// Skip the AKIA prefix; measure entropy on the 16-char suffix.
			return m[0] + 4, m[1]
		},
	})
}

// register is a package-private convenience for init-time pattern
// registration. AddPattern (exported) is for runtime registration by
// the policy loader.
func register(p Pattern) {
	mu.Lock()
	patterns = append(patterns, p)
	mu.Unlock()
}
