package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// globPattern is a compiled glob. We translate the glob syntax into a
// fully-anchored regex (^...$) so equality is a single boolean.
//
// Supported metacharacters:
//
//   - matches any sequence of characters (including empty)
//     ?  matches exactly one character
//
// All other characters are matched literally. Regex metacharacters in
// the input are quoted via regexp.QuoteMeta so they cannot escape into
// the underlying regex.
type globPattern struct {
	raw string
	re  *regexp.Regexp
}

// compileGlob translates a glob string into an anchored regex.
// Empty input is invalid (and likely a YAML mistake).
func compileGlob(s string) (*globPattern, error) {
	if s == "" {
		return nil, fmt.Errorf("empty glob")
	}

	var b strings.Builder
	b.WriteString("^")
	for _, r := range s {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")

	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, fmt.Errorf("compile glob %q: %w", s, err)
	}
	return &globPattern{raw: s, re: re}, nil
}

// match reports whether name matches the compiled glob. Case-sensitive.
func (g *globPattern) match(name string) bool {
	if g == nil || g.re == nil {
		return false
	}
	return g.re.MatchString(name)
}
