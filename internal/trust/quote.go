package trust

import "strings"

// shellQuote wraps s for safe use as a single argument in POSIX shells.
// It uses single-quote wrapping and escapes any embedded single quotes,
// which is the only character single-quotes do not handle.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
