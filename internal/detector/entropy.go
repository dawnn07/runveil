package detector

import "math"

// shannonEntropy returns the Shannon entropy of s in bits per byte.
// Returns 0 for the empty string. Computed over the byte distribution
// of s — this is sufficient for distinguishing low-entropy patterns
// (test fixtures, ALL-CAPS placeholders) from high-entropy random keys.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * math.Log2(p)
	}
	return h
}
