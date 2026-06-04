package detector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCorpus_LowFPOnCleanText runs Scan over a small known-clean corpus
// and asserts the false-positive count stays low. Not a hard CI gate;
// the limit is generous so it catches regressions without blocking
// legitimate new patterns.
func TestCorpus_LowFPOnCleanText(t *testing.T) {
	corpus := loadCorpus(t)
	if len(corpus) < 1000 {
		t.Fatalf("corpus too small (%d bytes); add more files", len(corpus))
	}

	findings := Scan(corpus)

	// We allow up to 3 false positives across the whole corpus. Anything
	// more suggests a recently-added pattern is too eager.
	const maxFP = 3
	if len(findings) > maxFP {
		t.Errorf("corpus produced %d findings; want ≤ %d. Patterns matched:", len(findings), maxFP)
		for _, f := range findings {
			t.Errorf("  - %s (severity=%s) at offset %d", f.Pattern, f.Severity, f.Offset)
		}
	}
}

// loadCorpus concatenates the contents of a few known-clean Go source
// files from this repo to use as the corpus. Using project-internal
// files (rather than checked-in test fixtures) keeps the corpus
// representative and self-updating.
func loadCorpus(t *testing.T) string {
	t.Helper()
	repoRoot := findRepoRoot(t)
	files := []string{
		"cmd/runveil/main.go",
		"internal/ca/ca.go",
		"internal/ca/leaf.go",
		"internal/proxy/server.go",
		"internal/proxy/upstream.go",
		"internal/proxy/intercept.go",
		"internal/pipeline/chain.go",
		"internal/pipeline/stage.go",
	}
	var b strings.Builder
	for _, f := range files {
		path := filepath.Join(repoRoot, f)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read corpus file %s: %v", path, err)
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	return b.String()
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not find repo root (no go.mod within 10 parents of cwd)")
	return ""
}
