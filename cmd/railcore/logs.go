package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"railcore/internal/audit"
)

func runLogs(args []string) {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "directory containing audit.log")
	filePath := fs.String("file", "", "explicit path to audit log (overrides --data-dir)")
	numLines := fs.Int("n", 50, "number of recent records to show before exiting / starting follow")
	follow := fs.Bool("follow", false, "after the initial output, stream new records as they arrive")
	fs.BoolVar(follow, "f", false, "shorthand for --follow")
	jsonOut := fs.Bool("json", false, "print raw JSON lines instead of the pretty format")
	_ = fs.Parse(args)

	if *numLines <= 0 {
		fmt.Fprintln(os.Stderr, "logs: -n must be > 0")
		os.Exit(2)
	}

	path := *filePath
	if path == "" {
		path = filepath.Join(*dataDir, "audit.log")
	}

	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "logs: %s: file not found. Has the proxy run yet?\n", path)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "logs: open %s: %v\n", path, err)
		os.Exit(1)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logs: read %s: %v\n", path, err)
		os.Exit(1)
	}
	records, skipped := parseAuditBytes(data)
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "logs: skipped %d malformed lines\n", skipped)
	}

	startIdx := 0
	if len(records) > *numLines {
		startIdx = len(records) - *numLines
	}
	for _, r := range records[startIdx:] {
		emit(r, *jsonOut)
	}

	if !*follow {
		return
	}

	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logs: seek end: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		fi, err := f.Stat()
		if err != nil {
			continue
		}
		if fi.Size() < offset {
			f.Close()
			f, err = os.Open(path)
			if err != nil {
				continue
			}
			offset = 0
			scanner = bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 1024*1024)
			continue
		}
		if fi.Size() == offset {
			continue
		}
		for scanner.Scan() {
			var r audit.Record
			if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
				continue
			}
			emit(r, *jsonOut)
		}
		offset, _ = f.Seek(0, io.SeekCurrent)
	}
}

// parseAuditBytes scans newline-separated JSON Lines and returns the
// successfully-parsed records plus the count of lines that failed to
// parse (which the caller may surface as a warning).
func parseAuditBytes(data []byte) (records []audit.Record, skipped int) {
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r audit.Record
		if err := json.Unmarshal(line, &r); err != nil {
			skipped++
			continue
		}
		records = append(records, r)
	}
	return records, skipped
}

func emit(r audit.Record, jsonOut bool) {
	if jsonOut {
		raw, err := json.Marshal(r)
		if err != nil {
			return
		}
		os.Stdout.Write(raw)
		os.Stdout.Write([]byte("\n"))
		return
	}
	fmt.Println(formatRecord(r))
}

func formatRecord(r audit.Record) string {
	statusIcon := "✓"
	if r.Status >= 400 {
		statusIcon = "✗"
	}
	hhmmss := r.Time.Format("15:04:05")
	base := fmt.Sprintf("%s  %s  %-4s  %-22s  %-30s  %3d  %5dms  %s",
		hhmmss, statusIcon, r.Method, r.Host, truncate(r.Path, 30), r.Status, r.DurationMs, r.Decision)
	if len(r.Findings) > 0 {
		ruleNames := extractRuleNames(r.Findings)
		base += fmt.Sprintf("  findings=%d [%s]", len(r.Findings), strings.Join(ruleNames, ","))
	}
	return base
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func extractRuleNames(findings []any) []string {
	var names []string
	for _, f := range findings {
		m, ok := f.(map[string]any)
		if !ok {
			continue
		}
		rule, ok := m["rule"].(string)
		if !ok || rule == "" {
			continue
		}
		names = append(names, rule)
	}
	return names
}
