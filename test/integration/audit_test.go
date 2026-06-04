// End-to-end tests for sub-project #6: real http.Client through a real
// proxy with a real audit.Writer writing to a temp file. Asserts the
// audit log contains well-formed JSON records.
package integration

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"runveil/internal/audit"
	"runveil/internal/ca"
	"runveil/internal/pipeline"
	"runveil/internal/policy"
	"runveil/internal/proxy"
	pathscanstage "runveil/internal/stage/pathscan"
)

func setupAudit(t *testing.T, policyYAML string) (client *http.Client, auditPath string, cleanup func()) {
	t.Helper()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	tmpDir := t.TempDir()
	auditPath = filepath.Join(tmpDir, "audit.log")

	auditWriter, err := audit.NewWriter(audit.Config{
		Path:       auditPath,
		MaxSizeMB:  10,
		MaxBackups: 1,
		MaxAgeDays: 1,
	}, nil)
	if err != nil {
		t.Fatalf("audit.NewWriter: %v", err)
	}

	caInst, err := ca.GenerateOrLoad(tmpDir + "/ca")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	chain := pipeline.NewChain()
	if policyYAML != "" {
		pol, err := policy.LoadFromBytes([]byte(policyYAML))
		if err != nil {
			t.Fatalf("policy.LoadFromBytes: %v", err)
		}
		chain.Register(pathscanstage.New(pathscanstage.Config{Policies: policy.NewProvider(pol)}, nil))
	}

	srv := proxy.New(proxy.Config{
		Addr:             "127.0.0.1:0",
		CA:               caInst,
		Pipeline:         chain,
		UpstreamTLS:      &tls.Config{RootCAs: upstreamPool, ServerName: upstreamURL.Hostname()},
		UpstreamResolver: func(_ string) (string, error) { return upstreamURL.Host, nil },
		AuditFunc:        auditWriter,
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Serve(ctx, ln)

	caPool := x509.NewCertPool()
	caPool.AddCert(caInst.RootCert())
	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client = &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "api.anthropic.com"},
		},
		Timeout: 10 * time.Second,
	}

	cleanupCalled := false
	cleanup = func() {
		if cleanupCalled {
			return
		}
		cleanupCalled = true
		cancel()
		_ = ln.Close()
		upstream.Close()
		_ = auditWriter.Close()
	}
	return client, auditPath, cleanup
}

func TestAudit_E2E_RequestProducesAuditLine(t *testing.T) {
	client, auditPath, cleanup := setupAudit(t, "")
	defer cleanup()

	body := `{"model":"claude-opus-4-7","messages":[{"role":"user","content":"hi"}]}`
	resp, err := client.Post("https://api.anthropic.com/v1/messages", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// The proxy's audit Log call happens in a defer after the response
	// is streamed to the client, so it may not have landed yet. Wait for
	// the audit file to contain at least one line before closing.
	records := waitForAuditRecords(t, auditPath, 1, 2*time.Second)

	// Flush the audit writer; idempotent.
	cleanup()

	if len(records) != 1 {
		t.Fatalf("got %d audit records, want 1", len(records))
	}
	r := records[0]
	if r.Decision != "continue" {
		t.Errorf("Decision = %q, want continue", r.Decision)
	}
	if r.Host != "api.anthropic.com" {
		t.Errorf("Host = %q, want api.anthropic.com", r.Host)
	}
	if r.Vendor != "anthropic" || r.Endpoint != "messages" {
		t.Errorf("Vendor/Endpoint = %q/%q", r.Vendor, r.Endpoint)
	}
}

func TestAudit_E2E_BlockProducesAuditLineWithFindings(t *testing.T) {
	yaml := `
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
`
	client, auditPath, cleanup := setupAudit(t, yaml)
	defer cleanup()

	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "t1", "name": "Read",
				 "input": {"file_path": "/src/payments/charge.go"}}
			]}
		]
	}`
	resp, err := client.Post("https://api.anthropic.com/v1/messages", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	records := waitForAuditRecords(t, auditPath, 1, 2*time.Second)
	cleanup()

	if len(records) != 1 {
		t.Fatalf("got %d audit records, want 1", len(records))
	}
	r := records[0]
	if r.Decision != "block" {
		t.Errorf("Decision = %q, want block", r.Decision)
	}
	if len(r.Findings) < 1 {
		t.Fatalf("Findings should not be empty; got %+v", r.Findings)
	}
	f0, ok := r.Findings[0].(map[string]any)
	if !ok {
		t.Fatalf("Findings[0] is not a map: %T", r.Findings[0])
	}
	if f0["detector"] != "path-scan" {
		t.Errorf("detector = %v, want path-scan", f0["detector"])
	}
}

// waitForAuditRecords polls auditPath until it contains at least want
// fully-parseable JSON records, or timeout elapses. The audit writer is
// async (proxy's defer enqueues, a background goroutine flushes), so a
// short poll is more reliable than a fixed sleep on slow CI. Returns
// whatever was parsed at the moment the condition was met (or timed
// out); the caller asserts the expected count.
func waitForAuditRecords(t *testing.T, auditPath string, want int, timeout time.Duration) []audit.Record {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var records []audit.Record
	for time.Now().Before(deadline) {
		records = readAuditRecords(t, auditPath)
		if len(records) >= want {
			return records
		}
		time.Sleep(20 * time.Millisecond)
	}
	return records
}

func readAuditRecords(t *testing.T, auditPath string) []audit.Record {
	t.Helper()
	f, err := os.Open(auditPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("open audit: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var records []audit.Record
	for scanner.Scan() {
		var r audit.Record
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			continue
		}
		records = append(records, r)
	}
	return records
}
