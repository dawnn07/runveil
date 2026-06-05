// End-to-end test for the redact policy action: a real http.Client sends an
// Anthropic /v1/messages request containing a fake AWS key through an
// in-process proxy configured with action:redact. The test asserts that
//  1. the upstream receives a body with [REDACTED] in place of the secret;
//  2. the proxy forwarded the request (status ≠ 403);
//  3. the audit log records decision:"modify".
package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"runveil/internal/audit"
	"runveil/internal/ca"
	"runveil/internal/pipeline"
	"runveil/internal/policy"
	"runveil/internal/proxy"
	"runveil/internal/stage/secretscan"
)

const redactTestPolicyYAML = `
version: 1
rules:
  - name: redact-aws
    match: {pattern: aws_*}
    action: redact
`

// setupRedactProxyForHost stands up an in-process proxy with the secretscan
// stage using a redact-aws policy, wired to a stub TLS upstream that records
// its request body. It also enables audit logging.
//
// targetHost is the hostname the http.Client will CONNECT through the proxy
// (e.g. "api.anthropic.com" or "api.openai.com"); the proxy redirects all
// traffic to the local stub regardless.
//
// Returns:
//   - client: an *http.Client that routes traffic through the proxy
//   - upstreamBodyCh: a buffered channel (cap 1) receiving the raw bytes the
//     stub upstream observed for the first request
//   - auditPath: path to the audit log file
//   - cleanup: must be called (defer is fine) to tear everything down
func setupRedactProxyForHost(t *testing.T, targetHost string) (client *http.Client, upstreamBodyCh <-chan []byte, auditPath string, cleanup func()) {
	t.Helper()

	bodyCh := make(chan []byte, 1)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		select {
		case bodyCh <- raw:
		default:
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	tmpDir := t.TempDir()
	auditPath = tmpDir + "/audit.log"

	auditWriter, err := audit.NewWriter(audit.Config{
		Path:       auditPath,
		MaxSizeMB:  10,
		MaxBackups: 1,
		MaxAgeDays: 1,
	}, nil)
	if err != nil {
		t.Fatalf("audit.NewWriter: %v", err)
	}

	pol, err := policy.LoadFromBytes([]byte(redactTestPolicyYAML))
	if err != nil {
		t.Fatalf("policy.LoadFromBytes: %v", err)
	}
	provider := policy.NewProvider(pol)

	caInst, err := ca.GenerateOrLoad(tmpDir + "/ca")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}

	chain := pipeline.NewChain()
	chain.Register(secretscan.New(secretscan.Config{Policies: provider}, nil))

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
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: targetHost},
		},
		Timeout: 10 * time.Second,
	}

	var once sync.Once
	cleanup = func() {
		once.Do(func() {
			cancel()
			_ = ln.Close()
			upstream.Close()
			_ = auditWriter.Close()
		})
	}
	return client, bodyCh, auditPath, cleanup
}

// setupRedactProxy is a convenience wrapper around setupRedactProxyForHost
// for callers that target api.anthropic.com.
func setupRedactProxy(t *testing.T) (client *http.Client, upstreamBodyCh <-chan []byte, auditPath string, cleanup func()) {
	t.Helper()
	return setupRedactProxyForHost(t, "api.anthropic.com")
}

// TestRedact_AnthropicEndToEnd verifies the full redact flow end-to-end:
//  1. sends a /v1/messages body containing a fake AWS key through the proxy;
//  2. checks the upstream never saw the raw secret (only [REDACTED]);
//  3. checks the proxy forwarded rather than blocked;
//  4. checks the audit log records decision:"modify".
func TestRedact_AnthropicEndToEnd(t *testing.T) {
	client, upstreamBodyCh, auditPath, cleanup := setupRedactProxy(t)
	defer cleanup()

	const fakeKey = "AKIAIOSFODNN7EXAMPLE"
	reqBody := `{"model":"claude-3","max_tokens":16,"messages":[{"role":"user","content":"my key ` + fakeKey + ` thanks"}]}`

	resp, err := client.Post(
		"https://api.anthropic.com/v1/messages",
		"application/json",
		bytes.NewBufferString(reqBody),
	)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// 1. The proxy must forward (not block).
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("proxy returned 403; expected forwarding for redact action")
	}

	// 2. The upstream must have received the redacted body, not the raw secret.
	var upstreamRaw []byte
	select {
	case upstreamRaw = <-upstreamBodyCh:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not receive the request within 5s")
	}

	if bytes.Contains(upstreamRaw, []byte(fakeKey)) {
		t.Errorf("upstream body still contains the secret %q; upstream body: %s", fakeKey, upstreamRaw)
	}
	if !bytes.Contains(upstreamRaw, []byte("[REDACTED]")) {
		t.Errorf("upstream body does not contain [REDACTED]; upstream body: %s", upstreamRaw)
	}

	// 3. The audit log must record decision:"modify".
	// waitForAuditRecords and readAuditRecords are defined in audit_test.go
	// (same package). The audit write is async (background goroutine flush),
	// so we poll briefly.
	records := waitForAuditRecords(t, auditPath, 1, 3*time.Second)
	cleanup() // flush before asserting

	if len(records) == 0 {
		t.Fatal("no audit records written")
	}
	r := records[0]
	if r.Decision != "modify" {
		t.Errorf("audit decision = %q, want %q", r.Decision, "modify")
	}
	if r.Host != "api.anthropic.com" {
		t.Errorf("audit host = %q, want api.anthropic.com", r.Host)
	}
}

// TestRedact_OpenAIChatEndToEnd verifies the full redact flow end-to-end for
// an OpenAI /v1/chat/completions request:
//  1. sends a request body containing a fake AWS key through the proxy;
//  2. checks the upstream never saw the raw secret (only [REDACTED]);
//  3. checks the proxy forwarded rather than blocked;
//  4. checks the audit log records decision:"modify".
func TestRedact_OpenAIChatEndToEnd(t *testing.T) {
	client, upstreamBodyCh, auditPath, cleanup := setupRedactProxyForHost(t, "api.openai.com")
	defer cleanup()

	const fakeKey = "AKIAIOSFODNN7EXAMPLE"
	reqBody := `{"model":"gpt-4o","messages":[{"role":"user","content":"my key ` + fakeKey + ` thanks"}]}`

	resp, err := client.Post(
		"https://api.openai.com/v1/chat/completions",
		"application/json",
		bytes.NewBufferString(reqBody),
	)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// 1. The proxy must forward (not block).
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("proxy returned 403; expected forwarding for redact action")
	}

	// 2. The upstream must have received the redacted body, not the raw secret.
	var upstreamRaw []byte
	select {
	case upstreamRaw = <-upstreamBodyCh:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not receive the request within 5s")
	}

	if bytes.Contains(upstreamRaw, []byte(fakeKey)) {
		t.Errorf("upstream body still contains the secret %q; upstream body: %s", fakeKey, upstreamRaw)
	}
	if !bytes.Contains(upstreamRaw, []byte("[REDACTED]")) {
		t.Errorf("upstream body does not contain [REDACTED]; upstream body: %s", upstreamRaw)
	}

	// 3. The audit log must record decision:"modify".
	// waitForAuditRecords and readAuditRecords are defined in audit_test.go
	// (same package). The audit write is async (background goroutine flush),
	// so we poll briefly.
	records := waitForAuditRecords(t, auditPath, 1, 3*time.Second)
	cleanup() // flush before asserting

	if len(records) == 0 {
		t.Fatal("no audit records written")
	}
	r := records[0]
	if r.Decision != "modify" {
		t.Errorf("audit decision = %q, want %q", r.Decision, "modify")
	}
	if r.Host != "api.openai.com" {
		t.Errorf("audit host = %q, want api.openai.com", r.Host)
	}
}

// TestRedact_AnthropicToolUseEndToEnd verifies that the redact policy correctly
// scrubs a secret embedded inside a tool_use content block's input object while
// preserving non-secret fields and keeping the body valid JSON:
//  1. sends a /v1/messages body with a tool_use block containing a fake AWS key
//     as the value of "token" field through the proxy;
//  2. checks the upstream never saw the raw secret (only [REDACTED]);
//  3. checks that "path":"/etc" (a non-secret tool-input field) survived;
//  4. checks the upstream body is valid JSON;
//  5. checks the proxy forwarded rather than blocked;
//  6. checks the audit log records decision:"modify".
func TestRedact_AnthropicToolUseEndToEnd(t *testing.T) {
	client, upstreamBodyCh, auditPath, cleanup := setupRedactProxyForHost(t, "api.anthropic.com")
	defer cleanup()

	const fakeKey = "AKIAIOSFODNN7EXAMPLE"
	reqBody := `{"model":"claude-3","max_tokens":16,"messages":[{"role":"assistant","content":[{"type":"tool_use","name":"Read","input":{"path":"/etc","token":"` + fakeKey + `"}}]}]}`

	resp, err := client.Post(
		"https://api.anthropic.com/v1/messages",
		"application/json",
		bytes.NewBufferString(reqBody),
	)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// 1. The proxy must forward (not block).
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("proxy returned 403; expected forwarding for redact action")
	}

	// 2. Collect the body the stub upstream observed.
	var upstreamRaw []byte
	select {
	case upstreamRaw = <-upstreamBodyCh:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not receive the request within 5s")
	}

	// 3. The secret must have been redacted.
	if bytes.Contains(upstreamRaw, []byte(fakeKey)) {
		t.Errorf("upstream body still contains the secret %q; upstream body: %s", fakeKey, upstreamRaw)
	}
	if !bytes.Contains(upstreamRaw, []byte("[REDACTED]")) {
		t.Errorf("upstream body does not contain [REDACTED]; upstream body: %s", upstreamRaw)
	}

	// 4. The non-secret tool-input field must have survived.
	if !bytes.Contains(upstreamRaw, []byte(`"path":"/etc"`)) {
		t.Errorf(`upstream body missing "path":"/etc"; upstream body: %s`, upstreamRaw)
	}

	// 5. The upstream body must still be valid JSON.
	if !json.Valid(upstreamRaw) {
		t.Errorf("upstream body is not valid JSON; upstream body: %s", upstreamRaw)
	}

	// 6. The audit log must record decision:"modify".
	// waitForAuditRecords and readAuditRecords are defined in audit_test.go
	// (same package). The audit write is async (background goroutine flush),
	// so we poll briefly.
	records := waitForAuditRecords(t, auditPath, 1, 3*time.Second)
	cleanup() // flush before asserting

	if len(records) == 0 {
		t.Fatal("no audit records written")
	}
	r := records[0]
	if r.Decision != "modify" {
		t.Errorf("audit decision = %q, want %q", r.Decision, "modify")
	}
	if r.Host != "api.anthropic.com" {
		t.Errorf("audit host = %q, want api.anthropic.com", r.Host)
	}
}

// TestRedact_OpenAIToolArgsEndToEnd verifies that the redact policy correctly
// scrubs a secret embedded inside an OpenAI tool_calls function arguments
// string while preserving non-secret fields and keeping the body valid JSON:
//  1. sends a /v1/chat/completions body with a tool_calls entry whose arguments
//     JSON string contains a fake AWS key through the proxy;
//  2. checks the upstream never saw the raw secret (only [REDACTED]);
//  3. checks that "cmd":"ls" (a non-secret argument) survived;
//  4. checks the upstream body is valid JSON;
//  5. checks the proxy forwarded rather than blocked;
//  6. checks the audit log records decision:"modify".
func TestRedact_OpenAIToolArgsEndToEnd(t *testing.T) {
	client, upstreamBodyCh, auditPath, cleanup := setupRedactProxyForHost(t, "api.openai.com")
	defer cleanup()

	const fakeKey = "AKIAIOSFODNN7EXAMPLE"
	reqBody := `{"model":"gpt-4o","messages":[{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"run","arguments":"{\"cmd\":\"ls\",\"token\":\"` + fakeKey + `\"}"}}]}]}`

	resp, err := client.Post(
		"https://api.openai.com/v1/chat/completions",
		"application/json",
		bytes.NewBufferString(reqBody),
	)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// 1. The proxy must forward (not block).
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("proxy returned 403; expected forwarding for redact action")
	}

	// 2. Collect the body the stub upstream observed.
	var upstreamRaw []byte
	select {
	case upstreamRaw = <-upstreamBodyCh:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not receive the request within 5s")
	}

	// 3. The secret must have been redacted.
	if bytes.Contains(upstreamRaw, []byte(fakeKey)) {
		t.Errorf("upstream body still contains the secret %q; upstream body: %s", fakeKey, upstreamRaw)
	}
	if !bytes.Contains(upstreamRaw, []byte("[REDACTED]")) {
		t.Errorf("upstream body does not contain [REDACTED]; upstream body: %s", upstreamRaw)
	}

	// 4. The non-secret tool argument must have survived.
	if !bytes.Contains(upstreamRaw, []byte("cmd")) {
		t.Errorf(`upstream body missing "cmd" key; upstream body: %s`, upstreamRaw)
	}
	if !bytes.Contains(upstreamRaw, []byte("ls")) {
		t.Errorf(`upstream body missing "ls" value; upstream body: %s`, upstreamRaw)
	}

	// 5. The upstream body must still be valid JSON.
	if !json.Valid(upstreamRaw) {
		t.Errorf("upstream body is not valid JSON; upstream body: %s", upstreamRaw)
	}

	// 6. The audit log must record decision:"modify".
	// waitForAuditRecords and readAuditRecords are defined in audit_test.go
	// (same package). The audit write is async (background goroutine flush),
	// so we poll briefly.
	toolRecords := waitForAuditRecords(t, auditPath, 1, 3*time.Second)
	cleanup() // flush before asserting

	if len(toolRecords) == 0 {
		t.Fatal("no audit records written")
	}
	tr := toolRecords[0]
	if tr.Decision != "modify" {
		t.Errorf("audit decision = %q, want %q", tr.Decision, "modify")
	}
	if tr.Host != "api.openai.com" {
		t.Errorf("audit host = %q, want api.openai.com", tr.Host)
	}
}
