// End-to-end tests for sub-project #4: real http.Client through a real
// proxy with the pathscan stage and a real Policy, against a fake
// httptest upstream. Exercises Anthropic tool_use path matching.
package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"railcore/internal/ca"
	"railcore/internal/pipeline"
	"railcore/internal/policy"
	"railcore/internal/proxy"
	pathscanstage "railcore/internal/stage/pathscan"
)

func setupPathscan(t *testing.T, policyYAML string) (client *http.Client, upstreamHits *int32, cleanup func()) {
	t.Helper()

	var hits int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	pol, err := policy.LoadFromBytes([]byte(policyYAML))
	if err != nil {
		t.Fatalf("policy.LoadFromBytes: %v", err)
	}

	caInst, err := ca.GenerateOrLoad(t.TempDir())
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	chain := pipeline.NewChain()
	chain.Register(pathscanstage.New(pathscanstage.Config{Policy: pol}, nil))

	srv := proxy.New(proxy.Config{
		Addr:             "127.0.0.1:0",
		CA:               caInst,
		Pipeline:         chain,
		UpstreamTLS:      &tls.Config{RootCAs: upstreamPool, ServerName: upstreamURL.Hostname()},
		UpstreamResolver: func(_ string) (string, error) { return upstreamURL.Host, nil },
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

	cleanup = func() {
		cancel()
		_ = ln.Close()
		upstream.Close()
	}
	return client, &hits, cleanup
}

func TestPathscan_E2E_BlockOnPayments(t *testing.T) {
	yaml := `
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
  - name: default
    match: {all: true}
    action: warn
`
	client, upstreamHits, cleanup := setupPathscan(t, yaml)
	defer cleanup()

	body := `{
		"model": "claude-opus-4-7",
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := atomic.LoadInt32(upstreamHits); got != 0 {
		t.Fatalf("upstream hits = %d, want 0", got)
	}

	respBody, _ := io.ReadAll(resp.Body)
	var parsed struct {
		Findings []map[string]interface{} `json:"findings"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if len(parsed.Findings) < 1 {
		t.Fatalf("expected >=1 finding, got %d", len(parsed.Findings))
	}
	f := parsed.Findings[0]
	if f["detector"] != "path-scan" {
		t.Errorf("detector = %v, want path-scan", f["detector"])
	}
	if f["tool"] != "Read" {
		t.Errorf("tool = %v, want Read", f["tool"])
	}
	if f["path"] != "/src/payments/charge.go" {
		t.Errorf("path = %v, want /src/payments/charge.go", f["path"])
	}
	if f["rule"] != "block-payments" {
		t.Errorf("rule = %v, want block-payments", f["rule"])
	}
}

func TestPathscan_E2E_AllowOverridesBlock(t *testing.T) {
	yaml := `
version: 1
rules:
  - name: allow-payments-test
    match: {path: "**/payments/test/**"}
    action: allow
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
`
	client, upstreamHits, cleanup := setupPathscan(t, yaml)
	defer cleanup()

	body := `{
		"model": "claude-opus-4-7",
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "t1", "name": "Read",
				 "input": {"file_path": "/src/payments/test/fixture.go"}}
			]}
		]
	}`
	resp, err := client.Post("https://api.anthropic.com/v1/messages", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (allow precedes block)", resp.StatusCode)
	}
	if got := atomic.LoadInt32(upstreamHits); got != 1 {
		t.Fatalf("upstream hits = %d, want 1", got)
	}
}

func TestPathscan_E2E_BadPathYAMLFailsLoader(t *testing.T) {
	_, err := policy.LoadFromBytes([]byte(`
version: 1
rules:
  - name: r
    match: {}
    action: block
`))
	if err == nil {
		t.Fatal("expected error from LoadFromBytes on empty match")
	}
	if !strings.Contains(err.Error(), "match") {
		t.Errorf("error message should mention match; got %q", err.Error())
	}
}
