// End-to-end tests for sub-project #3: real http.Client through a real
// proxy that has a real Policy loaded from inline YAML, against a fake
// httptest upstream.
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
	"railcore/internal/stage/secretscan"
)

func setupPolicy(t *testing.T, policyYAML string) (client *http.Client, upstreamHits *int32, cleanup func()) {
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
	chain.Register(secretscan.New(secretscan.Config{Policies: policy.NewProvider(pol)}, nil))

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
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "api.openai.com"},
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

func TestPolicy_E2E_YAMLBlocksAWS(t *testing.T) {
	yaml := `
version: 1
rules:
  - name: block-aws
    match: {pattern: aws_*}
    action: block
  - name: default
    match: {all: true}
    action: warn
`
	client, upstreamHits, cleanup := setupPolicy(t, yaml)
	defer cleanup()

	body := `{
		"model": "gpt-4o",
		"messages": [
			{"role": "user", "content": "key: AKIAIOSFODNN7EXAMPLE here"}
		]
	}`
	resp, err := client.Post("https://api.openai.com/v1/chat/completions", "application/json", strings.NewReader(body))
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
	if parsed.Findings[0]["rule"] != "block-aws" {
		t.Errorf("rule = %v, want block-aws", parsed.Findings[0]["rule"])
	}
	if strings.Contains(string(respBody), "AKIA") {
		t.Errorf("response body contains matched secret bytes: %s", string(respBody))
	}
}

func TestPolicy_E2E_YAMLAllowlistOverridesBlock(t *testing.T) {
	yaml := `
version: 1
rules:
  - name: allow-fixture
    match: {pattern: aws_access_key_id}
    action: allow
  - name: block-aws
    match: {pattern: aws_*}
    action: block
`
	client, upstreamHits, cleanup := setupPolicy(t, yaml)
	defer cleanup()

	body := `{
		"model": "gpt-4o",
		"messages": [
			{"role": "user", "content": "key: AKIAIOSFODNN7EXAMPLE"}
		]
	}`
	resp, err := client.Post("https://api.openai.com/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (allow rule precedes block)", resp.StatusCode)
	}
	if got := atomic.LoadInt32(upstreamHits); got != 1 {
		t.Fatalf("upstream hits = %d, want 1", got)
	}
}

func TestPolicy_E2E_BadYAMLFailsLoader(t *testing.T) {
	_, err := policy.LoadFromBytes([]byte(`
version: 1
rules:
  - name: r
    match: {pattern: ""}
    action: warn
`))
	if err == nil {
		t.Fatal("expected error from policy.LoadFromBytes on invalid glob")
	}
	if !strings.Contains(err.Error(), "rule") {
		t.Errorf("error message should mention which rule failed; got %q", err.Error())
	}
}
