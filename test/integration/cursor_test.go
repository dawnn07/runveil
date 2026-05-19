// End-to-end test for sub-project #7: a real http.Client through a real
// proxy with a path-blocking policy. Sends an OpenAI /v1/responses
// request matching the shape Cursor produces in BYOK + Composer mode,
// and verifies the proxy returns 403 with a path-scan finding.
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
	"testing"
	"time"

	"railcore/internal/ca"
	"railcore/internal/pipeline"
	"railcore/internal/policy"
	"railcore/internal/proxy"
	pathscanstage "railcore/internal/stage/pathscan"
)

func TestCursor_BYOK_OpenAIResponses_BlocksPayments(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	tmpDir := t.TempDir()
	caInst, err := ca.GenerateOrLoad(tmpDir + "/ca")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}

	yaml := `
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
`
	pol, err := policy.LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("policy.LoadFromBytes: %v", err)
	}

	chain := pipeline.NewChain()
	chain.Register(pathscanstage.New(pathscanstage.Config{Policies: policy.NewProvider(pol)}, nil))

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
	defer cancel()
	go srv.Serve(ctx, ln)

	caPool := x509.NewCertPool()
	caPool.AddCert(caInst.RootCert())
	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "api.openai.com"},
		},
		Timeout: 10 * time.Second,
	}

	body := `{
		"model": "gpt-4.1",
		"input": [
			{"role": "user", "content": "open the charge file"},
			{"type": "function_call", "name": "read_file",
			 "arguments": "{\"path\":\"/src/payments/charge.go\"}",
			 "call_id": "fc_1"}
		]
	}`
	resp, err := client.Post("https://api.openai.com/v1/responses", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Status = %d, want 403", resp.StatusCode)
	}
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["error"] != "blocked by railcore policy" {
		t.Errorf("error = %v, want 'blocked by railcore policy'", got["error"])
	}
	findings, ok := got["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("findings missing or empty: %v", got)
	}
}
