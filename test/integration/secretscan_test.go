// End-to-end tests for sub-project #2: a real http.Client driving real
// JSON request bodies through a real proxy with the secretscan stage
// registered, against a fake httptest upstream.
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
	"railcore/internal/proxy"
	"railcore/internal/stage/secretscan"
)

func setupSecretscan(t *testing.T, blockOnDetect bool) (client *http.Client, upstreamHits *int32, cleanup func()) {
	t.Helper()

	var hits int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	caInst, err := ca.GenerateOrLoad(t.TempDir())
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	chain := pipeline.NewChain()
	chain.Register(secretscan.New(secretscan.Config{BlockOnDetect: blockOnDetect}, nil))

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

func TestSecretscan_E2E_BlockOnAWSKey(t *testing.T) {
	client, upstreamHits, cleanup := setupSecretscan(t, true)
	defer cleanup()

	body := `{
		"model": "gpt-4o",
		"messages": [
			{"role": "user", "content": "review:\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
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
		t.Fatalf("upstream dialed %d times; want 0", got)
	}

	respBody, _ := io.ReadAll(resp.Body)
	var parsed struct {
		Error    string                   `json:"error"`
		Detector string                   `json:"detector"`
		Findings []map[string]interface{} `json:"findings"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		t.Fatalf("response not JSON: %v, body=%s", err, string(respBody))
	}
	if parsed.Detector != "secret-scan" {
		t.Errorf("detector = %q, want secret-scan", parsed.Detector)
	}
	if len(parsed.Findings) < 1 {
		t.Fatalf("expected >=1 finding, got %d; body=%s", len(parsed.Findings), string(respBody))
	}
	if strings.Contains(string(respBody), "AKIA") {
		t.Errorf("response body contains matched secret bytes: %s", string(respBody))
	}
}

func TestSecretscan_E2E_TestFixturePassesThrough(t *testing.T) {
	client, upstreamHits, cleanup := setupSecretscan(t, true)
	defer cleanup()

	body := `{
		"model": "gpt-4o",
		"messages": [
			{"role": "user", "content": "fixture: AKIA0000000000000000"}
		]
	}`
	resp, err := client.Post("https://api.openai.com/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (test fixture should pass entropy filter)", resp.StatusCode)
	}
	if got := atomic.LoadInt32(upstreamHits); got != 1 {
		t.Fatalf("upstream dialed %d times; want 1", got)
	}
}

func TestSecretscan_E2E_WarnModeStillForwards(t *testing.T) {
	client, upstreamHits, cleanup := setupSecretscan(t, false)
	defer cleanup()

	body := `{
		"model": "gpt-4o",
		"messages": [
			{"role": "user", "content": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}
		]
	}`
	resp, err := client.Post("https://api.openai.com/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (warn mode forwards)", resp.StatusCode)
	}
	if got := atomic.LoadInt32(upstreamHits); got != 1 {
		t.Fatalf("upstream dialed %d times; want 1", got)
	}
}
