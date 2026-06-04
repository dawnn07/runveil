// End-to-end test for sub-project #12: a real proxy whose policy comes
// from a RemoteSource pointed at an httptest policy server. Verifies
// fetch-and-enforce, then a live policy change picked up by polling.
package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"runveil/internal/ca"
	"runveil/internal/pipeline"
	"runveil/internal/policy"
	"runveil/internal/proxy"
	pathscanstage "runveil/internal/stage/pathscan"
)

func TestRemotePolicy_E2E_ProxyFetchesAndEnforces(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	// Policy server: starts with a block-payments policy.
	blockPolicy := `
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
`
	warnPolicy := `
version: 1
rules:
  - name: warn-all
    match: {all: true}
    action: warn
`
	var mu sync.Mutex
	served, etag := blockPolicy, `"v1"`
	policySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = io.WriteString(w, served)
	}))
	t.Cleanup(policySrv.Close)

	tmpDir := t.TempDir()
	caInst, err := ca.GenerateOrLoad(tmpDir + "/ca")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}

	// Build the RemoteSource the way the proxy does.
	var policies *policy.Provider
	src, err := policy.NewRemoteSource(policy.RemoteConfig{
		URL:       policySrv.URL,
		Interval:  20 * time.Millisecond,
		CachePath: filepath.Join(tmpDir, "policy-cache.yaml"),
	}, nil,
		func(np *policy.Policy) { policies.Set(np) },
		func(error, []byte) {})
	if err != nil {
		t.Fatalf("NewRemoteSource: %v", err)
	}
	initial, err := src.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	policies = policy.NewProvider(initial)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := src.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	chain := pipeline.NewChain()
	chain.Register(pathscanstage.New(pathscanstage.Config{Policies: policies}, nil))

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
	go srv.Serve(ctx, ln)

	caPool := x509.NewCertPool()
	caPool.AddCert(caInst.RootCert())
	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "api.anthropic.com"},
		},
		Timeout: 10 * time.Second,
	}

	// A tool_use reading a payments path — blocked by the initial policy.
	body := `{"messages":[{"role":"assistant","content":[` +
		`{"type":"tool_use","name":"Read","id":"x","input":{"file_path":"/src/payments/charge.go"}}]}]}`

	resp, err := client.Post("https://api.anthropic.com/v1/messages", "application/json",
		strings.NewReader(body))
	if err != nil {
		t.Fatalf("first Post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("first request: status = %d, want 403 (block-payments)", resp.StatusCode)
	}

	// Swap the served policy to warn-only; the poller picks it up.
	mu.Lock()
	served, etag = warnPolicy, `"v2"`
	mu.Unlock()

	// Poll until the live policy reflects the change.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp2, err := client.Post("https://api.anthropic.com/v1/messages", "application/json",
			strings.NewReader(body))
		if err != nil {
			t.Fatalf("poll Post: %v", err)
		}
		resp2.Body.Close()
		if resp2.StatusCode == http.StatusOK {
			return // policy change picked up — success
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the remote policy change to take effect")
}
