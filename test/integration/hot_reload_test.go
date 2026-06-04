// End-to-end test for sub-project #8: spin up a real proxy with a
// real policy file, modify the policy mid-flight, assert the next
// request reflects the new rules.
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

func TestHotReload_E2E_PolicyChangeBlocksOnNextRequest(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.log")
	policyPath := filepath.Join(tmpDir, "policy.yaml")

	// Initial policy: warn-all only, no block.
	if err := os.WriteFile(policyPath, []byte(`
version: 1
rules:
  - name: default-warn
    match: {all: true}
    action: warn
`), 0o600); err != nil {
		t.Fatalf("write initial policy: %v", err)
	}

	auditWriter, err := audit.NewWriter(audit.Config{
		Path:       auditPath,
		MaxSizeMB:  10,
		MaxBackups: 1,
		MaxAgeDays: 1,
	}, nil)
	if err != nil {
		t.Fatalf("audit.NewWriter: %v", err)
	}
	t.Cleanup(func() { _ = auditWriter.Close() })

	caInst, err := ca.GenerateOrLoad(tmpDir + "/ca")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}

	initialPol, err := policy.LoadFromFile(policyPath)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	policies := policy.NewProvider(initialPol)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	watcher, err := policy.NewWatcher(policyPath, nil,
		func(np *policy.Policy) {
			before := policies.Get().RuleCount()
			policies.Set(np)
			auditWriter.Event(audit.Event{
				Time:        time.Now(),
				Kind:        "policy_reload",
				PolicyPath:  policyPath,
				Outcome:     "accepted",
				RulesBefore: before,
				RulesAfter:  np.RuleCount(),
			})
		},
		func(rerr error, _ []byte) {
			auditWriter.Event(audit.Event{
				Time:    time.Now(),
				Kind:    "policy_reload",
				Outcome: "rejected",
				Error:   rerr.Error(),
			})
		},
	)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	t.Cleanup(func() { _ = watcher.Close() })
	if err := watcher.Start(ctx); err != nil {
		t.Fatalf("watcher.Start: %v", err)
	}

	chain := pipeline.NewChain()
	chain.Register(pathscanstage.New(pathscanstage.Config{Policies: policies}, nil))

	srv := proxy.New(proxy.Config{
		Addr:             "127.0.0.1:0",
		CA:               caInst,
		Pipeline:         chain,
		AuditFunc:        auditWriter,
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

	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "name": "Read", "id": "x",
				 "input": {"file_path": "/src/payments/charge.go"}}
			]}
		]
	}`

	// First request — should pass under warn-only policy.
	resp, err := client.Post("https://api.anthropic.com/v1/messages", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("first Post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first request: status = %d, want 200", resp.StatusCode)
	}

	// Update policy to block payments paths.
	if err := os.WriteFile(policyPath, []byte(`
version: 1
rules:
  - name: block-payments
    match: {path: "**/payments/**"}
    action: block
  - name: default-warn
    match: {all: true}
    action: warn
`), 0o600); err != nil {
		t.Fatalf("write updated policy: %v", err)
	}

	// Wait for the watcher to pick up the reload by polling the audit
	// file for a kind=policy_reload outcome=accepted event.
	waitForReloadEvent(t, auditPath, "accepted", 3*time.Second)

	// Second request — should be blocked under the new policy.
	resp2, err := client.Post("https://api.anthropic.com/v1/messages", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("second Post: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("second request: status = %d, want 403 (policy should now block)", resp2.StatusCode)
	}
}

// waitForReloadEvent polls the audit file until a policy_reload event
// with the given outcome appears, or the timeout fires.
func waitForReloadEvent(t *testing.T, path, outcome string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if line == "" {
					continue
				}
				var e audit.Event
				if err := json.Unmarshal([]byte(line), &e); err != nil {
					continue
				}
				if e.Kind == "policy_reload" && e.Outcome == outcome {
					return
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for kind=policy_reload outcome=%s in %s", outcome, path)
}
