// End-to-end test for sub-project #10: a real proxy with an
// IdentityLogger-wrapped audit Writer. Drives one request through and
// asserts the persisted audit record carries the configured identity.
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
	"testing"
	"time"

	"runveil/internal/audit"
	"runveil/internal/ca"
	"runveil/internal/pipeline"
	"runveil/internal/proxy"
)

func TestIdentity_E2E_AuditRecordCarriesUser(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.log")

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

	// Wrap the file writer in an IdentityLogger — the same composition
	// the proxy builds at startup.
	identity := audit.Identity{User: "alice@corp.com", Machine: "alice-mbp"}
	auditLogger := audit.NewIdentityLogger(auditWriter, identity)

	caInst, err := ca.GenerateOrLoad(tmpDir + "/ca")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}

	srv := proxy.New(proxy.Config{
		Addr:             "127.0.0.1:0",
		CA:               caInst,
		Pipeline:         pipeline.NewChain(),
		AuditFunc:        auditLogger,
		UpstreamTLS:      &tls.Config{RootCAs: upstreamPool, ServerName: upstreamURL.Hostname()},
		UpstreamResolver: func(_ string) (string, error) { return upstreamURL.Host, nil },
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
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

	resp, err := client.Post("https://api.anthropic.com/v1/messages", "application/json",
		strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	resp.Body.Close()

	// The proxy's audit Log call happens in a defer after the response is
	// streamed back, so the record may not have landed yet. Poll until the
	// audit file contains the record before closing the writer.
	records := waitForAuditRecords(t, auditPath, 1, 2*time.Second)

	// Flush the writer so the record is on disk; Close is idempotent.
	_ = auditWriter.Close()

	if len(records) != 1 {
		t.Fatalf("got %d audit records, want 1", len(records))
	}
	r := records[0]
	if r.User != "alice@corp.com" {
		t.Errorf("User = %q, want alice@corp.com", r.User)
	}
	if r.Machine != "alice-mbp" {
		t.Errorf("Machine = %q, want alice-mbp", r.Machine)
	}
}
