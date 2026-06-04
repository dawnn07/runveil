// End-to-end test for sub-project #11: a real proxy with a
// metrics.Collector in the audit fan-out. Drives one request through
// and asserts the Collector's /metrics output reflects it.
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
	"strings"
	"testing"
	"time"

	"runveil/internal/audit"
	"runveil/internal/ca"
	"runveil/internal/metrics"
	"runveil/internal/pipeline"
	"runveil/internal/proxy"
)

func TestMetrics_E2E_RequestIncrementsCounter(t *testing.T) {
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

	// The metrics Collector is the audit sink — same composition the
	// proxy builds when --metrics-port is set.
	collector := metrics.NewCollector()
	var auditLogger audit.Logger = collector

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

	// The proxy's audit Log call runs in a deferred goroutine; poll the
	// Collector's /metrics output until the counter reflects the request.
	deadline := time.Now().Add(2 * time.Second)
	var body string
	for time.Now().Before(deadline) {
		rec := httptest.NewRecorder()
		collector.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		body = rec.Body.String()
		if strings.Contains(body, `runveil_requests_total{decision="continue"} 1`) {
			return // success
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for runveil_requests_total to reach 1; last scrape:\n%s", body)
}
