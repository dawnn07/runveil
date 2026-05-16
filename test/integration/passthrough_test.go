// Package integration contains end-to-end tests that spin up an in-process
// Railcore proxy and a fake upstream, then drive real http.Client traffic
// through both. These tests exercise the same wiring `cmd/railcore` does.
package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"railcore/internal/ca"
	"railcore/internal/pipeline"
	"railcore/internal/proxy"
)

func setup(t *testing.T) (*http.Client, *httptest.Server, func()) {
	t.Helper()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "method=%s path=%s", r.Method, r.URL.Path)
	}))
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	caInst, err := ca.GenerateOrLoad(t.TempDir())
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	chain := pipeline.NewChain()
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

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "e2e.test"},
		},
		Timeout: 10 * time.Second,
	}

	cleanup := func() {
		cancel()
		_ = ln.Close()
		upstream.Close()
	}
	return client, upstream, cleanup
}

func TestPassthrough_GET(t *testing.T) {
	client, _, cleanup := setup(t)
	defer cleanup()

	resp, err := client.Get("https://e2e.test/hello")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if got, want := string(body), "method=GET path=/hello"; got != want {
		t.Fatalf("body=%q, want %q", got, want)
	}
}

func TestPassthrough_POST(t *testing.T) {
	client, _, cleanup := setup(t)
	defer cleanup()

	resp, err := client.Post("https://e2e.test/echo", "application/json",
		nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if got, want := string(body), "method=POST path=/echo"; got != want {
		t.Fatalf("body=%q, want %q", got, want)
	}
}
