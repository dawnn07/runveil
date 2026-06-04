// Package integration contains end-to-end tests that spin up an in-process
// Runveil proxy and a fake upstream, then drive real http.Client traffic
// through both. These tests exercise the same wiring `cmd/runveil` does.
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

	"runveil/internal/ca"
	"runveil/internal/pipeline"
	"runveil/internal/proxy"
)

func setupH2(t *testing.T) (*http.Client, *httptest.Server, func()) {
	t.Helper()

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "method=%s path=%s", r.Method, r.URL.Path)
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
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
		UpstreamTLS:      &tls.Config{RootCAs: upstreamPool, ServerName: upstreamURL.Hostname(), NextProtos: []string{"h2"}},
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

	transport := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		TLSClientConfig:   &tls.Config{RootCAs: caPool, ServerName: "e2e.test", NextProtos: []string{"h2"}},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	cleanup := func() {
		cancel()
		_ = ln.Close()
		upstream.Close()
	}
	return client, upstream, cleanup
}

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
			Proxy:           http.ProxyURL(proxyURL),
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

func TestPassthrough_HTTP2(t *testing.T) {
	client, _, cleanup := setupH2(t)
	defer cleanup()

	resp, err := client.Get("https://e2e.test/h2")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("Proto = %s, want HTTP/2", resp.Proto)
	}
	body, _ := io.ReadAll(resp.Body)
	if got, want := string(body), "method=GET path=/h2"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}
