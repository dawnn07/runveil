package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
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
)

func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	c, err := ca.GenerateOrLoad(t.TempDir())
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	chain := pipeline.NewChain()
	srv := New(Config{
		Addr:         "127.0.0.1:0",
		CA:           c,
		Pipeline:     chain,
		MaxBodyBytes: 32 * 1024 * 1024,
	})

	ln, err := net.Listen("tcp", srv.Addr())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() { _ = srv.Serve(context.Background(), ln) }()
	return srv, ln.Addr().String()
}

func TestProxy_RejectsConnectToNon443(t *testing.T) {
	_, addr := newTestServer(t)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Write([]byte("CONNECT api.openai.com:80 HTTP/1.1\r\nHost: api.openai.com:80\r\n\r\n")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("expected JSON error body, got Content-Type=%q", resp.Header.Get("Content-Type"))
	}
}

func TestProxy_InterceptsAndForwardsGET(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	srv, addr := newTestServer(t)
	srv.cfg.UpstreamTLS = &tls.Config{RootCAs: upstreamPool, ServerName: upstreamURL.Hostname()}
	srv.cfg.UpstreamResolver = func(_ string) (string, error) { return upstreamURL.Host, nil }

	caPool := x509.NewCertPool()
	caPool.AddCert(srv.cfg.CA.RootCert())
	proxyURL, _ := url.Parse("http://" + addr)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "example.test"},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get("https://example.test/")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "hello-from-upstream" {
		t.Fatalf("body = %q, want hello-from-upstream", string(body))
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

type alwaysBlockStage struct{}

func (alwaysBlockStage) Name() string { return "always-block" }
func (alwaysBlockStage) Process(_ context.Context, _ *pipeline.RequestCtx) (pipeline.Decision, error) {
	return pipeline.Block, nil
}

func TestProxy_BlockReturns403AndSkipsUpstream(t *testing.T) {
	var upstreamHits int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		_, _ = io.WriteString(w, "should-not-reach")
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	srv, addr := newTestServer(t)
	srv.cfg.UpstreamTLS = &tls.Config{RootCAs: upstreamPool, ServerName: upstreamURL.Hostname()}
	srv.cfg.UpstreamResolver = func(_ string) (string, error) { return upstreamURL.Host, nil }
	srv.cfg.Pipeline.Register(alwaysBlockStage{})

	caPool := x509.NewCertPool()
	caPool.AddCert(srv.cfg.CA.RootCert())
	proxyURL, _ := url.Parse("http://" + addr)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "blocked.test"},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get("https://blocked.test/")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&upstreamHits); got != 0 {
		t.Fatalf("upstream was dialled %d times; expected 0", got)
	}
}
