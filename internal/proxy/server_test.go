package proxy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
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
