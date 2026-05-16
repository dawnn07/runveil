// Package proxy implements the Railcore forward HTTPS proxy.
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"railcore/internal/ca"
	"railcore/internal/pipeline"
)

// Config configures a Server. All fields are required unless documented.
type Config struct {
	Addr         string          // e.g. "127.0.0.1:9443"
	CA           *ca.CA          // local CA for minting leaves
	Pipeline     *pipeline.Chain // request pipeline
	MaxBodyBytes int64           // cap per-request body (default 32 MiB)
	Logger       *slog.Logger    // optional; defaults to slog.Default()

	// UpstreamTLS, if non-nil, is used when dialling upstream. Default is
	// a tls.Config that uses the system root store.
	UpstreamTLS *tls.Config

	// UpstreamResolver, if non-nil, maps a CONNECT host (e.g. api.openai.com)
	// to the actual upstream host:port to dial. Used in tests to point the
	// proxy at httptest servers. nil means dial host:443 directly.
	UpstreamResolver func(host string) (string, error)
}

// Server is the Railcore forward HTTPS proxy.
type Server struct {
	cfg Config
	log *slog.Logger
}

// Addr is the configured listen address.
func (s *Server) Addr() string { return s.cfg.Addr }

// New returns a Server configured from cfg. It does not start listening;
// call Serve.
func New(cfg Config) *Server {
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = 32 * 1024 * 1024
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Server{cfg: cfg, log: log}
}

// Serve accepts connections on ln until ctx is cancelled or ln is closed.
// Each accepted connection is handled in its own goroutine.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			s.log.Warn("accept failed", "err", err.Error())
			continue
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, raw net.Conn) {
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReader(raw)
	req, err := http.ReadRequest(br)
	if err != nil {
		s.log.Debug("read first request failed", "err", err.Error())
		return
	}

	if req.Method != http.MethodConnect {
		writeJSONError(raw, http.StatusBadRequest, "only CONNECT supported", "method", req.Method)
		return
	}

	host, port, err := net.SplitHostPort(req.Host)
	if err != nil || port != "443" {
		writeJSONError(raw, http.StatusBadRequest, "only HTTPS (:443) intercepted", "target", req.Host)
		return
	}

	// Clear the read deadline before the TLS handshake — TLS has its own.
	_ = raw.SetDeadline(time.Time{})

	if _, err := raw.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		s.log.Debug("write 200 failed", "err", err.Error())
		return
	}

	requestID := uuid.NewString()
	if err := s.handleIntercepted(ctx, raw, host, requestID); err != nil {
		s.log.Warn("intercept failed", "request_id", requestID, "host", host, "err", err.Error())
	}
}

func writeJSONError(w io.Writer, status int, msg string, kvs ...string) {
	body := map[string]any{"error": msg}
	for i := 0; i+1 < len(kvs); i += 2 {
		body[kvs[i]] = kvs[i+1]
	}
	payload, _ := json.Marshal(body)

	resp := strings.Builder{}
	fmt.Fprintf(&resp, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	resp.WriteString("Content-Type: application/json\r\n")
	fmt.Fprintf(&resp, "Content-Length: %d\r\n", len(payload))
	resp.WriteString("Connection: close\r\n\r\n")
	resp.Write(payload)
	_, _ = w.Write([]byte(resp.String()))
}
