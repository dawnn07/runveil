package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"

	"golang.org/x/net/http2"
)

// handleIntercepted performs the server-side TLS handshake with the client
// using a minted leaf, then serves the inner HTTP traffic with either an
// HTTP/1.1 or HTTP/2 server depending on ALPN negotiation. The same
// http.Handler runs the pipeline and forwards upstream in both cases.
func (s *Server) handleIntercepted(ctx context.Context, raw net.Conn, host, requestID string) error {
	leaf, err := s.cfg.CA.MintLeaf(host)
	if err != nil {
		return fmt.Errorf("mint leaf: %w", err)
	}

	tlsConn := tls.Server(raw, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("tls handshake: %w", err)
	}
	defer tlsConn.Close()

	handler := s.newHandler(host, requestID)

	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		h2srv := &http2.Server{}
		h2srv.ServeConn(tlsConn, &http2.ServeConnOpts{Handler: handler})
		return nil
	}

	// HTTP/1.1: drive a one-shot http.Server over the intercepted conn.
	// http.Server.Serve spawns conn goroutines and returns early when Accept
	// errors. We use a ConnState hook + WaitGroup to block until the single
	// connection goroutine fully exits before returning (and letting the
	// caller's defer close the underlying conn).
	var wg sync.WaitGroup
	h1srv := &http.Server{
		Handler: handler,
		ConnState: func(_ net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				wg.Add(1)
			case http.StateClosed:
				wg.Done()
			}
		},
	}
	if err := h1srv.Serve(newSingleConnListener(tlsConn)); err != nil && err != errListenerClosed {
		return err
	}
	wg.Wait()
	return nil
}
