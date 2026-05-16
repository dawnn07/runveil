package proxy

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"railcore/internal/pipeline"
)

// writeJSONResp writes a JSON error response via an http.ResponseWriter.
// Used by the handler that runs inside http.Server / http2.Server, where
// we cannot write to the raw net.Conn directly.
func writeJSONResp(w http.ResponseWriter, status int, msg string, kvs ...string) {
	body := map[string]any{"error": msg}
	for i := 0; i+1 < len(kvs); i += 2 {
		body[kvs[i]] = kvs[i+1]
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// newHandler returns the http.Handler that runs the pipeline and forwards
// allowed requests upstream. Used by both H1 and H2 servers.
func (s *Server) newHandler(host, requestID string) http.Handler {
	transport := &http.Transport{
		TLSClientConfig:       s.upstreamTLSConfig(host),
		ForceAttemptHTTP2:     true,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}
	client := &http.Client{Transport: transport, Timeout: 0}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		w = rec // shadow so all subsequent writes go through the recorder
		start := time.Now()
		decision := pipeline.Continue
		var bytesIn int64

		defer func() {
			s.log.Info("request complete",
				"request_id", requestID,
				"host", host,
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"bytes_in", bytesIn,
				"bytes_out", rec.bytesOut,
				"duration_ms", time.Since(start).Milliseconds(),
				"decision", decision.String(),
			)
		}()

		// Enforce body cap. MaxBytesReader returns an error on Read once the
		// limit is exceeded.
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			if isMaxBytesErr(err) {
				writeJSONResp(w, http.StatusRequestEntityTooLarge, "request body too large", "max_bytes", fmt.Sprint(s.cfg.MaxBodyBytes))
				return
			}
			writeJSONResp(w, http.StatusBadRequest, "read body failed", "detail", err.Error())
			return
		}
		bytesIn = int64(len(body))

		// Build the RequestCtx with a body-replacement so stages that read
		// rc.Req.Body still see the bytes.
		r.Body = io.NopCloser(newByteReader(body))
		r.ContentLength = int64(len(body))

		rc := &pipeline.RequestCtx{
			Req:       r,
			Host:      host,
			Metadata:  map[string]any{"request_id": requestID},
			StartedAt: time.Now(),
		}
		dec, _ := s.cfg.Pipeline.Run(r.Context(), rc)
		decision = dec
		if dec == pipeline.Block {
			writeJSONResp(w, http.StatusForbidden, "blocked by railcore policy", "request_id", requestID)
			return
		}

		target, err := s.resolveUpstream(host)
		if err != nil {
			writeJSONResp(w, http.StatusBadGateway, "resolve upstream failed", "host", host, "detail", err.Error())
			return
		}

		out, err := http.NewRequestWithContext(r.Context(), r.Method,
			"https://"+target+r.URL.RequestURI(), io.NopCloser(newByteReader(body)))
		if err != nil {
			writeJSONResp(w, http.StatusBadGateway, "build upstream request failed", "detail", err.Error())
			return
		}
		out.Header = r.Header.Clone()
		// Strip hop-by-hop headers per RFC 7230 §6.1. http.Transport drops
		// some of these on the wire, but explicit removal also prevents
		// Connection: close from leaking and defeating upstream keep-alive.
		for _, h := range []string{
			"Connection", "Keep-Alive", "Proxy-Connection",
			"Proxy-Authenticate", "Proxy-Authorization",
			"Te", "Trailer", "Transfer-Encoding", "Upgrade",
		} {
			out.Header.Del(h)
		}
		// http.Client manages Host header from the URL; preserve original
		// for SNI-sensitive upstreams via the TLS config's ServerName.
		out.ContentLength = int64(len(body))

		resp, err := client.Do(out)
		if err != nil {
			writeJSONResp(w, http.StatusBadGateway, "upstream unreachable", "host", host, "detail", err.Error())
			return
		}
		defer resp.Body.Close()

		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		flusher, _ := w.(http.Flusher)
		buf := make([]byte, 16*1024)
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			if rerr != nil {
				return
			}
		}
	})
}

func (s *Server) resolveUpstream(host string) (string, error) {
	if s.cfg.UpstreamResolver != nil {
		return s.cfg.UpstreamResolver(host)
	}
	return net.JoinHostPort(host, "443"), nil
}

func (s *Server) upstreamTLSConfig(serverName string) *tls.Config {
	if s.cfg.UpstreamTLS != nil {
		cfg := s.cfg.UpstreamTLS.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = serverName
		}
		return cfg
	}
	// IMPORTANT: no RootCAs set => system trust store is used. Do NOT add
	// the Railcore CA here; that would let Railcore MITM itself.
	return &tls.Config{ServerName: serverName}
}

func isMaxBytesErr(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}

// byteReader is an io.Reader over a fixed []byte. Used to re-create a
// request body after we've slurped it into memory for the body cap.
type byteReader struct {
	b []byte
	i int
}

func newByteReader(b []byte) *byteReader { return &byteReader{b: b} }

func (r *byteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

// statusRecorder wraps http.ResponseWriter to capture status code and bytes
// written for the completion log. It also passes through Flusher.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	bytesOut    int64
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.status = code
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(p)
	r.bytesOut += int64(n)
	return n, err
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// errListenerClosed is returned by singleConnListener.Accept after its one
// connection has been served. http.Server treats this as a clean shutdown.
var errListenerClosed = errors.New("railcore: single-shot listener closed")

// singleConnListener serves exactly one connection then errors on Accept,
// causing http.Server.Serve to return. The bool is guarded by a mutex
// because http.Server may Accept concurrently with us tearing down.
type singleConnListener struct {
	conn net.Conn
	mu   sync.Mutex
	done bool
}

func newSingleConnListener(c net.Conn) *singleConnListener {
	return &singleConnListener{conn: c}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done {
		return nil, errListenerClosed
	}
	l.done = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error { return nil }

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
