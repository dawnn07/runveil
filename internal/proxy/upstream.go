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

	"runveil/internal/audit"
	"runveil/internal/parser"
	"runveil/internal/pipeline"
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
		var rc *pipeline.RequestCtx

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
			if s.cfg.AuditFunc != nil {
				vendor, endpoint := vendorAndEndpoint(rc)
				s.cfg.AuditFunc.Log(audit.Record{
					Time:       start,
					RequestID:  requestID,
					Host:       host,
					Method:     r.Method,
					Path:       r.URL.Path,
					Status:     rec.status,
					BytesIn:    bytesIn,
					BytesOut:   rec.bytesOut,
					DurationMs: time.Since(start).Milliseconds(),
					Vendor:     vendor,
					Endpoint:   endpoint,
					Decision:   decision.String(),
					Findings:   findingsFromMetadata(rc),
				})
			}
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

		rc = &pipeline.RequestCtx{
			Req:       r,
			Host:      host,
			Metadata:  map[string]any{"request_id": requestID, "body": body},
			StartedAt: time.Now(),
		}
		dec, _ := s.cfg.Pipeline.Run(r.Context(), rc)
		decision = dec
		if dec == pipeline.Block {
			writeBlockResp(w, requestID, rc)
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
	// the Runveil CA here; that would let Runveil MITM itself.
	return &tls.Config{ServerName: serverName}
}

func isMaxBytesErr(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}

// writeBlockResp writes a 403 with a JSON body listing the findings (if
// any) from both pathscan and secretscan stages. The detector field is
// per-finding (each finding's MarshalJSON emits its own detector value).
//
// Matched secret bytes are deliberately never echoed; path values ARE
// echoed because the path is the actionable signal for operators.
func writeBlockResp(w http.ResponseWriter, requestID string, rc *pipeline.RequestCtx) {
	body := map[string]any{
		"error":      "blocked by runveil policy",
		"request_id": requestID,
	}

	var all []any
	if v, ok := rc.Metadata["pathscan.findings"]; ok {
		all = append(all, v)
	}
	if v, ok := rc.Metadata["secretscan.findings"]; ok {
		all = append(all, v)
	}
	if len(all) > 0 {
		body["findings"] = flattenFindings(all)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// flattenFindings handles the case where rc.Metadata holds typed slices
// (e.g., []secretscan.EnrichedFinding or []pathscan.PathFinding) that
// must be unwrapped, vs. raw []map[string]any from tests. We marshal
// each input to JSON, then unmarshal as a []any, producing a uniformly
// shaped flat slice.
func flattenFindings(in []any) []any {
	var out []any
	for _, v := range in {
		raw, err := json.Marshal(v)
		if err != nil {
			continue
		}
		var single any
		if err := json.Unmarshal(raw, &single); err != nil {
			continue
		}
		switch s := single.(type) {
		case []any:
			out = append(out, s...)
		default:
			out = append(out, single)
		}
	}
	return out
}

// vendorAndEndpoint inspects the parsed request via the parser package
// to extract the vendor name and endpoint identifier. Returns ("","")
// if rc is nil, the body isn't stored, or the request isn't a known AI
// endpoint.
func vendorAndEndpoint(rc *pipeline.RequestCtx) (vendor, endpoint string) {
	if rc == nil {
		return "", ""
	}
	body, ok := rc.Metadata["body"].([]byte)
	if !ok {
		return "", ""
	}
	parsed, err := parser.ParseRequest(rc.Host, rc.Req, body)
	if err != nil || parsed == nil {
		return "", ""
	}
	return parsed.Vendor, parsed.Endpoint
}

// findingsFromMetadata collects findings from both secretscan and
// pathscan stages' metadata keys into a flat []any (delegating the
// typed-slice flattening to the existing flattenFindings helper).
// Returns nil if neither key is present.
func findingsFromMetadata(rc *pipeline.RequestCtx) []any {
	if rc == nil {
		return nil
	}
	var raw []any
	if v, ok := rc.Metadata["pathscan.findings"]; ok {
		raw = append(raw, v)
	}
	if v, ok := rc.Metadata["secretscan.findings"]; ok {
		raw = append(raw, v)
	}
	if len(raw) == 0 {
		return nil
	}
	return flattenFindings(raw)
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
var errListenerClosed = errors.New("runveil: single-shot listener closed")

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
