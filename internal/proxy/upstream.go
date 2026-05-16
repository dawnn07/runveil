package proxy

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"railcore/internal/pipeline"
)

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
		// Enforce body cap. MaxBytesReader returns an error on Read once the
		// limit is exceeded.
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			if isMaxBytesErr(err) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

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
		if dec == pipeline.Block {
			http.Error(w, "blocked by railcore policy", http.StatusForbidden)
			return
		}

		target, err := s.resolveUpstream(host)
		if err != nil {
			http.Error(w, "resolve upstream: "+err.Error(), http.StatusBadGateway)
			return
		}

		out, err := http.NewRequestWithContext(r.Context(), r.Method,
			"https://"+target+r.URL.RequestURI(), io.NopCloser(newByteReader(body)))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
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
			http.Error(w, "upstream unreachable: "+err.Error(), http.StatusBadGateway)
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

