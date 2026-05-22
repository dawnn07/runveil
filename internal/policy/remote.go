package policy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	defaultRemoteInterval = 30 * time.Second
	defaultRemoteTimeout  = 10 * time.Second
)

// RemoteConfig configures a RemoteSource.
type RemoteConfig struct {
	URL        string        // required; the policy endpoint
	AuthHeader string        // optional; header name, e.g. "Authorization"
	AuthValue  string        // optional; token value (from env, never a flag)
	Interval   time.Duration // poll interval; default 30s
	CachePath  string        // disk cache file path
	Timeout    time.Duration // per-request HTTP timeout; default 10s
}

// RemoteSource fetches a policy from an HTTP(S) URL, polls for updates,
// and caches the last accepted policy to disk. It mirrors Watcher's
// callback contract so the proxy wiring is symmetric.
//
// Lifecycle: call Fetch once (synchronous bootstrap), then Start (the
// background poller). The two phases never overlap, so the ETag fields
// need no lock.
type RemoteSource struct {
	cfg      RemoteConfig
	client   *http.Client
	logger   *slog.Logger
	onAccept func(*Policy)
	onReject func(error, []byte)

	etag         string // last ETag, for If-None-Match
	lastModified string // last Last-Modified, for If-Modified-Since

	closeOnce sync.Once
	done      chan struct{}
	cancel    context.CancelFunc // set by Start, invoked by Close to abort in-flight requests
	wg        sync.WaitGroup
}

// NewRemoteSource validates cfg, applies defaults, and returns a
// RemoteSource. It does not perform any network I/O — call Fetch and
// Start for that.
func NewRemoteSource(cfg RemoteConfig, logger *slog.Logger,
	onAccept func(*Policy), onReject func(error, []byte)) (*RemoteSource, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("policy: remote URL is required")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("policy: parse remote URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("policy: remote URL scheme must be http or https, got %q", u.Scheme)
	}
	if onAccept == nil || onReject == nil {
		return nil, fmt.Errorf("policy: remote callbacks are required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaultRemoteInterval
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultRemoteTimeout
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &RemoteSource{
		cfg:      cfg,
		client:   &http.Client{Timeout: cfg.Timeout},
		logger:   logger,
		onAccept: onAccept,
		onReject: onReject,
		done:     make(chan struct{}),
	}, nil
}

// Fetch performs one synchronous GET. On a 2xx body it validates the
// policy, writes the disk cache, records the ETag, and returns the
// Policy. On transport failure or an invalid policy it returns an
// error. Used for the proxy's cold-start bootstrap.
func (s *RemoteSource) Fetch() (*Policy, error) {
	resp, err := s.doRequest(context.Background())
	if err != nil {
		return nil, fmt.Errorf("policy: remote fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("policy: remote fetch: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("policy: read remote body: %w", err)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("policy: remote fetch: empty body")
	}
	p, err := LoadFromBytes(body)
	if err != nil {
		return nil, fmt.Errorf("policy: invalid remote policy: %w", err)
	}
	s.etag = resp.Header.Get("ETag")
	s.lastModified = resp.Header.Get("Last-Modified")
	s.writeCache(body)
	return p, nil
}

// Start launches the background poll goroutine. It returns immediately;
// the goroutine runs until ctx is cancelled or Close is called.
func (s *RemoteSource) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.wg.Add(1)
	go s.run(runCtx)
	return nil
}

// Close stops the poller. Idempotent. Joins the goroutine.
func (s *RemoteSource) Close() error {
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		close(s.done)
		s.wg.Wait()
	})
	return nil
}

func (s *RemoteSource) run(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-ticker.C:
			s.poll(ctx)
		}
	}
}

// poll performs one conditional GET and dispatches the result. A 304 or
// a transport failure is a quiet no-op (the latter WARN-logged); a
// served-but-invalid policy fires onReject; a valid one fires onAccept.
func (s *RemoteSource) poll(ctx context.Context) {
	resp, err := s.doRequest(ctx)
	if err != nil {
		s.logger.Warn("policy poll failed", "url", s.cfg.URL, "err", err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		_, _ = io.Copy(io.Discard, resp.Body)
		s.logger.Debug("policy unchanged", "url", s.cfg.URL)
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		s.logger.Warn("policy poll failed", "url", s.cfg.URL, "status", resp.StatusCode)
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Warn("policy poll read failed", "url", s.cfg.URL, "err", err.Error())
		return
	}
	if len(body) == 0 {
		s.onReject(fmt.Errorf("policy: remote returned empty body"), body)
		return
	}
	p, err := LoadFromBytes(body)
	if err != nil {
		s.onReject(err, body)
		return
	}
	s.etag = resp.Header.Get("ETag")
	s.lastModified = resp.Header.Get("Last-Modified")
	s.writeCache(body)
	s.onAccept(p)
}

// doRequest builds and executes the conditional GET.
func (s *RemoteSource) doRequest(ctx context.Context) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.URL, nil)
	if err != nil {
		return nil, err
	}
	if s.etag != "" {
		req.Header.Set("If-None-Match", s.etag)
	}
	if s.lastModified != "" {
		req.Header.Set("If-Modified-Since", s.lastModified)
	}
	if s.cfg.AuthHeader != "" && s.cfg.AuthValue != "" {
		req.Header.Set(s.cfg.AuthHeader, s.cfg.AuthValue)
	}
	return s.client.Do(req)
}

// writeCache persists the raw validated policy bytes. Best-effort: a
// failure is logged but does not fail the reload.
func (s *RemoteSource) writeCache(raw []byte) {
	if s.cfg.CachePath == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.cfg.CachePath), 0o700); err != nil {
		s.logger.Warn("policy cache dir create failed",
			"path", s.cfg.CachePath, "err", err.Error())
		return
	}
	if err := os.WriteFile(s.cfg.CachePath, raw, 0o600); err != nil {
		s.logger.Warn("policy cache write failed",
			"path", s.cfg.CachePath, "err", err.Error())
	}
}
