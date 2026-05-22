package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultSinkBatchSize     = 100
	defaultSinkFlushInterval = 5 * time.Second
	defaultSinkMaxBuffer     = 64
	defaultSinkTimeout       = 10 * time.Second
	defaultSinkBufferSize    = 1024
	defaultSinkBaseBackoff   = 1 * time.Second
	maxSinkBackoff           = 60 * time.Second
)

// HTTPConfig configures an HTTPSink. URL is required; the remaining
// fields fall back to defaults when zero.
type HTTPConfig struct {
	URL              string        // required; SIEM collector endpoint
	AuthHeader       string        // optional; header name, e.g. "Authorization"
	AuthValue        string        // optional; header value (token/key)
	BatchSize        int           // lines per batch before flush; default 100
	FlushInterval    time.Duration // max age of a partial batch; default 5s
	MaxBufferBatches int           // retry-buffer cap in batches; default 64
	Timeout          time.Duration // per-POST HTTP timeout; default 10s
	BufferSize       int           // ingest channel capacity; default 1024
	BaseBackoff      time.Duration // first retry interval; default 1s
}

// HTTPSink is a Logger that batches marshaled records/events and POSTs
// them as NDJSON to an HTTP SIEM collector. Failed batches are retried
// from a bounded in-memory buffer with exponential backoff.
type HTTPSink struct {
	cfg       HTTPConfig
	client    *http.Client
	logger    *slog.Logger
	ch        chan []byte
	closed    atomic.Bool
	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

// NewHTTPSink validates cfg, applies defaults, starts the background
// batching goroutine, and returns a *HTTPSink. Returns an error if URL
// is empty or not an http(s) URL.
func NewHTTPSink(cfg HTTPConfig, logger *slog.Logger) (*HTTPSink, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("audit: SIEM URL is required")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("audit: parse SIEM URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("audit: SIEM URL scheme must be http or https, got %q", u.Scheme)
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultSinkBatchSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaultSinkFlushInterval
	}
	if cfg.MaxBufferBatches <= 0 {
		cfg.MaxBufferBatches = defaultSinkMaxBuffer
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultSinkTimeout
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = defaultSinkBufferSize
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = defaultSinkBaseBackoff
	}
	if logger == nil {
		logger = slog.Default()
	}

	s := &HTTPSink{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
		logger: logger,
		ch:     make(chan []byte, cfg.BufferSize),
		done:   make(chan struct{}),
	}
	s.wg.Add(1)
	go s.run()
	return s, nil
}

// Log implements Logger. Marshals the record and enqueues it
// non-blocking; drops with a WARN if the ingest channel is full. Safe
// to call after Close (no-op).
func (s *HTTPSink) Log(r Record) {
	if s == nil || s.closed.Load() {
		return
	}
	line, err := json.Marshal(r)
	if err != nil {
		s.logger.Error("siem: marshal record", "request_id", r.RequestID, "err", err.Error())
		return
	}
	s.enqueue(line)
}

// Event implements Logger. Marshals the event and enqueues it
// non-blocking; drops with a WARN if the ingest channel is full. Safe
// to call after Close (no-op).
func (s *HTTPSink) Event(e Event) {
	if s == nil || s.closed.Load() {
		return
	}
	line, err := json.Marshal(e)
	if err != nil {
		s.logger.Error("siem: marshal event", "kind", e.Kind, "err", err.Error())
		return
	}
	s.enqueue(line)
}

func (s *HTTPSink) enqueue(line []byte) {
	select {
	case s.ch <- line:
	default:
		s.logger.Warn("siem ingest channel full; dropping record")
	}
}

// Close signals shutdown, runs a final best-effort flush of the retry
// buffer, and joins the background goroutine. Idempotent.
func (s *HTTPSink) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.done)
		s.wg.Wait()
	})
	return nil
}

// run is the background batching goroutine. It owns all mutable state
// (current, retryBuffer, backoff) so no locks are needed beyond the
// ingest channel.
func (s *HTTPSink) run() {
	defer s.wg.Done()

	var current [][]byte     // lines accumulating toward the next batch
	var retryBuffer [][]byte // finalized NDJSON batch bodies, oldest first
	backoff := s.cfg.BaseBackoff
	retrying := false

	flushTicker := time.NewTicker(s.cfg.FlushInterval)
	defer flushTicker.Stop()
	retryTimer := time.NewTimer(time.Hour)
	retryTimer.Stop()
	defer retryTimer.Stop()

	finalize := func() {
		if len(current) == 0 {
			return
		}
		body := append(bytes.Join(current, []byte("\n")), '\n')
		current = nil
		retryBuffer = append(retryBuffer, body)
		if len(retryBuffer) > s.cfg.MaxBufferBatches {
			retryBuffer = retryBuffer[1:]
			s.logger.Warn("siem retry buffer full; dropping oldest batch")
		}
	}

	tryDrain := func() {
		for len(retryBuffer) > 0 {
			if err := s.post(retryBuffer[0]); err != nil {
				retryTimer.Reset(backoff)
				backoff *= 2
				if backoff > maxSinkBackoff {
					backoff = maxSinkBackoff
				}
				retrying = true
				return
			}
			retryBuffer = retryBuffer[1:]
			backoff = s.cfg.BaseBackoff
		}
		retrying = false
	}

	// maybeDrain attempts delivery only when not already in a backoff
	// wait — avoids hammering a downed SIEM on every incoming record.
	maybeDrain := func() {
		if !retrying {
			tryDrain()
		}
	}

	for {
		select {
		case line := <-s.ch:
			current = append(current, line)
			if len(current) >= s.cfg.BatchSize {
				finalize()
				maybeDrain()
			}
		case <-flushTicker.C:
			if len(current) > 0 {
				finalize()
				maybeDrain()
			}
		case <-retryTimer.C:
			tryDrain()
		case <-s.done:
			// Drain the ingest channel non-blocking, finalize, then
			// one best-effort delivery pass.
		drainLoop:
			for {
				select {
				case line := <-s.ch:
					current = append(current, line)
				default:
					break drainLoop
				}
			}
			finalize()
			s.finalDrain(retryBuffer)
			return
		}
	}
}

// finalDrain makes one delivery pass over the retry buffer on shutdown.
// Undeliverable batches are dropped with a logged count.
func (s *HTTPSink) finalDrain(retryBuffer [][]byte) {
	dropped := 0
	for _, body := range retryBuffer {
		if err := s.post(body); err != nil {
			dropped++
		}
	}
	if dropped > 0 {
		s.logger.Warn("siem: batches dropped on shutdown", "count", dropped)
	}
}

// post sends one NDJSON batch body. Returns an error on transport
// failure or a non-2xx status.
func (s *HTTPSink) post(body []byte) error {
	req, err := http.NewRequest(http.MethodPost, s.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if s.cfg.AuthHeader != "" && s.cfg.AuthValue != "" {
		req.Header.Set(s.cfg.AuthHeader, s.cfg.AuthValue)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("siem: POST returned status %d", resp.StatusCode)
	}
	return nil
}
