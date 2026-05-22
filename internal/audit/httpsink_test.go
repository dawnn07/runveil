package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeSIEM is an httptest-backed collector that records POST bodies and
// headers. statusFn lets a test return non-2xx for the first N calls.
type fakeSIEM struct {
	mu       sync.Mutex
	bodies   [][]byte
	headers  []http.Header
	server   *httptest.Server
	statusFn func(callNum int) int // returns the HTTP status for call N (1-based)
}

func newFakeSIEM(t *testing.T, statusFn func(int) int) *fakeSIEM {
	t.Helper()
	f := &fakeSIEM{statusFn: statusFn}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		f.mu.Lock()
		callNum := len(f.bodies) + 1
		f.bodies = append(f.bodies, body.Bytes())
		f.headers = append(f.headers, r.Header.Clone())
		f.mu.Unlock()
		status := http.StatusOK
		if f.statusFn != nil {
			status = f.statusFn(callNum)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeSIEM) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bodies)
}

func (f *fakeSIEM) allBodies() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.bodies))
	copy(out, f.bodies)
	return out
}

func (f *fakeSIEM) lastHeader() http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.headers) == 0 {
		return nil
	}
	return f.headers[len(f.headers)-1]
}

// countNDJSONLines returns the number of non-empty lines in body, and
// fails the test if any line is not a valid JSON object.
func countNDJSONLines(t *testing.T, body []byte) int {
	t.Helper()
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var probe map[string]any
		if err := json.Unmarshal(line, &probe); err != nil {
			t.Errorf("NDJSON line not valid JSON: %v; line=%s", err, line)
		}
		n++
	}
	return n
}

// waitFor polls cond every 10ms until it returns true or the deadline
// fires; fails the test on timeout.
func waitFor(t *testing.T, cond func() bool, timeout time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", msg)
}

// siemCaptureHandler collects slog records so tests can assert on WARN msgs.
type siemCaptureHandler struct {
	mu      sync.Mutex
	records []string
}

func (h *siemCaptureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *siemCaptureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.records = append(h.records, r.Message)
	h.mu.Unlock()
	return nil
}
func (h *siemCaptureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *siemCaptureHandler) WithGroup(_ string) slog.Handler      { return h }
func (h *siemCaptureHandler) has(msg string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, m := range h.records {
		if m == msg {
			return true
		}
	}
	return false
}

func fastConfig(url string) HTTPConfig {
	return HTTPConfig{
		URL:           url,
		BatchSize:     5,
		FlushInterval: 50 * time.Millisecond,
		BaseBackoff:   10 * time.Millisecond,
		Timeout:       2 * time.Second,
	}
}

func TestHTTPSink_NewRejectsEmptyURL(t *testing.T) {
	_, err := NewHTTPSink(HTTPConfig{URL: ""}, discardLogger())
	if err == nil {
		t.Error("expected error for empty URL")
	}
}

func TestHTTPSink_NewRejectsBadURL(t *testing.T) {
	_, err := NewHTTPSink(HTTPConfig{URL: "ftp://nope"}, discardLogger())
	if err == nil {
		t.Error("expected error for non-http(s) scheme")
	}
}

func TestHTTPSink_DeliversBatch(t *testing.T) {
	siem := newFakeSIEM(t, nil)
	s, err := NewHTTPSink(fastConfig(siem.server.URL), discardLogger())
	if err != nil {
		t.Fatalf("NewHTTPSink: %v", err)
	}
	defer s.Close()

	for i := 0; i < 5; i++ {
		s.Log(Record{Time: time.Now(), RequestID: "r"})
	}
	waitFor(t, func() bool { return siem.callCount() >= 1 }, 2*time.Second, "one batch POST")

	bodies := siem.allBodies()
	if got := countNDJSONLines(t, bodies[0]); got != 5 {
		t.Errorf("first batch had %d NDJSON lines, want 5", got)
	}
}

func TestHTTPSink_FlushIntervalDeliversPartialBatch(t *testing.T) {
	siem := newFakeSIEM(t, nil)
	s, err := NewHTTPSink(fastConfig(siem.server.URL), discardLogger())
	if err != nil {
		t.Fatalf("NewHTTPSink: %v", err)
	}
	defer s.Close()

	for i := 0; i < 3; i++ {
		s.Log(Record{Time: time.Now(), RequestID: "r"})
	}
	waitFor(t, func() bool { return siem.callCount() >= 1 }, 2*time.Second, "partial batch flush")
	if got := countNDJSONLines(t, siem.allBodies()[0]); got != 3 {
		t.Errorf("partial batch had %d lines, want 3", got)
	}
}

func TestHTTPSink_SetsAuthHeader(t *testing.T) {
	siem := newFakeSIEM(t, nil)
	cfg := fastConfig(siem.server.URL)
	cfg.AuthHeader = "Authorization"
	cfg.AuthValue = "Splunk test-token"
	s, err := NewHTTPSink(cfg, discardLogger())
	if err != nil {
		t.Fatalf("NewHTTPSink: %v", err)
	}
	defer s.Close()

	for i := 0; i < 5; i++ {
		s.Log(Record{RequestID: "r"})
	}
	waitFor(t, func() bool { return siem.callCount() >= 1 }, 2*time.Second, "batch POST")
	if got := siem.lastHeader().Get("Authorization"); got != "Splunk test-token" {
		t.Errorf("Authorization header = %q, want %q", got, "Splunk test-token")
	}
}

func TestHTTPSink_NoAuthHeaderWhenUnconfigured(t *testing.T) {
	siem := newFakeSIEM(t, nil)
	s, err := NewHTTPSink(fastConfig(siem.server.URL), discardLogger())
	if err != nil {
		t.Fatalf("NewHTTPSink: %v", err)
	}
	defer s.Close()

	for i := 0; i < 5; i++ {
		s.Log(Record{RequestID: "r"})
	}
	waitFor(t, func() bool { return siem.callCount() >= 1 }, 2*time.Second, "batch POST")
	if got := siem.lastHeader().Get("Authorization"); got != "" {
		t.Errorf("Authorization header = %q, want empty", got)
	}
}

func TestHTTPSink_RetriesOnServerError(t *testing.T) {
	siem := newFakeSIEM(t, func(call int) int {
		if call <= 2 {
			return http.StatusServiceUnavailable
		}
		return http.StatusOK
	})
	s, err := NewHTTPSink(fastConfig(siem.server.URL), discardLogger())
	if err != nil {
		t.Fatalf("NewHTTPSink: %v", err)
	}
	defer s.Close()

	for i := 0; i < 5; i++ {
		s.Log(Record{RequestID: "r"})
	}
	waitFor(t, func() bool { return siem.callCount() >= 3 }, 3*time.Second,
		"batch delivered after retries")
}

func TestHTTPSink_DropsOldestWhenBufferFull(t *testing.T) {
	siem := newFakeSIEM(t, func(int) int { return http.StatusServiceUnavailable })
	ch := &siemCaptureHandler{}
	cfg := fastConfig(siem.server.URL)
	cfg.MaxBufferBatches = 2
	cfg.BaseBackoff = time.Hour // keep the retry timer from interfering
	s, err := NewHTTPSink(cfg, slog.New(ch))
	if err != nil {
		t.Fatalf("NewHTTPSink: %v", err)
	}
	defer s.Close()

	for i := 0; i < 100; i++ {
		s.Log(Record{RequestID: "r"})
	}
	waitFor(t, func() bool { return ch.has("siem retry buffer full; dropping oldest batch") },
		3*time.Second, "drop-oldest WARN")
}

func TestHTTPSink_LogAfterCloseIsSafe(t *testing.T) {
	siem := newFakeSIEM(t, nil)
	s, err := NewHTTPSink(fastConfig(siem.server.URL), discardLogger())
	if err != nil {
		t.Fatalf("NewHTTPSink: %v", err)
	}
	_ = s.Close()
	s.Log(Record{RequestID: "post-close"})
	s.Event(Event{Kind: "post-close"})
}

func TestHTTPSink_CloseFlushesPending(t *testing.T) {
	siem := newFakeSIEM(t, nil)
	s, err := NewHTTPSink(fastConfig(siem.server.URL), discardLogger())
	if err != nil {
		t.Fatalf("NewHTTPSink: %v", err)
	}
	s.Log(Record{RequestID: "a"})
	s.Log(Record{RequestID: "b"})
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if siem.callCount() < 1 {
		t.Fatalf("Close did not flush pending records; callCount=%d", siem.callCount())
	}
	if got := countNDJSONLines(t, siem.allBodies()[0]); got != 2 {
		t.Errorf("flushed batch had %d lines, want 2", got)
	}
}

func TestHTTPSink_CloseIdempotent(t *testing.T) {
	siem := newFakeSIEM(t, nil)
	s, err := NewHTTPSink(fastConfig(siem.server.URL), discardLogger())
	if err != nil {
		t.Fatalf("NewHTTPSink: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
