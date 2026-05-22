package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const remoteValidYAML = `
version: 1
rules:
  - name: r1
    match: {all: true}
    action: warn
`

const remoteValidYAML2 = `
version: 1
rules:
  - name: r1
    match: {all: true}
    action: warn
  - name: r2
    match: {all: true}
    action: block
`

const remoteInvalidYAML = `not: valid: yaml: at: all`

// policyServer is an httptest server that serves a policy body which
// tests can swap, with ETag support.
type policyServer struct {
	mu     sync.Mutex
	body   string
	etag   string
	hits   int
	server *httptest.Server
}

func newPolicyServer(t *testing.T, body string) *policyServer {
	t.Helper()
	ps := &policyServer{body: body, etag: `"v1"`}
	ps.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ps.mu.Lock()
		defer ps.mu.Unlock()
		ps.hits++
		if inm := r.Header.Get("If-None-Match"); inm != "" && inm == ps.etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", ps.etag)
		_, _ = w.Write([]byte(ps.body))
	}))
	t.Cleanup(ps.server.Close)
	return ps
}

func (ps *policyServer) set(body, etag string) {
	ps.mu.Lock()
	ps.body, ps.etag = body, etag
	ps.mu.Unlock()
}

func (ps *policyServer) hitCount() int {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.hits
}

func waitSig(t *testing.T, ch <-chan struct{}, timeout time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestRemoteSource_NewRejectsBadURL(t *testing.T) {
	for _, u := range []string{"", "ftp://nope", "://bad"} {
		_, err := NewRemoteSource(RemoteConfig{URL: u}, discardLogger(),
			func(*Policy) {}, func(error, []byte) {})
		if err == nil {
			t.Errorf("NewRemoteSource(%q) expected error", u)
		}
	}
}

func TestRemoteSource_FetchLoadsValidPolicy(t *testing.T) {
	ps := newPolicyServer(t, remoteValidYAML)
	s, err := NewRemoteSource(RemoteConfig{
		URL:       ps.server.URL,
		CachePath: filepath.Join(t.TempDir(), "policy-cache.yaml"),
	}, discardLogger(), func(*Policy) {}, func(error, []byte) {})
	if err != nil {
		t.Fatalf("NewRemoteSource: %v", err)
	}
	p, err := s.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if p.RuleCount() != 1 {
		t.Errorf("RuleCount = %d, want 1", p.RuleCount())
	}
}

func TestRemoteSource_FetchRejectsInvalidPolicy(t *testing.T) {
	ps := newPolicyServer(t, remoteInvalidYAML)
	s, _ := NewRemoteSource(RemoteConfig{
		URL:       ps.server.URL,
		CachePath: filepath.Join(t.TempDir(), "policy-cache.yaml"),
	}, discardLogger(), func(*Policy) {}, func(error, []byte) {})
	if _, err := s.Fetch(); err == nil {
		t.Error("Fetch expected error for invalid policy")
	}
}

func TestRemoteSource_FetchWritesCache(t *testing.T) {
	ps := newPolicyServer(t, remoteValidYAML)
	cachePath := filepath.Join(t.TempDir(), "policy-cache.yaml")
	s, _ := NewRemoteSource(RemoteConfig{URL: ps.server.URL, CachePath: cachePath},
		discardLogger(), func(*Policy) {}, func(error, []byte) {})
	if _, err := s.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	cached, err := LoadFromFile(cachePath)
	if err != nil {
		t.Fatalf("cache file did not re-parse: %v", err)
	}
	if cached.RuleCount() != 1 {
		t.Errorf("cached RuleCount = %d, want 1", cached.RuleCount())
	}
}

func TestRemoteSource_FetchSendsAuthHeader(t *testing.T) {
	gotAuth := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(remoteValidYAML))
	}))
	t.Cleanup(srv.Close)
	s, _ := NewRemoteSource(RemoteConfig{
		URL:        srv.URL,
		AuthHeader: "Authorization",
		AuthValue:  "Bearer test-token",
		CachePath:  filepath.Join(t.TempDir(), "policy-cache.yaml"),
	}, discardLogger(), func(*Policy) {}, func(error, []byte) {})
	if _, err := s.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer test-token")
	}
}

func TestRemoteSource_PollAcceptsChangedPolicy(t *testing.T) {
	ps := newPolicyServer(t, remoteValidYAML)
	accepted := make(chan struct{}, 4)
	var got *Policy
	s, _ := NewRemoteSource(RemoteConfig{
		URL:       ps.server.URL,
		Interval:  20 * time.Millisecond,
		CachePath: filepath.Join(t.TempDir(), "policy-cache.yaml"),
	}, discardLogger(),
		func(p *Policy) { got = p; accepted <- struct{}{} },
		func(error, []byte) { t.Error("unexpected reject") })

	if _, err := s.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	ps.set(remoteValidYAML2, `"v2"`)
	waitSig(t, accepted, 2*time.Second, "onAccept after policy change")
	if got == nil || got.RuleCount() != 2 {
		t.Errorf("accepted RuleCount = %d, want 2", got.RuleCount())
	}
}

func TestRemoteSource_PollHonorsNotModified(t *testing.T) {
	ps := newPolicyServer(t, remoteValidYAML)
	s, _ := NewRemoteSource(RemoteConfig{
		URL:       ps.server.URL,
		Interval:  20 * time.Millisecond,
		CachePath: filepath.Join(t.TempDir(), "policy-cache.yaml"),
	}, discardLogger(),
		func(*Policy) { t.Error("unexpected accept on unchanged policy") },
		func(error, []byte) { t.Error("unexpected reject") })

	if _, err := s.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	_ = s.Start(ctx)
	t.Cleanup(func() { _ = s.Close() })

	time.Sleep(200 * time.Millisecond)
}

func TestRemoteSource_PollRejectsInvalidPolicy(t *testing.T) {
	ps := newPolicyServer(t, remoteValidYAML)
	rejected := make(chan struct{}, 4)
	s, _ := NewRemoteSource(RemoteConfig{
		URL:       ps.server.URL,
		Interval:  20 * time.Millisecond,
		CachePath: filepath.Join(t.TempDir(), "policy-cache.yaml"),
	}, discardLogger(),
		func(*Policy) {},
		func(error, []byte) { rejected <- struct{}{} })

	if _, err := s.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	_ = s.Start(ctx)
	t.Cleanup(func() { _ = s.Close() })

	ps.set(remoteInvalidYAML, `"bad"`)
	waitSig(t, rejected, 2*time.Second, "onReject after invalid policy served")
}

func TestRemoteSource_PollTransportFailureKeepsQuiet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	s, _ := NewRemoteSource(RemoteConfig{
		URL:       srv.URL,
		Interval:  20 * time.Millisecond,
		CachePath: filepath.Join(t.TempDir(), "policy-cache.yaml"),
	}, discardLogger(),
		func(*Policy) { t.Error("unexpected accept on 500") },
		func(error, []byte) { t.Error("unexpected reject on 500") })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	_ = s.Start(ctx)
	t.Cleanup(func() { _ = s.Close() })

	time.Sleep(200 * time.Millisecond)
}

func TestRemoteSource_CloseIdempotent(t *testing.T) {
	ps := newPolicyServer(t, remoteValidYAML)
	s, _ := NewRemoteSource(RemoteConfig{
		URL:       ps.server.URL,
		CachePath: filepath.Join(t.TempDir(), "policy-cache.yaml"),
	}, discardLogger(), func(*Policy) {}, func(error, []byte) {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = s.Start(ctx)
	if err := s.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestRemoteSource_CloseStopsPolling(t *testing.T) {
	ps := newPolicyServer(t, remoteValidYAML)
	s, _ := NewRemoteSource(RemoteConfig{
		URL:       ps.server.URL,
		Interval:  20 * time.Millisecond,
		CachePath: filepath.Join(t.TempDir(), "policy-cache.yaml"),
	}, discardLogger(), func(*Policy) {}, func(error, []byte) {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = s.Start(ctx)
	time.Sleep(100 * time.Millisecond)
	_ = s.Close()
	hitsAtClose := ps.hitCount()
	time.Sleep(150 * time.Millisecond)
	if after := ps.hitCount(); after != hitsAtClose {
		t.Errorf("server hit %d more times after Close (%d → %d)", after-hitsAtClose, hitsAtClose, after)
	}
}
