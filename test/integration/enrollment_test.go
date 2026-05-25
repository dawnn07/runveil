// End-to-end test for sub-project #13: a real proxy whose enrollment
// is loaded from <dataDir>/device.json. Verifies (a) the device token
// is sent as Authorization to the remote policy server, and (b) the
// org_id is stamped onto audit records for proxied requests.
package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"railcore/internal/audit"
	"railcore/internal/ca"
	"railcore/internal/enrollment"
	"railcore/internal/pipeline"
	"railcore/internal/policy"
	"railcore/internal/proxy"
	pathscanstage "railcore/internal/stage/pathscan"
)

func TestEnrollment_E2E_DeviceTokenAndOrgID(t *testing.T) {
	// Ensure no env-var leakage from the test harness.
	t.Setenv("RAILCORE_ORG_ID", "")
	t.Setenv("RAILCORE_DEVICE_TOKEN", "")
	t.Setenv("RAILCORE_POLICY_TOKEN", "")

	// --- Upstream HTTPS server that the proxy will forward to. ---
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	// --- Policy server: records every Authorization header it sees. ---
	const policyYAML = `
version: 1
rules:
  - name: warn-all
    match: {all: true}
    action: warn
`
	var (
		mu       sync.Mutex
		authSeen []string
	)
	policySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authSeen = append(authSeen, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("ETag", `"v1"`)
		_, _ = io.WriteString(w, policyYAML)
	}))
	t.Cleanup(policySrv.Close)

	// --- Data dir with a valid device.json. ---
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir dataDir: %v", err)
	}
	const orgID = "org_int"
	const deviceToken = "dt_int"
	devicePath := filepath.Join(dataDir, "device.json")
	if err := os.WriteFile(devicePath,
		[]byte(`{"org_id":"`+orgID+`","device_token":"`+deviceToken+`"}`), 0o600); err != nil {
		t.Fatalf("write device.json: %v", err)
	}

	// --- Audit log to a file we can read back. ---
	auditPath := filepath.Join(tmpDir, "audit.log")
	auditWriter, err := audit.NewWriter(audit.Config{
		Path: auditPath, MaxSizeMB: 1, MaxBackups: 1, MaxAgeDays: 1,
	}, nil)
	if err != nil {
		t.Fatalf("audit.NewWriter: %v", err)
	}
	t.Cleanup(func() { _ = auditWriter.Close() })

	// --- Load enrollment the way the proxy does. ---
	enr, err := enrollment.Load(dataDir)
	if err != nil {
		t.Fatalf("enrollment.Load: %v", err)
	}
	if enr.OrgID != orgID || enr.DeviceToken != deviceToken {
		t.Fatalf("enrollment: got %+v, want {%s, %s}", enr, orgID, deviceToken)
	}

	// --- Wrap the audit writer with the IdentityLogger carrying OrgID. ---
	var auditLogger audit.Logger = auditWriter
	auditLogger = audit.NewIdentityLogger(auditLogger, audit.Identity{
		User: "intuser", Machine: "intmachine", OrgID: enr.OrgID,
	})

	// --- Build the RemoteSource using the device token as auth. ---
	// Match the proxy's auth semantics from sub-project #12: AuthValue
	// is passed verbatim. The operator is responsible for putting any
	// scheme prefix (e.g., "Bearer ") into device.json if their server
	// expects it. Here we use the bare token to keep the assertion
	// straightforward.
	caInst, err := ca.GenerateOrLoad(filepath.Join(tmpDir, "ca"))
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	var policies *policy.Provider
	src, err := policy.NewRemoteSource(policy.RemoteConfig{
		URL:        policySrv.URL,
		AuthHeader: "Authorization",
		AuthValue:  enr.DeviceToken,
		Interval:   50 * time.Millisecond,
		CachePath:  filepath.Join(tmpDir, "policy-cache.yaml"),
	}, nil,
		func(np *policy.Policy) { policies.Set(np) },
		func(error, []byte) {})
	if err != nil {
		t.Fatalf("NewRemoteSource: %v", err)
	}
	initial, err := src.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	policies = policy.NewProvider(initial)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := src.Start(ctx); err != nil {
		t.Fatalf("src.Start: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	// --- Build the proxy. ---
	chain := pipeline.NewChain()
	chain.Register(pathscanstage.New(pathscanstage.Config{Policies: policies}, nil))

	srv := proxy.New(proxy.Config{
		Addr:             "127.0.0.1:0",
		CA:               caInst,
		Pipeline:         chain,
		AuditFunc:        auditLogger,
		UpstreamTLS:      &tls.Config{RootCAs: upstreamPool, ServerName: upstreamURL.Hostname()},
		UpstreamResolver: func(_ string) (string, error) { return upstreamURL.Host, nil },
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go srv.Serve(ctx, ln)

	// --- Make a proxied HTTPS request through the agent. ---
	caPool := x509.NewCertPool()
	caPool.AddCert(caInst.RootCert())
	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "api.anthropic.com"},
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Post("https://api.anthropic.com/v1/messages",
		"application/json", strings.NewReader(`{"hi":1}`))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	resp.Body.Close()

	// --- Assertion 1: policy server saw Authorization equal to the device token. ---
	mu.Lock()
	seen := append([]string(nil), authSeen...)
	mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("policy server received no requests")
	}
	found := false
	for _, h := range seen {
		if h == deviceToken {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("policy server: never saw Authorization=%q; saw %v", deviceToken, seen)
	}

	// --- Assertion 2: audit log contains a record with our org_id. ---
	// The proxy's audit Log call happens in a defer after the response is
	// streamed back, so the record may not have landed yet. Poll until the
	// audit file contains the record before closing the writer.
	records := waitForAuditRecords(t, auditPath, 1, 2*time.Second)

	// Flush the audit writer so no further writes race with the read.
	_ = auditWriter.Close()

	foundOrg := false
	for _, r := range records {
		if r.OrgID == orgID {
			foundOrg = true
			break
		}
	}
	if !foundOrg {
		t.Errorf("audit log: no record carried org_id=%q; records: %+v", orgID, records)
	}
}
