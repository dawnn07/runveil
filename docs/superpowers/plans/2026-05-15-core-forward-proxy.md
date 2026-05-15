# Core Forward Proxy + TLS Interception Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the foundation of Railcore — a localhost forward HTTPS proxy that intercepts TLS, runs an extensible request pipeline, and forwards traffic to upstream AI provider APIs unmodified — so sub-projects #2–6 can register stages against it.

**Architecture:** Single Go module, custom forward proxy on stdlib `net/http` (no third-party proxy libraries). Four internal packages with a one-way dependency graph: `pipeline`, `ca`, `trust` are leaves; `proxy` depends on all three. One stage (`forwardStage`, a no-op `Continue`) is registered for this cycle.

**Tech Stack:** Go 1.23 (stdlib only for runtime — `net/http`, `crypto/*`, `log/slog`); `github.com/google/uuid` for request IDs; `go.uber.org/goleak` and `github.com/stretchr/testify` for tests; `golangci-lint` + `govulncheck` in CI; GitHub Actions matrix across Linux/macOS/Windows.

**Spec:** [`docs/superpowers/specs/2026-05-15-core-forward-proxy-design.md`](../specs/2026-05-15-core-forward-proxy-design.md)

---

## File Map

| File | Purpose |
|---|---|
| `go.mod`, `go.sum` | Module declaration, dependency lock |
| `.gitignore` | Ignore build artifacts, CA dir for local runs |
| `LICENSE` | Apache 2.0 |
| `README.md` | Placeholder pointing at spec |
| `Makefile` | `make build`, `make test`, `make lint` |
| `cmd/railcore/main.go` | Thin entrypoint: load CA, register `forwardStage`, start server |
| `internal/pipeline/stage.go` | `Stage` interface, `RequestCtx`, `Decision` enum |
| `internal/pipeline/chain.go` | `Chain` dispatch with panic recovery |
| `internal/pipeline/chain_test.go` | Unit tests for `Chain` |
| `internal/ca/ca.go` | Root CA generate + load + on-disk persistence |
| `internal/ca/leaf.go` | Per-host leaf minting with in-memory cache |
| `internal/ca/ca_test.go` | Unit tests for CA + leaf |
| `internal/trust/trust.go` | Platform-agnostic `Installer` interface + `ErrNeedsManual` |
| `internal/trust/trust_linux.go` | Linux: `update-ca-certificates` + NSS fallback |
| `internal/trust/trust_darwin.go` | macOS: `security add-trusted-cert` |
| `internal/trust/trust_windows.go` | Windows: `certutil -addstore` |
| `internal/trust/trust_test.go` | Shared unit tests (real install gated by env var) |
| `internal/proxy/server.go` | Listen, accept, `CONNECT` parsing, request dispatch |
| `internal/proxy/intercept.go` | TLS server-side interception with minted leaf |
| `internal/proxy/upstream.go` | Upstream TLS dial + streaming response copy |
| `internal/proxy/server_test.go` | Unit tests for proxy |
| `test/integration/passthrough_test.go` | End-to-end tests against `httptest.NewTLSServer` |
| `.github/workflows/ci.yml` | CI matrix: build, lint, test, vuln-check across 3 OSes |

**Dependency direction (must not be violated):**

```
cmd/railcore  →  internal/proxy  →  { internal/pipeline, internal/ca, internal/trust }
```

`internal/pipeline`, `internal/ca`, `internal/trust` import nothing else from `internal/`.

---

## Task 1: Module bootstrap and repo skeleton

**Files:**
- Create: `go.mod`
- Create: `.gitignore`
- Create: `LICENSE`
- Create: `README.md`
- Create: `Makefile`

- [ ] **Step 1: Initialize Go module**

Run from repo root:
```bash
go mod init railcore
```

Expected: `go.mod` created with `module railcore` and the active Go version.

- [ ] **Step 2: Pin Go version to 1.23**

Edit `go.mod` so the `go` directive reads:
```
go 1.23
```

- [ ] **Step 3: Write `.gitignore`**

Create `.gitignore` with:
```
# Binaries
/railcore
/railcore.exe
/dist/

# Go build cache
*.test
*.out
coverage.txt

# Local CA generated during dev runs
.railcore-data/
~/.railcore/

# IDE
.vscode/
.idea/
*.swp
```

- [ ] **Step 4: Write `LICENSE`**

Create `LICENSE` containing the full text of the **Apache License 2.0** (https://www.apache.org/licenses/LICENSE-2.0.txt — paste the canonical text, do not paraphrase).

Set the copyright line to:
```
Copyright 2026 Railcore Authors
```

- [ ] **Step 5: Write placeholder `README.md`**

Create `README.md`:
```markdown
# Railcore

Local-first AI firewall for coding assistants. Intercepts AI tool traffic to detect and prevent leakage of secrets and sensitive code.

This repository is in active development. See [`docs/superpowers/specs/`](docs/superpowers/specs/) for design documents.

## License

Apache 2.0 — see [LICENSE](LICENSE).
```

- [ ] **Step 6: Write `Makefile`**

Create `Makefile`:
```makefile
.PHONY: build test test-race lint vet vuln clean

build:
	go build -o railcore ./cmd/railcore

test:
	go test ./...

test-race:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

vet:
	go vet ./...

vuln:
	govulncheck ./...

clean:
	rm -f railcore railcore.exe
	rm -rf dist/
```

- [ ] **Step 7: Verify the module builds (no source yet, just metadata)**

Run:
```bash
go mod tidy
```

Expected: no errors. `go.sum` may not yet exist (no deps).

- [ ] **Step 8: Commit**

```bash
git add go.mod .gitignore LICENSE README.md Makefile
git commit -m "chore: bootstrap Go module and repo skeleton"
```

---

## Task 2: Pipeline — `Stage` interface and `RequestCtx`

**Files:**
- Create: `internal/pipeline/stage.go`
- Create: `internal/pipeline/chain_test.go` (test stubs only in this task)

- [ ] **Step 1: Write `stage.go` with types only (no `Chain` yet)**

Create `internal/pipeline/stage.go`:
```go
// Package pipeline defines the Stage interface and Chain dispatcher used
// by the Railcore proxy to run extensible request-processing stages.
//
// pipeline is a leaf package: it must not import any other internal/ package.
package pipeline

import (
	"context"
	"net/http"
	"time"
)

// Decision is the result a Stage returns after processing a request.
type Decision int

const (
	// Continue passes control to the next stage.
	Continue Decision = iota
	// Block halts the chain. The proxy returns 403 to the client without
	// dialling upstream.
	Block
	// Modify is a hint that the current stage mutated rc.Req. The proxy
	// treats Modify identically to Continue in this release.
	Modify
)

// String returns a stable lowercase name for the decision, suitable for logs.
func (d Decision) String() string {
	switch d {
	case Continue:
		return "continue"
	case Block:
		return "block"
	case Modify:
		return "modify"
	default:
		return "unknown"
	}
}

// RequestCtx is the per-request value threaded through every Stage.
// Stages may read rc.Req, annotate rc.Metadata, and (for Modify decisions)
// mutate rc.Req. Concurrent access by other goroutines is not supported.
type RequestCtx struct {
	Req       *http.Request
	Host      string
	Metadata  map[string]any
	StartedAt time.Time
}

// Stage is a single processing step in the request pipeline.
type Stage interface {
	Name() string
	Process(ctx context.Context, rc *RequestCtx) (Decision, error)
}
```

- [ ] **Step 2: Verify it compiles**

Run:
```bash
go build ./internal/pipeline/...
```

Expected: no output, exit 0.

- [ ] **Step 3: Commit**

```bash
git add internal/pipeline/stage.go
git commit -m "feat(pipeline): add Stage interface, RequestCtx, Decision enum"
```

---

## Task 3: Pipeline — `Chain` with TDD

**Files:**
- Create: `internal/pipeline/chain_test.go`
- Create: `internal/pipeline/chain.go`

- [ ] **Step 1: Write the failing test file**

Create `internal/pipeline/chain_test.go`:
```go
package pipeline

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type recordingStage struct {
	name     string
	decision Decision
	err      error
	panic    any
	called   *int32
}

func (s *recordingStage) Name() string { return s.name }
func (s *recordingStage) Process(_ context.Context, _ *RequestCtx) (Decision, error) {
	atomic.AddInt32(s.called, 1)
	if s.panic != nil {
		panic(s.panic)
	}
	return s.decision, s.err
}

func newCtx() *RequestCtx {
	req := httptest.NewRequest("POST", "https://api.example.com/v1/chat", nil)
	return &RequestCtx{
		Req:       req,
		Host:      "api.example.com",
		Metadata:  map[string]any{},
		StartedAt: time.Now(),
	}
}

func TestChain_EmptyChainReturnsContinue(t *testing.T) {
	c := NewChain()
	dec, err := c.Run(context.Background(), newCtx())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec != Continue {
		t.Fatalf("expected Continue, got %v", dec)
	}
}

func TestChain_RunsStagesInRegistrationOrder(t *testing.T) {
	var order []string
	var mu sync.Mutex
	mkStage := func(name string) Stage {
		return &funcStage{
			name: name,
			fn: func(_ context.Context, _ *RequestCtx) (Decision, error) {
				mu.Lock()
				order = append(order, name)
				mu.Unlock()
				return Continue, nil
			},
		}
	}
	c := NewChain()
	c.Register(mkStage("a"))
	c.Register(mkStage("b"))
	c.Register(mkStage("c"))

	if _, err := c.Run(context.Background(), newCtx()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"a", "b", "c"}
	if len(order) != len(want) {
		t.Fatalf("got %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("got %v, want %v", order, want)
		}
	}
}

func TestChain_BlockHaltsChain(t *testing.T) {
	var called int32
	first := &recordingStage{name: "block", decision: Block, called: &called}
	var afterCalled int32
	after := &recordingStage{name: "after", decision: Continue, called: &afterCalled}

	c := NewChain()
	c.Register(first)
	c.Register(after)

	dec, err := c.Run(context.Background(), newCtx())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec != Block {
		t.Fatalf("expected Block, got %v", dec)
	}
	if atomic.LoadInt32(&afterCalled) != 0 {
		t.Fatalf("stage after Block must not be called, but was called %d times", afterCalled)
	}
}

func TestChain_PanicRecoveredAsContinue(t *testing.T) {
	var afterCalled int32
	c := NewChain()
	c.Register(&recordingStage{name: "panic", decision: Continue, panic: "boom", called: new(int32)})
	c.Register(&recordingStage{name: "after", decision: Continue, called: &afterCalled})

	dec, err := c.Run(context.Background(), newCtx())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec != Continue {
		t.Fatalf("expected Continue after panic, got %v", dec)
	}
	if atomic.LoadInt32(&afterCalled) != 1 {
		t.Fatalf("stage after recovered panic must be called once, got %d", afterCalled)
	}
}

func TestChain_StageErrorTreatedAsContinue(t *testing.T) {
	var afterCalled int32
	c := NewChain()
	c.Register(&recordingStage{name: "err", decision: Continue, err: errors.New("oops"), called: new(int32)})
	c.Register(&recordingStage{name: "after", decision: Continue, called: &afterCalled})

	dec, err := c.Run(context.Background(), newCtx())
	if err != nil {
		t.Fatalf("Chain.Run must not return errors to caller; got %v", err)
	}
	if dec != Continue {
		t.Fatalf("expected Continue, got %v", dec)
	}
	if atomic.LoadInt32(&afterCalled) != 1 {
		t.Fatalf("subsequent stage must still run after error; called %d times", afterCalled)
	}
}

func TestChain_ConcurrentRunsAreIsolated(t *testing.T) {
	stage := &funcStage{name: "annotate", fn: func(_ context.Context, rc *RequestCtx) (Decision, error) {
		rc.Metadata["x"] = 1
		return Continue, nil
	}}
	c := NewChain()
	c.Register(stage)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rc := newCtx()
			if _, err := c.Run(context.Background(), rc); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if rc.Metadata["x"] != 1 {
				t.Errorf("metadata bleed between requests")
			}
		}()
	}
	wg.Wait()
}

// funcStage is a Stage backed by a function; used in tests above.
type funcStage struct {
	name string
	fn   func(context.Context, *RequestCtx) (Decision, error)
}

func (s *funcStage) Name() string { return s.name }
func (s *funcStage) Process(ctx context.Context, rc *RequestCtx) (Decision, error) {
	return s.fn(ctx, rc)
}
```

- [ ] **Step 2: Run the test and confirm it fails**

Run:
```bash
go test ./internal/pipeline/...
```

Expected: compile error — `NewChain`, `Chain.Register`, `Chain.Run` are undefined.

- [ ] **Step 3: Implement `chain.go`**

Create `internal/pipeline/chain.go`:
```go
package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
)

// Chain dispatches a sequence of registered Stages over a RequestCtx.
//
// Chain is safe for concurrent use after all Register calls complete.
// Register itself is NOT safe to call concurrently with Run.
type Chain struct {
	stages []Stage
	log    *slog.Logger
}

// NewChain returns an empty Chain that logs to slog.Default().
func NewChain() *Chain {
	return &Chain{log: slog.Default()}
}

// WithLogger returns a copy of c that uses log instead of slog.Default().
func (c *Chain) WithLogger(log *slog.Logger) *Chain {
	cp := *c
	cp.log = log
	return &cp
}

// Register adds s to the end of the chain.
func (c *Chain) Register(s Stage) {
	c.stages = append(c.stages, s)
}

// Run executes each stage in order. The first stage to return Block halts
// the chain and Run returns Block. Stages that panic or return a non-nil
// error are logged and treated as Continue (fail-open).
func (c *Chain) Run(ctx context.Context, rc *RequestCtx) (Decision, error) {
	for _, s := range c.stages {
		dec, err := c.runStage(ctx, s, rc)
		if dec == Block {
			return Block, nil
		}
		if err != nil {
			c.log.Warn("pipeline stage returned error",
				"stage", s.Name(),
				"host", rc.Host,
				"err", err.Error())
			// Treat as Continue (fail-open).
			continue
		}
		// Continue or Modify both proceed; nothing to do.
		_ = dec
	}
	return Continue, nil
}

func (c *Chain) runStage(ctx context.Context, s Stage, rc *RequestCtx) (dec Decision, err error) {
	defer func() {
		if r := recover(); r != nil {
			c.log.Error("pipeline stage panicked",
				"stage", s.Name(),
				"host", rc.Host,
				"panic", fmt.Sprint(r),
				"stack", string(debug.Stack()))
			dec = Continue
			err = nil
		}
	}()
	return s.Process(ctx, rc)
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run:
```bash
go test -race -count=1 ./internal/pipeline/...
```

Expected: `PASS` for all six tests, `ok railcore/internal/pipeline`.

- [ ] **Step 5: Commit**

```bash
git add internal/pipeline/chain.go internal/pipeline/chain_test.go
git commit -m "feat(pipeline): add Chain with panic recovery and fail-open errors"
```

---

## Task 4: CA — root generate and persist

**Files:**
- Create: `internal/ca/ca_test.go`
- Create: `internal/ca/ca.go`

- [ ] **Step 1: Write the failing test for `GenerateOrLoad`**

Create `internal/ca/ca_test.go`:
```go
package ca

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenerateOrLoad_CreatesFreshRoot(t *testing.T) {
	dir := t.TempDir()
	c, err := GenerateOrLoad(dir)
	if err != nil {
		t.Fatalf("GenerateOrLoad: %v", err)
	}
	if c == nil {
		t.Fatal("CA is nil")
	}

	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %s to exist: %v", p, err)
		}
	}

	// Skip permission assertions on Windows; POSIX modes are not meaningful.
	if runtime.GOOS != "windows" {
		keyInfo, err := os.Stat(keyPath)
		if err != nil {
			t.Fatalf("stat key: %v", err)
		}
		if mode := keyInfo.Mode().Perm(); mode != 0o600 {
			t.Fatalf("key perm = %o, want 0600", mode)
		}
	}

	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("ca.crt is not PEM-encoded")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("root cert must have IsCA=true")
	}
	if cert.Subject.CommonName != "Railcore Local CA" {
		t.Fatalf("CN = %q, want %q", cert.Subject.CommonName, "Railcore Local CA")
	}
}

func TestGenerateOrLoad_ReloadsExistingRoot(t *testing.T) {
	dir := t.TempDir()
	c1, err := GenerateOrLoad(dir)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	c2, err := GenerateOrLoad(dir)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !c1.rootCert.Equal(c2.rootCert) {
		t.Fatal("second call returned a different cert; expected identical reload")
	}
}

func TestRootPath_PointsAtCertFile(t *testing.T) {
	dir := t.TempDir()
	c, err := GenerateOrLoad(dir)
	if err != nil {
		t.Fatalf("GenerateOrLoad: %v", err)
	}
	if got, want := c.RootPath(), filepath.Join(dir, "ca.crt"); got != want {
		t.Fatalf("RootPath = %q, want %q", got, want)
	}
}
```

- [ ] **Step 2: Run and confirm tests fail to compile**

Run:
```bash
go test ./internal/ca/...
```

Expected: compile error — `GenerateOrLoad`, `RootPath`, `rootCert` undefined.

- [ ] **Step 3: Implement `ca.go`**

Create `internal/ca/ca.go`:
```go
// Package ca generates and persists a local Certificate Authority used to
// MITM HTTPS traffic, and mints per-host leaf certificates signed by it.
//
// ca is a leaf package: it must not import any other internal/ package.
package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	rootCertFile = "ca.crt"
	rootKeyFile  = "ca.key"
	rootCN       = "Railcore Local CA"
	rootValidity = 10 * 365 * 24 * time.Hour
	rootKeyBits  = 4096
)

// CA holds the root certificate and signing key for the local Railcore CA,
// plus an in-memory cache of minted leaf certificates.
type CA struct {
	dir      string
	rootCert *x509.Certificate
	rootKey  *rsa.PrivateKey

	leafMu    sync.Mutex
	leafCache map[string]*leafEntry
}

// GenerateOrLoad returns a CA backed by ca.crt + ca.key under dir, creating
// them on first use. The directory is created with mode 0700 if missing.
func GenerateOrLoad(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create ca dir: %w", err)
	}
	certPath := filepath.Join(dir, rootCertFile)
	keyPath := filepath.Join(dir, rootKeyFile)

	if _, err := os.Stat(certPath); err == nil {
		return loadRoot(dir, certPath, keyPath)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat ca cert: %w", err)
	}

	return generateRoot(dir, certPath, keyPath)
}

func generateRoot(dir, certPath, keyPath string) (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, rootKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: rootCN, Organization: []string{"Railcore"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(rootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign root: %w", err)
	}

	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return nil, fmt.Errorf("write cert: %w", err)
	}
	if err := writePEM(keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), 0o600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated cert: %w", err)
	}

	return &CA{
		dir:       dir,
		rootCert:  cert,
		rootKey:   key,
		leafCache: make(map[string]*leafEntry),
	}, nil
}

func loadRoot(dir, certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("ca.crt is not PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("ca.key is not PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}

	return &CA{
		dir:       dir,
		rootCert:  cert,
		rootKey:   key,
		leafCache: make(map[string]*leafEntry),
	}, nil
}

// RootPath returns the absolute path of the root certificate file on disk.
func (c *CA) RootPath() string {
	return filepath.Join(c.dir, rootCertFile)
}

// RootCert returns the parsed root certificate. The returned pointer must
// not be mutated.
func (c *CA) RootCert() *x509.Certificate {
	return c.rootCert
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("random serial: %w", err)
	}
	return n, nil
}
```

- [ ] **Step 4: Create a minimal `leaf.go` stub so the package compiles**

Create `internal/ca/leaf.go`:
```go
package ca

// leafEntry is the in-memory cache value for minted leaf certificates.
// Populated by MintLeaf (added in the next task).
type leafEntry struct{}
```

- [ ] **Step 5: Run the tests and confirm they pass**

Run:
```bash
go test -race -count=1 ./internal/ca/...
```

Expected: `PASS` for all three tests.

- [ ] **Step 6: Commit**

```bash
git add internal/ca/ca.go internal/ca/leaf.go internal/ca/ca_test.go
git commit -m "feat(ca): generate and persist local CA root"
```

---

## Task 5: CA — per-host leaf minting

**Files:**
- Modify: `internal/ca/leaf.go`
- Modify: `internal/ca/ca_test.go` (append tests)

- [ ] **Step 1: Append failing tests for `MintLeaf`**

Append to `internal/ca/ca_test.go`:
```go

func TestMintLeaf_ContainsHostSANAndChainsToRoot(t *testing.T) {
	dir := t.TempDir()
	c, err := GenerateOrLoad(dir)
	if err != nil {
		t.Fatalf("GenerateOrLoad: %v", err)
	}

	tlsCert, err := c.MintLeaf("api.openai.com")
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	if len(tlsCert.Certificate) == 0 {
		t.Fatal("tls.Certificate.Certificate is empty")
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	found := false
	for _, san := range leaf.DNSNames {
		if san == "api.openai.com" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("leaf DNS SANs = %v, want to contain api.openai.com", leaf.DNSNames)
	}

	pool := x509.NewCertPool()
	pool.AddCert(c.rootCert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("leaf did not chain to root: %v", err)
	}
}

func TestMintLeaf_CachesByHost(t *testing.T) {
	c, err := GenerateOrLoad(t.TempDir())
	if err != nil {
		t.Fatalf("GenerateOrLoad: %v", err)
	}
	a, err := c.MintLeaf("api.openai.com")
	if err != nil {
		t.Fatalf("first MintLeaf: %v", err)
	}
	b, err := c.MintLeaf("api.openai.com")
	if err != nil {
		t.Fatalf("second MintLeaf: %v", err)
	}
	// Pointer equality: same cached cert returned both times.
	if a != b {
		t.Fatal("expected same *tls.Certificate from cache; got different pointers")
	}
}

func TestMintLeaf_ConcurrentSameHostReturnsSingleCert(t *testing.T) {
	c, err := GenerateOrLoad(t.TempDir())
	if err != nil {
		t.Fatalf("GenerateOrLoad: %v", err)
	}
	const n = 32
	results := make(chan any, n)
	for i := 0; i < n; i++ {
		go func() {
			cert, err := c.MintLeaf("api.openai.com")
			if err != nil {
				results <- err
				return
			}
			results <- cert
		}()
	}
	var first any
	for i := 0; i < n; i++ {
		r := <-results
		if err, ok := r.(error); ok {
			t.Fatalf("MintLeaf error: %v", err)
		}
		if first == nil {
			first = r
			continue
		}
		if r != first {
			t.Fatal("concurrent MintLeaf for same host returned different certs")
		}
	}
}
```

- [ ] **Step 2: Run and confirm new tests fail to compile**

Run:
```bash
go test ./internal/ca/...
```

Expected: compile error — `MintLeaf` undefined on `*CA`.

- [ ] **Step 3: Implement `leaf.go`**

Replace the contents of `internal/ca/leaf.go`:
```go
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"
)

const (
	leafValidity = 7 * 24 * time.Hour
)

// leafEntry is the in-memory cache value for minted leaf certificates.
type leafEntry struct {
	cert *tls.Certificate
}

// MintLeaf returns a tls.Certificate for the given host, signed by the
// root CA. The same *tls.Certificate is returned for repeated calls for
// the same host (cached for the lifetime of the CA).
func (c *CA) MintLeaf(host string) (*tls.Certificate, error) {
	c.leafMu.Lock()
	defer c.leafMu.Unlock()

	if entry, ok := c.leafCache[host]; ok {
		return entry.cert, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"Railcore"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.rootCert, &key.PublicKey, c.rootKey)
	if err != nil {
		return nil, fmt.Errorf("sign leaf: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{der, c.rootCert.Raw},
		PrivateKey:  key,
	}

	c.leafCache[host] = &leafEntry{cert: tlsCert}
	return tlsCert, nil
}
```

- [ ] **Step 4: Run tests with `-race` and confirm they pass**

Run:
```bash
go test -race -count=1 ./internal/ca/...
```

Expected: `PASS` for six tests total in the ca package.

- [ ] **Step 5: Commit**

```bash
git add internal/ca/leaf.go internal/ca/ca_test.go
git commit -m "feat(ca): mint per-host leaf certs with in-memory cache"
```

---

## Task 6: Trust — platform-agnostic interface and `ErrNeedsManual`

**Files:**
- Create: `internal/trust/trust.go`
- Create: `internal/trust/trust_test.go`

- [ ] **Step 1: Write failing test for the interface contract**

Create `internal/trust/trust_test.go`:
```go
package trust

import (
	"errors"
	"testing"
)

func TestNew_ReturnsNonNilInstaller(t *testing.T) {
	i := New()
	if i == nil {
		t.Fatal("New() returned nil")
	}
}

func TestErrNeedsManual_HasMessage(t *testing.T) {
	if !errors.Is(ErrNeedsManual, ErrNeedsManual) {
		t.Fatal("ErrNeedsManual does not satisfy errors.Is on itself")
	}
	if ErrNeedsManual.Error() == "" {
		t.Fatal("ErrNeedsManual has empty message")
	}
}

func TestManualInstructions_NonEmpty(t *testing.T) {
	// Whichever platform we're on, ManualInstructions must return a
	// non-empty string suitable for printing to the user.
	got := ManualInstructions("/some/path/ca.crt")
	if got == "" {
		t.Fatal("ManualInstructions returned empty string")
	}
}
```

- [ ] **Step 2: Run and confirm tests fail to compile**

Run:
```bash
go test ./internal/trust/...
```

Expected: compile error — `Installer`, `New`, `ErrNeedsManual`, `ManualInstructions` undefined.

- [ ] **Step 3: Implement `trust.go` (interface + shared types only)**

Create `internal/trust/trust.go`:
```go
// Package trust installs the Railcore local CA into the operating system's
// trust store. trust is a leaf package: it must not import any other
// internal/ package.
package trust

import "errors"

// ErrNeedsManual is returned from Install when auto-install cannot proceed
// (e.g., insufficient privileges, missing system tools). Callers should
// surface ManualInstructions to the user.
var ErrNeedsManual = errors.New("trust store install requires manual steps")

// Installer is the platform-agnostic trust-store API.
type Installer interface {
	// Install registers caPath as a trusted root in the OS trust store.
	// Returns ErrNeedsManual if the operation requires user action.
	Install(caPath string) error

	// Uninstall removes a previously installed root identified by caPath.
	Uninstall(caPath string) error

	// Status reports whether caPath appears to be trusted, and the method
	// (e.g., "system", "user-nss", "manual") used to verify.
	Status(caPath string) (installed bool, method string, err error)
}
```

- [ ] **Step 4: Implement per-platform stubs returning `ErrNeedsManual`**

Create `internal/trust/trust_linux.go`:
```go
//go:build linux

package trust

import (
	"fmt"
	"os/exec"
)

func New() Installer { return &linuxInstaller{} }

type linuxInstaller struct{}

func (l *linuxInstaller) Install(caPath string) error {
	// Try system store first (requires root).
	if err := tryUpdateCACertificates(caPath); err == nil {
		return nil
	}
	// Fall back to user NSS DB.
	if err := tryNSSInstall(caPath); err == nil {
		return nil
	}
	return ErrNeedsManual
}

func (l *linuxInstaller) Uninstall(caPath string) error {
	_ = tryNSSUninstall(caPath)
	_ = tryUpdateCACertificatesUninstall(caPath)
	return nil
}

func (l *linuxInstaller) Status(caPath string) (bool, string, error) {
	// Best-effort: check both stores. Full verification is integration-test territory.
	if _, err := exec.LookPath("update-ca-certificates"); err == nil {
		return false, "system-unknown", nil
	}
	return false, "manual", nil
}

func tryUpdateCACertificates(caPath string) error {
	if _, err := exec.LookPath("update-ca-certificates"); err != nil {
		return fmt.Errorf("update-ca-certificates not found: %w", err)
	}
	dest := "/usr/local/share/ca-certificates/railcore.crt"
	cp := exec.Command("cp", caPath, dest)
	if out, err := cp.CombinedOutput(); err != nil {
		return fmt.Errorf("cp: %s: %w", string(out), err)
	}
	upd := exec.Command("update-ca-certificates")
	if out, err := upd.CombinedOutput(); err != nil {
		return fmt.Errorf("update-ca-certificates: %s: %w", string(out), err)
	}
	return nil
}

func tryUpdateCACertificatesUninstall(_ string) error {
	dest := "/usr/local/share/ca-certificates/railcore.crt"
	exec.Command("rm", "-f", dest).Run()
	exec.Command("update-ca-certificates", "--fresh").Run()
	return nil
}

func tryNSSInstall(caPath string) error {
	if _, err := exec.LookPath("certutil"); err != nil {
		return fmt.Errorf("certutil not found: %w", err)
	}
	cmd := exec.Command("certutil", "-d", "sql:"+nssDBPath(), "-A", "-t", "C,,", "-n", "railcore", "-i", caPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("certutil: %s: %w", string(out), err)
	}
	return nil
}

func tryNSSUninstall(_ string) error {
	if _, err := exec.LookPath("certutil"); err != nil {
		return nil
	}
	cmd := exec.Command("certutil", "-d", "sql:"+nssDBPath(), "-D", "-n", "railcore")
	_, _ = cmd.CombinedOutput()
	return nil
}

func nssDBPath() string {
	if home, err := homeDir(); err == nil {
		return home + "/.pki/nssdb"
	}
	return "/root/.pki/nssdb"
}

// ManualInstructions returns shell commands the user can run by hand.
func ManualInstructions(caPath string) string {
	return fmt.Sprintf(`sudo cp %s /usr/local/share/ca-certificates/railcore.crt && sudo update-ca-certificates
# or, per-user (Firefox/Chrome NSS):
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n railcore -i %s
`, caPath, caPath)
}
```

Create `internal/trust/trust_darwin.go`:
```go
//go:build darwin

package trust

import (
	"fmt"
	"os/exec"
)

func New() Installer { return &darwinInstaller{} }

type darwinInstaller struct{}

func (d *darwinInstaller) Install(caPath string) error {
	// System keychain (admin required).
	sys := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain", caPath)
	if out, err := sys.CombinedOutput(); err == nil {
		_ = out
		return nil
	}
	// Fall back to user login keychain.
	usr := exec.Command("security", "add-trusted-cert", "-r", "trustRoot",
		"-k", homeKeychain(), caPath)
	if out, err := usr.CombinedOutput(); err == nil {
		_ = out
		return nil
	}
	return ErrNeedsManual
}

func (d *darwinInstaller) Uninstall(caPath string) error {
	exec.Command("security", "remove-trusted-cert", "-d", caPath).Run()
	exec.Command("security", "remove-trusted-cert", caPath).Run()
	return nil
}

func (d *darwinInstaller) Status(_ string) (bool, string, error) {
	return false, "darwin-unknown", nil
}

func homeKeychain() string {
	if home, err := homeDir(); err == nil {
		return home + "/Library/Keychains/login.keychain-db"
	}
	return ""
}

// ManualInstructions returns shell commands the user can run by hand.
func ManualInstructions(caPath string) string {
	return fmt.Sprintf(`sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s
# or, per-user:
security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db %s
`, caPath, caPath)
}
```

Create `internal/trust/trust_windows.go`:
```go
//go:build windows

package trust

import (
	"fmt"
	"os/exec"
)

func New() Installer { return &windowsInstaller{} }

type windowsInstaller struct{}

func (w *windowsInstaller) Install(caPath string) error {
	// LocalMachine root (requires admin).
	sys := exec.Command("certutil", "-addstore", "-f", "Root", caPath)
	if out, err := sys.CombinedOutput(); err == nil {
		_ = out
		return nil
	}
	// Fall back to current user.
	ps := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`Import-Certificate -FilePath "%s" -CertStoreLocation Cert:\CurrentUser\Root | Out-Null`, caPath))
	if out, err := ps.CombinedOutput(); err == nil {
		_ = out
		return nil
	}
	return ErrNeedsManual
}

func (w *windowsInstaller) Uninstall(caPath string) error {
	exec.Command("certutil", "-delstore", "Root", caPath).Run()
	exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Subject -like "*Railcore*" } | Remove-Item`)).Run()
	return nil
}

func (w *windowsInstaller) Status(_ string) (bool, string, error) {
	return false, "windows-unknown", nil
}

// ManualInstructions returns shell commands the user can run by hand.
func ManualInstructions(caPath string) string {
	return fmt.Sprintf(`# As Administrator:
certutil -addstore -f Root "%s"
# or, per-user (PowerShell):
Import-Certificate -FilePath "%s" -CertStoreLocation Cert:\CurrentUser\Root
`, caPath, caPath)
}
```

- [ ] **Step 5: Add the shared `homeDir` helper**

Create `internal/trust/home.go`:
```go
package trust

import "os"

func homeDir() (string, error) {
	return os.UserHomeDir()
}
```

- [ ] **Step 6: Run the tests and confirm they pass**

Run:
```bash
go test -race -count=1 ./internal/trust/...
```

Expected: `PASS` for three tests on Linux. (On macOS / Windows the same tests run via build-tagged files.)

- [ ] **Step 7: Verify build-tagged files compile for all three GOOS targets**

Run:
```bash
GOOS=linux   go build ./internal/trust/...
GOOS=darwin  go build ./internal/trust/...
GOOS=windows go build ./internal/trust/...
```

Expected: each command exits 0 with no output.

- [ ] **Step 8: Commit**

```bash
git add internal/trust/
git commit -m "feat(trust): cross-platform trust-store install with manual fallback"
```

---

## Task 7: Trust — opt-in real-install integration test

**Files:**
- Modify: `internal/trust/trust_test.go` (append)

- [ ] **Step 1: Append the gated integration test**

Append to `internal/trust/trust_test.go`:
```go

// TestInstall_RealTrustStore actually mutates the running machine's trust
// store. Disabled by default; enable with RAILCORE_INTEGRATION=1.
//
// The test installs and then uninstalls a freshly generated CA. It fails
// loud if Install returns an error other than ErrNeedsManual.
func TestInstall_RealTrustStore(t *testing.T) {
	if os.Getenv("RAILCORE_INTEGRATION") != "1" {
		t.Skip("set RAILCORE_INTEGRATION=1 to enable trust-store integration test")
	}

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := writeTestCA(caPath); err != nil {
		t.Fatalf("write test CA: %v", err)
	}

	i := New()
	t.Cleanup(func() { _ = i.Uninstall(caPath) })

	if err := i.Install(caPath); err != nil && !errors.Is(err, ErrNeedsManual) {
		t.Fatalf("Install: %v", err)
	}
}

// writeTestCA generates a throwaway CA and writes it to path. Defined here
// (not imported from internal/ca) to keep trust a leaf package.
func writeTestCA(path string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Railcore Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}
```

Add these imports to the top of `internal/trust/trust_test.go` (merge with the existing `errors`/`testing` block):
```go
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)
```

- [ ] **Step 2: Run tests without the env var; the integration test should skip**

Run:
```bash
go test -race -count=1 ./internal/trust/...
```

Expected: `--- SKIP: TestInstall_RealTrustStore` plus PASS for the other three tests.

- [ ] **Step 3: Commit**

```bash
git add internal/trust/trust_test.go
git commit -m "test(trust): add opt-in real trust-store integration test"
```

---

## Task 8: Proxy — `CONNECT` parsing with TDD

**Files:**
- Create: `internal/proxy/server_test.go`
- Create: `internal/proxy/server.go`

- [ ] **Step 1: Write the failing test for non-:443 CONNECT rejection**

Create `internal/proxy/server_test.go`:
```go
package proxy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"railcore/internal/ca"
	"railcore/internal/pipeline"
)

func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	c, err := ca.GenerateOrLoad(t.TempDir())
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	chain := pipeline.NewChain()
	srv := New(Config{
		Addr:        "127.0.0.1:0",
		CA:          c,
		Pipeline:    chain,
		MaxBodyBytes: 32 * 1024 * 1024,
	})

	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() { _ = srv.Serve(context.Background(), ln) }()
	return srv, ln.Addr().String()
}

func TestProxy_RejectsConnectToNon443(t *testing.T) {
	_, addr := newTestServer(t)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Write([]byte("CONNECT api.openai.com:80 HTTP/1.1\r\nHost: api.openai.com:80\r\n\r\n")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("expected JSON error body, got Content-Type=%q", resp.Header.Get("Content-Type"))
	}
}
```

- [ ] **Step 2: Run and confirm tests fail to compile**

Run:
```bash
go test ./internal/proxy/...
```

Expected: compile error — `New`, `Config`, `Server.Addr`, `Server.Serve` undefined.

- [ ] **Step 3: Implement minimal `server.go`**

Create `internal/proxy/server.go`:
```go
// Package proxy implements the Railcore forward HTTPS proxy.
package proxy

import (
	"bufio"
	"context"
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
	Addr         string             // e.g. "127.0.0.1:9443"
	CA           *ca.CA             // local CA for minting leaves
	Pipeline     *pipeline.Chain    // request pipeline
	MaxBodyBytes int64              // cap per-request body (default 32 MiB)
	Logger       *slog.Logger       // optional; defaults to slog.Default()
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

// handleIntercepted is implemented in intercept.go.
//
// Placeholder so server.go compiles standalone; real impl in next task.
func (s *Server) handleIntercepted(_ context.Context, _ net.Conn, _ string, _ string) error {
	return fmt.Errorf("not implemented yet")
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
```

- [ ] **Step 4: Add `google/uuid` to dependencies**

Run:
```bash
go get github.com/google/uuid@latest
go mod tidy
```

- [ ] **Step 5: Run the test and confirm it passes**

Run:
```bash
go test -race -count=1 ./internal/proxy/...
```

Expected: `PASS` for `TestProxy_RejectsConnectToNon443`.

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/server.go internal/proxy/server_test.go go.mod go.sum
git commit -m "feat(proxy): accept CONNECT, reject non-:443 targets with 400"
```

---

## Task 9: Proxy — TLS interception with minted leaf

**Files:**
- Create: `internal/proxy/intercept.go`
- Modify: `internal/proxy/server.go` (remove placeholder `handleIntercepted`)
- Modify: `internal/proxy/server_test.go` (append)

- [ ] **Step 1: Append a failing test for end-to-end TLS interception**

Append to `internal/proxy/server_test.go`:
```go

func TestProxy_InterceptsAndForwardsGET(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	srv, addr := newTestServer(t)
	srv.cfg.UpstreamTLS = &tls.Config{RootCAs: upstreamPool, ServerName: upstreamURL.Hostname()}
	srv.cfg.UpstreamResolver = func(_ string) (string, error) { return upstreamURL.Host, nil }

	caPool := x509.NewCertPool()
	caPool.AddCert(srv.cfg.CA.RootCert())
	proxyURL, _ := url.Parse("http://" + addr)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "example.test"},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get("https://example.test/")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "hello-from-upstream" {
		t.Fatalf("body = %q, want hello-from-upstream", string(body))
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}
```

Replace the imports at the top of `internal/proxy/server_test.go` with:
```go
import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"railcore/internal/ca"
	"railcore/internal/pipeline"
)
```

- [ ] **Step 2: Extend `Config` with `UpstreamTLS` and `UpstreamResolver`**

Edit `internal/proxy/server.go`. Update the `Config` struct:
```go
type Config struct {
	Addr             string
	CA               *ca.CA
	Pipeline         *pipeline.Chain
	MaxBodyBytes     int64
	Logger           *slog.Logger

	// UpstreamTLS, if non-nil, is used when dialling upstream. Default is
	// a tls.Config that uses the system root store.
	UpstreamTLS *tls.Config

	// UpstreamResolver, if non-nil, maps a CONNECT host (e.g. api.openai.com)
	// to the actual upstream host:port to dial. Used in tests to point the
	// proxy at httptest servers. nil means dial host:443 directly.
	UpstreamResolver func(host string) (string, error)
}
```

Add `"crypto/tls"` to `server.go` imports.

Remove the placeholder `handleIntercepted` function from `server.go` entirely (it will live in `intercept.go`).

- [ ] **Step 3: Add `golang.org/x/net/http2` dependency**

Run:
```bash
go get golang.org/x/net/http2@latest
go mod tidy
```

- [ ] **Step 4: Implement `intercept.go`**

Create `internal/proxy/intercept.go`:
```go
package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

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

	_ = tlsConn.SetDeadline(time.Now().Add(60 * time.Second))

	handler := s.newHandler(ctx, host, requestID)

	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		h2srv := &http2.Server{}
		h2srv.ServeConn(tlsConn, &http2.ServeConnOpts{Handler: handler})
		return nil
	}

	// HTTP/1.1: drive a one-shot http.Server over the intercepted conn.
	h1srv := &http.Server{Handler: handler}
	if err := h1srv.Serve(newSingleConnListener(tlsConn)); err != nil && err != errListenerClosed {
		return err
	}
	return nil
}
```

- [ ] **Step 5: Implement `upstream.go` (the single Handler used for both H1 and H2)**

Create `internal/proxy/upstream.go`:
```go
package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"railcore/internal/pipeline"
)

// newHandler returns the http.Handler that runs the pipeline and forwards
// allowed requests upstream. Used by both H1 and H2 servers.
func (s *Server) newHandler(parentCtx context.Context, host, requestID string) http.Handler {
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
	// IMPORTANT: no RootCAs set ⇒ system trust store is used. Do NOT add
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
```

- [ ] **Step 6: Run the test and confirm it passes**

Run:
```bash
go test -race -count=1 ./internal/proxy/...
```

Expected: `PASS` for `TestProxy_InterceptsAndForwardsGET` and the earlier 400 test.

- [ ] **Step 7: Commit**

```bash
git add internal/proxy/intercept.go internal/proxy/upstream.go internal/proxy/server.go internal/proxy/server_test.go go.mod go.sum
git commit -m "feat(proxy): intercept TLS, forward HTTP/1.1 and HTTP/2 to upstream"
```

---

## Task 10: Proxy — pipeline `Block` returns 403 without upstream dial

**Files:**
- Modify: `internal/proxy/server_test.go` (append)

- [ ] **Step 1: Append failing test for Block decision**

Append to `internal/proxy/server_test.go`:
```go

type alwaysBlockStage struct{}

func (alwaysBlockStage) Name() string { return "always-block" }
func (alwaysBlockStage) Process(_ context.Context, _ *pipeline.RequestCtx) (pipeline.Decision, error) {
	return pipeline.Block, nil
}

func TestProxy_BlockReturns403AndSkipsUpstream(t *testing.T) {
	var upstreamHits int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		_, _ = io.WriteString(w, "should-not-reach")
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	srv, addr := newTestServer(t)
	srv.cfg.UpstreamTLS = &tls.Config{RootCAs: upstreamPool, ServerName: upstreamURL.Hostname()}
	srv.cfg.UpstreamResolver = func(_ string) (string, error) { return upstreamURL.Host, nil }
	srv.cfg.Pipeline.Register(alwaysBlockStage{})

	caPool := x509.NewCertPool()
	caPool.AddCert(srv.cfg.CA.RootCert())
	proxyURL, _ := url.Parse("http://" + addr)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "blocked.test"},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get("https://blocked.test/")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&upstreamHits); got != 0 {
		t.Fatalf("upstream was dialled %d times; expected 0", got)
	}
}
```

Add `"sync/atomic"` to imports.

- [ ] **Step 2: Run the test and confirm it passes**

Run:
```bash
go test -race -count=1 ./internal/proxy/...
```

Expected: `PASS` for all proxy tests including the new one.

- [ ] **Step 3: Commit**

```bash
git add internal/proxy/server_test.go
git commit -m "test(proxy): verify Block decision returns 403 without upstream dial"
```

---

## Task 11: Proxy — 32 MiB body cap

**Files:**
- Modify: `internal/proxy/server_test.go` (append)
- Modify: `internal/proxy/intercept.go` (already enforces — verify)

- [ ] **Step 1: Append failing test for oversized body**

Append to `internal/proxy/server_test.go`:
```go

func TestProxy_OversizedBodyReturns413(t *testing.T) {
	srv, addr := newTestServer(t)
	srv.cfg.MaxBodyBytes = 1024 // 1 KiB cap for the test
	srv.cfg.UpstreamResolver = func(_ string) (string, error) {
		return "127.0.0.1:1", nil // unreachable; should never be dialled
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(srv.cfg.CA.RootCert())
	proxyURL, _ := url.Parse("http://" + addr)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "big.test"},
		},
		Timeout: 5 * time.Second,
	}

	body := strings.Repeat("A", 2048) // exceeds the 1 KiB cap
	resp, err := client.Post("https://big.test/", "text/plain", strings.NewReader(body))
	if err != nil {
		t.Fatalf("client.Post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}
```

- [ ] **Step 2: Run and confirm it passes**

Run:
```bash
go test -race -count=1 ./internal/proxy/...
```

Expected: `PASS` — the cap was implemented in Task 9; this test verifies it.

- [ ] **Step 3: Commit**

```bash
git add internal/proxy/server_test.go
git commit -m "test(proxy): verify 32 MiB body cap returns 413"
```

---

## Task 12: Proxy — SSE incremental flush

**Files:**
- Modify: `internal/proxy/server_test.go` (append)

- [ ] **Step 1: Append the SSE streaming test**

Append to `internal/proxy/server_test.go`:
```go

func TestProxy_SSEStreamsIncrementally(t *testing.T) {
	const numEvents = 5
	const gap = 50 * time.Millisecond

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for i := 0; i < numEvents; i++ {
			fmt.Fprintf(w, "data: event-%d\n\n", i)
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(gap)
		}
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	srv, addr := newTestServer(t)
	srv.cfg.UpstreamTLS = &tls.Config{RootCAs: upstreamPool, ServerName: upstreamURL.Hostname()}
	srv.cfg.UpstreamResolver = func(_ string) (string, error) { return upstreamURL.Host, nil }

	caPool := x509.NewCertPool()
	caPool.AddCert(srv.cfg.CA.RootCert())
	proxyURL, _ := url.Parse("http://" + addr)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "sse.test"},
		},
		Timeout: 10 * time.Second,
	}

	start := time.Now()
	resp, err := client.Get("https://sse.test/")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	for i := 0; i < numEvents; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read event %d: %v", i, err)
		}
		want := fmt.Sprintf("data: event-%d\n", i)
		if line != want {
			t.Fatalf("event %d = %q, want %q", i, line, want)
		}
		// Each event must arrive before the next event's gap elapses.
		// Allow generous slack: each event must arrive within gap*(i+2).
		elapsed := time.Since(start)
		if elapsed > gap*time.Duration(i+2) {
			t.Fatalf("event %d arrived after %v, expected within %v (buffering)", i, elapsed, gap*time.Duration(i+2))
		}
		// Skip the blank separator line.
		_, _ = reader.ReadString('\n')
	}
}
```

- [ ] **Step 2: Run the test and confirm it passes**

Run:
```bash
go test -race -count=1 -run TestProxy_SSEStreamsIncrementally ./internal/proxy/...
```

Expected: `PASS` within ~500ms.

- [ ] **Step 3: Commit**

```bash
git add internal/proxy/server_test.go
git commit -m "test(proxy): verify SSE responses are forwarded without buffering"
```

---

## Task 13: Proxy — concurrent requests + goroutine leak check

**Files:**
- Modify: `internal/proxy/server_test.go` (append)
- Modify: `go.mod` (add `go.uber.org/goleak`)

- [ ] **Step 1: Add `goleak` dependency**

Run:
```bash
go get go.uber.org/goleak@latest
go mod tidy
```

- [ ] **Step 2: Append the concurrent + leak test**

Append to `internal/proxy/server_test.go`:
```go

func TestProxy_ConcurrentRequestsNoLeaks(t *testing.T) {
	defer goleak.VerifyNone(t,
		// Silence known background goroutines from httptest's TLS server.
		goleak.IgnoreTopFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreTopFunction("net/http.(*persistConn).writeLoop"),
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
	)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	srv, addr := newTestServer(t)
	srv.cfg.UpstreamTLS = &tls.Config{RootCAs: upstreamPool, ServerName: upstreamURL.Hostname()}
	srv.cfg.UpstreamResolver = func(_ string) (string, error) { return upstreamURL.Host, nil }

	caPool := x509.NewCertPool()
	caPool.AddCert(srv.cfg.CA.RootCert())
	proxyURL, _ := url.Parse("http://" + addr)

	const n = 100
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
					TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "concurrent.test"},
				},
				Timeout: 10 * time.Second,
			}
			resp, err := client.Get("https://concurrent.test/")
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if string(body) != "ok" {
				errs <- fmt.Errorf("body = %q", string(body))
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("request failed: %v", err)
	}
}
```

Add to imports:
```go
"sync"
"go.uber.org/goleak"
```

- [ ] **Step 3: Run the test and confirm it passes**

Run:
```bash
go test -race -count=1 -run TestProxy_ConcurrentRequestsNoLeaks ./internal/proxy/...
```

Expected: `PASS` within ~10 seconds.

- [ ] **Step 4: Commit**

```bash
git add internal/proxy/server_test.go go.mod go.sum
git commit -m "test(proxy): 100 concurrent requests with goroutine leak check"
```

---

## Task 14: Wire the binary entrypoint

**Files:**
- Create: `cmd/railcore/main.go`

- [ ] **Step 1: Write the entrypoint**

Create `cmd/railcore/main.go`:
```go
// Package main is the Railcore proxy entrypoint. In this sub-project the
// binary supports a single command: `railcore proxy [--port N]`. Full CLI
// (init, start, stop, status, logs, test-policy) is sub-project #5.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"railcore/internal/ca"
	"railcore/internal/pipeline"
	"railcore/internal/proxy"
	"railcore/internal/trust"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "proxy" {
		fmt.Fprintln(os.Stderr, "usage: railcore proxy [--port N] [--data-dir PATH]")
		os.Exit(2)
	}

	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	port := fs.Int("port", defaultPort(), "TCP port to listen on (overrides RAILCORE_PORT)")
	dataDir := fs.String("data-dir", defaultDataDir(), "directory for CA + state")
	_ = fs.Parse(os.Args[2:])

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	caInst, err := ca.GenerateOrLoad(filepath.Join(*dataDir, "ca"))
	if err != nil {
		logger.Error("ca init failed", "err", err.Error())
		os.Exit(1)
	}

	// Best-effort trust install. If it fails, print manual instructions
	// and continue — the user may have done it already by hand.
	if err := trust.New().Install(caInst.RootPath()); err != nil {
		logger.Warn("trust-store auto-install did not complete",
			"err", err.Error(),
			"manual_steps", trust.ManualInstructions(caInst.RootPath()))
	}

	chain := pipeline.NewChain().WithLogger(logger)
	chain.Register(forwardStage{})

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	srv := proxy.New(proxy.Config{
		Addr:     addr,
		CA:       caInst,
		Pipeline: chain,
		Logger:   logger,
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("listen failed", "addr", addr, "err", err.Error())
		fmt.Fprintf(os.Stderr, "port %d in use; set RAILCORE_PORT or stop other process\n", *port)
		os.Exit(1)
	}
	logger.Info("railcore proxy listening", "addr", addr, "ca_path", caInst.RootPath())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	if err := srv.Serve(ctx, ln); err != nil {
		logger.Error("serve failed", "err", err.Error())
		os.Exit(1)
	}
}

func defaultPort() int {
	if v := os.Getenv("RAILCORE_PORT"); v != "" {
		var p int
		if _, err := fmt.Sscanf(v, "%d", &p); err == nil && p > 0 {
			return p
		}
	}
	return 9443
}

func defaultDataDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".railcore")
	}
	return ".railcore-data"
}

// forwardStage is the only registered stage in this sub-project. It is a
// no-op that always allows the request to proceed to upstream.
type forwardStage struct{}

func (forwardStage) Name() string { return "forward" }
func (forwardStage) Process(_ context.Context, _ *pipeline.RequestCtx) (pipeline.Decision, error) {
	return pipeline.Continue, nil
}
```

- [ ] **Step 2: Build the binary**

Run:
```bash
make build
```

Expected: produces `./railcore`. No errors.

- [ ] **Step 3: Smoke-test by hand**

Run:
```bash
./railcore proxy --port 9443 --data-dir /tmp/railcore-smoke &
sleep 1
curl -s -v -x http://127.0.0.1:9443 --cacert /tmp/railcore-smoke/ca/ca.crt https://example.com/ | head -20
kill %1
```

Expected: an HTTP response from example.com (status 200 or similar) demonstrating the proxy forwards real traffic.

- [ ] **Step 4: Commit**

```bash
git add cmd/railcore/main.go
git commit -m "feat(cmd): wire CA, pipeline, and proxy into railcore binary"
```

---

## Task 15: End-to-end integration test

**Files:**
- Create: `test/integration/passthrough_test.go`

- [ ] **Step 1: Write the integration test**

Create `test/integration/passthrough_test.go`:
```go
// Package integration contains end-to-end tests that spin up an in-process
// Railcore proxy and a fake upstream, then drive real http.Client traffic
// through both. These tests exercise the same wiring `cmd/railcore` does.
package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"railcore/internal/ca"
	"railcore/internal/pipeline"
	"railcore/internal/proxy"
)

func setup(t *testing.T) (*http.Client, *httptest.Server, func()) {
	t.Helper()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "method=%s path=%s", r.Method, r.URL.Path)
	}))
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	caInst, err := ca.GenerateOrLoad(t.TempDir())
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	chain := pipeline.NewChain()
	srv := proxy.New(proxy.Config{
		Addr:             "127.0.0.1:0",
		CA:               caInst,
		Pipeline:         chain,
		UpstreamTLS:      &tls.Config{RootCAs: upstreamPool, ServerName: upstreamURL.Hostname()},
		UpstreamResolver: func(_ string) (string, error) { return upstreamURL.Host, nil },
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Serve(ctx, ln)

	caPool := x509.NewCertPool()
	caPool.AddCert(caInst.RootCert())
	proxyURL, _ := url.Parse("http://" + ln.Addr().String())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "e2e.test"},
		},
		Timeout: 10 * time.Second,
	}

	cleanup := func() {
		cancel()
		_ = ln.Close()
		upstream.Close()
	}
	return client, upstream, cleanup
}

func TestPassthrough_GET(t *testing.T) {
	client, _, cleanup := setup(t)
	defer cleanup()

	resp, err := client.Get("https://e2e.test/hello")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if got, want := string(body), "method=GET path=/hello"; got != want {
		t.Fatalf("body=%q, want %q", got, want)
	}
}

func TestPassthrough_POST(t *testing.T) {
	client, _, cleanup := setup(t)
	defer cleanup()

	resp, err := client.Post("https://e2e.test/echo", "application/json",
		nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if got, want := string(body), "method=POST path=/echo"; got != want {
		t.Fatalf("body=%q, want %q", got, want)
	}
}
```

- [ ] **Step 2: Run the integration tests**

Run:
```bash
go test -race -count=1 ./test/integration/...
```

Expected: `PASS` for both tests.

- [ ] **Step 3: Commit**

```bash
git add test/integration/passthrough_test.go
git commit -m "test(integration): end-to-end passthrough through real proxy"
```

---

## Task 16: CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.golangci.yml`

- [ ] **Step 1: Write the lint config**

Create `.golangci.yml`:
```yaml
run:
  timeout: 5m

linters:
  disable-all: true
  enable:
    - errcheck
    - govet
    - staticcheck
    - unused

issues:
  exclude-rules:
    - path: _test\.go
      linters:
        - errcheck
```

- [ ] **Step 2: Write the GitHub Actions workflow**

Create `.github/workflows/ci.yml`:
```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    name: test (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'
          cache: true

      - name: go vet
        run: go vet ./...

      - name: go build
        run: go build ./...

      - name: go test (race + no cache)
        run: go test -race -count=1 ./...

      - name: gofmt check
        if: runner.os != 'Windows'
        run: |
          test -z "$(gofmt -l .)"

  lint:
    name: lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'
          cache: true
      - uses: golangci/golangci-lint-action@v6
        with:
          version: v1.59
          args: --timeout=5m

  trust-integration:
    name: trust-store integration (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    env:
      RAILCORE_INTEGRATION: '1'
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'
          cache: true
      - name: install + uninstall trust store
        run: go test -race -count=1 -run TestInstall_RealTrustStore ./internal/trust/...

  vuln:
    name: govulncheck (advisory)
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'
          cache: true
      - name: install govulncheck
        run: go install golang.org/x/vuln/cmd/govulncheck@latest
      - name: run govulncheck
        run: govulncheck ./...

  artifact:
    name: upload binary (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    needs: test
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'
          cache: true
      - run: go build -o railcore-${{ runner.os }}-${{ runner.arch }} ./cmd/railcore
      - uses: actions/upload-artifact@v4
        with:
          name: railcore-${{ runner.os }}-${{ runner.arch }}
          path: railcore-${{ runner.os }}-${{ runner.arch }}*
```

- [ ] **Step 3: Verify locally before pushing**

Run:
```bash
make vet
make test-race
```

Expected: both succeed.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml .golangci.yml
git commit -m "ci: GitHub Actions matrix across linux/macos/windows + lint + vuln"
```

---

## Task 17: Acceptance — real Cursor → real OpenAI (manual, Linux)

**Files:** none modified; this is a manual verification step.

- [ ] **Step 1: Build a release binary**

Run:
```bash
make build
```

Expected: `./railcore` exists.

- [ ] **Step 2: Start the proxy in one terminal**

Run:
```bash
./railcore proxy --port 9443
```

Expected: log line `railcore proxy listening addr=127.0.0.1:9443 ca_path=...`.

- [ ] **Step 3: Install the CA into the trust store (per the printed manual instructions if auto-install did not complete)**

The proxy's startup log will print either "trust-store auto-install did not complete" with manual instructions, or nothing (auto succeeded). If manual: run the printed commands now.

- [ ] **Step 4: Point Cursor at the proxy**

In Cursor settings, set `http.proxy` to `http://localhost:9443` and restart Cursor.

- [ ] **Step 5: Trigger a real OpenAI completion in Cursor**

Ask Cursor for any code completion that uses OpenAI.

- [ ] **Step 6: Verify in the proxy log**

Look at the proxy's stderr. You should see at least one log line for the request: `host=api.openai.com status=200` (or similar). The completion in Cursor must succeed.

- [ ] **Step 7: Document the result**

In the PR description (or directly in `docs/superpowers/specs/2026-05-15-core-forward-proxy-design.md` under a new "Acceptance Result" section), record: date, Cursor version, OpenAI model used, observed log line, outcome (pass/fail). If it fails, file an issue describing the failure mode — this is where cert-pinning bugs will surface.

- [ ] **Step 8: Commit the acceptance record**

```bash
git add docs/superpowers/specs/2026-05-15-core-forward-proxy-design.md
git commit -m "docs(spec): record acceptance test result"
```

---

## Self-Review Notes

After completing all tasks above:

1. **Spec coverage:**
   - §3 Repo layout → Tasks 1, 2, 4, 6, 8, 9, 14
   - §4.1 CA → Tasks 4, 5
   - §4.2 Trust → Tasks 6, 7
   - §4.3 Pipeline → Tasks 2, 3
   - §4.4 Proxy → Tasks 8, 9, 10, 11, 12, 13
   - §5 Data flow → Task 9 (TLS interception), Task 14 (wiring)
   - §6 Error handling: port-in-use (Task 14), CONNECT non-:443 (Task 8), body cap (Task 11), pipeline panic (Task 3), Block (Task 10), upstream unreachable (Task 9 `forwardH1` 502 path)
   - §7.1 Unit tests → Tasks 3, 4, 5, 6, 8–13
   - §7.2 Integration tests → Tasks 9, 10, 11, 12, 13, 15
   - §7.3 Acceptance → Task 17
   - §8 CI → Task 16
   - §9 Done definition → Tasks 16 (CI green), 17 (acceptance)

2. **Placeholders:** none. Task 8 contains a temporary stub `handleIntercepted` in `server.go` that returns "not implemented"; Task 9 Step 2 explicitly removes it when the real implementation lands in `intercept.go`.

3. **Type consistency:**
   - `Decision` values referenced consistently as `Continue`/`Block`/`Modify`.
   - `Config` field names match across all task code: `Addr`, `CA`, `Pipeline`, `MaxBodyBytes`, `Logger`, `UpstreamTLS`, `UpstreamResolver`.
   - `CA.RootCert()` and `CA.RootPath()` consistently used.
   - `Chain.NewChain()` returns `*Chain`; `Chain.Register(Stage)`; `Chain.Run(ctx, *RequestCtx)`.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-15-core-forward-proxy.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
