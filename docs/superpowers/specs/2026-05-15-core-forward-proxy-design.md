# Sub-project #1 — Core Forward Proxy + TLS Interception

**Status:** Design approved, pending spec review
**Date:** 2026-05-15
**Sub-project of:** Railcore MVP (see `part1.md`, `part2.md` in repo root)

---

## 1. Purpose and Scope

Build the foundation layer of Railcore: a localhost forward HTTPS proxy that intercepts TLS, runs an extensible request pipeline, and forwards traffic to upstream AI provider APIs unmodified. This is the substrate every later sub-project routes through.

**In scope:**
- Local Certificate Authority generation and per-host leaf-cert minting
- OS trust-store installation library (hybrid: auto-install, fall back to printing manual instructions) on Linux, macOS, Windows
- Forward HTTPS proxy listening on `localhost:9443` (configurable) that handles `CONNECT` tunnels, intercepts TLS, and forwards HTTP/1.1 and HTTP/2 requests
- A `Stage` / `Chain` pipeline framework with one registered stage (`forwardStage`, a no-op `Continue`)
- Stream-safe response forwarding (SSE, HTTP/2 streaming)
- GitHub Actions CI building and testing on all three platforms

**Out of scope (handled by later sub-projects):**
- Request parsers for OpenAI / Anthropic JSON formats (sub-project #2)
- Any detector — secret, PII, path (sub-projects #2, #4)
- YAML policy engine (#3)
- CLI commands beyond a thin `cmd/railcore` entrypoint that starts the proxy (#5)
- Daemon management, graceful shutdown, signal handling (#5)
- Structured audit logging (#6)
- Per-tool protocol quirks beyond standard HTTPS (#7)
- HTTP/3 / QUIC interception
- Release packaging (Homebrew, apt, winget, signed releases)

---

## 2. Decisions Locked in During Brainstorming

| Decision | Choice | Rationale |
|---|---|---|
| Target platforms (this cycle) | Linux + macOS + Windows | User requirement; bake cross-platform constraints into the architecture from day one rather than retrofit. |
| Trust-store install strategy | Hybrid: attempt auto-install, fall back to printing exact manual commands | Best UX when privileges allow; never leaves user stuck. |
| Pipeline framework | Build framework + `Stage` interface + dispatch chain. Only register a no-op `forwardStage`. | Locks in the extension contract without forcing every stage's payload to be designed before its sub-project. |
| Acceptance criterion | Real Cursor → OpenAI on Linux + CI build/test on all three platforms + `curl --proxy` integration tests | Validates the core against a real tool where iteration is fast; CI catches Mac/Windows regressions without requiring user to own those machines. |
| Proxy implementation | Custom forward proxy on stdlib `net/http` — no `goproxy`, no `martian` | Security product: minimise audit/supply-chain surface; cert-pinning and HTTP/2 streaming are flagged as critical risks and need full control. |

---

## 3. Repo Layout

Single Go module. Everything private under `internal/` for this cycle; promote to public packages only when an external consumer materialises.

```
railcore/
├── go.mod                                 # module railcore
├── go.sum
├── cmd/
│   └── railcore/                          # thin binary entrypoint
│       └── main.go
├── internal/
│   ├── proxy/                             # forward proxy server
│   │   ├── server.go                      # listen, accept, CONNECT handling
│   │   ├── intercept.go                   # TLS interception + leaf cert plumbing
│   │   ├── upstream.go                    # dial + splice to origin
│   │   └── server_test.go
│   ├── pipeline/                          # stage framework (the contract)
│   │   ├── stage.go                       # Stage interface + RequestCtx
│   │   ├── chain.go                       # composition / dispatch
│   │   └── chain_test.go
│   ├── ca/                                # local CA + leaf minting
│   │   ├── ca.go                          # generate root, persist to disk
│   │   ├── leaf.go                        # per-host leaf signing
│   │   └── ca_test.go
│   └── trust/                             # OS trust-store installation
│       ├── trust.go                       # platform-agnostic API
│       ├── trust_linux.go                 # update-ca-certificates / NSS
│       ├── trust_darwin.go                # security add-trusted-cert
│       ├── trust_windows.go               # certutil -addstore
│       └── trust_test.go
├── test/
│   └── integration/                       # curl-through-proxy tests
│       └── passthrough_test.go
├── .github/
│   └── workflows/
│       └── ci.yml
├── LICENSE                                # Apache 2.0
└── README.md
```

Package dependency graph (all dependencies point downward):

```
cmd/railcore
   └── internal/proxy
          ├── internal/pipeline   (leaf, no deps inside this repo)
          ├── internal/ca         (leaf)
          └── internal/trust      (leaf)
```

`internal/pipeline` is the contract sub-projects #2–6 will import to register stages. It must remain a leaf — no imports of `proxy`, `ca`, or `trust`.

---

## 4. Components

### 4.1 `internal/ca` — Local Certificate Authority

Generates and persists a single root CA. Mints short-lived per-host leaf certificates on demand.

**API (public surface within the module):**

```go
type CA struct { /* root cert + key + leaf cache */ }

// GenerateOrLoad creates a fresh root if one is not present at dir,
// otherwise loads the existing one. dir defaults to ~/.railcore/ca/.
func GenerateOrLoad(dir string) (*CA, error)

// MintLeaf returns a tls.Certificate for the given host, signed by the
// root CA. Cached in-memory after first call per host.
func (c *CA) MintLeaf(host string) (*tls.Certificate, error)

// Path to the root cert on disk (for trust-store install).
func (c *CA) RootPath() string
```

**Implementation notes:**
- Root: RSA 4096, 10-year validity, `CN=Railcore Local CA`, marked as CA basic constraint.
- Leaf: ECDSA P-256, 7-day validity, `SubjectAltName = host`, signed by the root.
- Key files written with `0600`; cert files `0644`. Directory `0700`.
- Cache keyed by host; concurrent `MintLeaf` calls for the same host return the same cert (lock around cache).
- Stdlib `crypto/*` only. No third-party crypto.

### 4.2 `internal/trust` — OS Trust-Store Installation

Platform-agnostic API with build-tagged per-OS implementations.

```go
type Installer interface {
    Install(caPath string) error
    Uninstall(caPath string) error
    Status(caPath string) (installed bool, method string, err error)
}

func New() Installer    // returns the right platform impl

// ErrNeedsManual is returned when auto-install fails or is unsupported.
// The error message contains the exact CLI command(s) the user can run.
var ErrNeedsManual = errors.New("trust store requires manual install")
```

**Per-platform behaviour:**

| OS | Auto path | Fallback (per-user) | Manual instructions printed if both fail |
|---|---|---|---|
| Linux | `cp` to `/usr/local/share/ca-certificates/railcore.crt` + `update-ca-certificates` | NSS DB: `certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n railcore -i <path>` | both commands |
| macOS | `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <path>` | `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db <path>` | login-keychain command |
| Windows | `certutil -addstore -f Root <path>` (admin) | `Import-Certificate -FilePath <path> -CertStoreLocation Cert:\CurrentUser\Root` | PowerShell command |

`Status()` lets startup code verify the cert is actually trusted before logging a warning.

### 4.3 `internal/pipeline` — Stage Framework

The contract that all later sub-projects will use to insert behaviour into request processing.

```go
type RequestCtx struct {
    Req       *http.Request
    Host      string                       // upstream host from CONNECT
    Metadata  map[string]any               // stages annotate freely
    StartedAt time.Time
}

type Decision int

const (
    Continue Decision = iota               // pass to next stage
    Block                                  // halt; proxy returns 403 to client
    Modify                                 // request mutated; pass to next stage
)

type Stage interface {
    Name() string
    Process(ctx context.Context, rc *RequestCtx) (Decision, error)
}

type Chain struct { /* slice of stages */ }

func (c *Chain) Register(s Stage)
func (c *Chain) Run(ctx context.Context, rc *RequestCtx) (Decision, error)
```

**Semantics:**
- Stages run in registration order.
- `Block` halts the chain and the proxy returns 403 without dialling upstream.
- `Continue` and `Modify` both pass control to the next stage. `Modify` is a hint for future stages that an earlier stage mutated `rc.Req`; the proxy itself treats it identically to `Continue` in this cycle (later sub-projects may add audit-log distinctions).
- A stage that panics is recovered by `Chain.Run`; the panic is logged at ERROR and the decision degrades to `Continue` (fail-open in this cycle).
- A stage that returns a non-nil error is logged at WARN; the decision is treated as `Continue`.

For this sub-project, exactly one stage is registered: a `forwardStage` that returns `Continue` unconditionally. It exists to prove the wiring works end-to-end.

### 4.4 `internal/proxy` — Forward HTTPS Proxy Server

**Listener:** binds `localhost:PORT` (default `9443`, overridable via `RAILCORE_PORT` env var).

**Request lifecycle:**
1. Accept TCP from the client; parse the leading line.
2. If it is `CONNECT host:443 HTTP/1.1`, proceed; otherwise return `400`.
3. Respond `HTTP/1.1 200 Connection Established`.
4. Mint a leaf via `internal/ca`; perform the TLS server handshake with the client, advertising ALPN `["h2", "http/1.1"]`.
5. Read the inner HTTP request off the intercepted connection.
6. Build `pipeline.RequestCtx`, call `chain.Run`.
7. On `Continue` / `Modify`: dial TLS to the real upstream **using the system trust store** (`tls.Config{}` with no `RootCAs` set), write the request, then `io.Copy` the response back, flushing after each write (HTTP/1.1) or via native HTTP/2 stream framing.
8. On `Block`: return `HTTP/1.1 403 Forbidden` with a small JSON body. (The body schema is sub-project #2's concern.)

**Hard invariants:**
- The upstream TLS dial **must not** include Railcore's CA in its `RootCAs`. Doing so would let Railcore MITM itself.
- The response body is **never** buffered. SSE depends on incremental flushing.
- The pipeline runs after the request body is fully read but **before** any bytes leave the proxy headed upstream — this is what makes block / redact possible in later sub-projects.
- Per-request body size is capped at **32 MiB**. Requests exceeding the cap get `413` before the pipeline runs.
- One goroutine per connection (stdlib `http.Server` default). No custom scheduler.

---

## 5. Request Data Flow (Cursor → OpenAI Example)

```
 1. Cursor reads HTTPS_PROXY=http://localhost:9443
 2. Cursor opens TCP to localhost:9443
 3. Cursor sends:  CONNECT api.openai.com:443 HTTP/1.1
                   Host: api.openai.com:443
    ────────────────────────────────────────────────────
 4. proxy.server accepts, parses CONNECT, extracts host
 5. proxy.server replies:  HTTP/1.1 200 Connection Established
 6. proxy.intercept calls ca.MintLeaf("api.openai.com") → leaf cert
 7. proxy.intercept performs TLS server handshake with Cursor,
    advertising ALPN ["h2","http/1.1"], using the minted leaf
    ────────────────────────────────────────────────────
 8. Cursor sends real HTTP request through the intercepted TLS:
        POST /v1/chat/completions HTTP/2
        Authorization: Bearer sk-...
        Content-Type: application/json
        <body>
 9. proxy.server parses the request into *http.Request
    ────────────────────────────────────────────────────
10. proxy.server builds RequestCtx{Req, Host: "api.openai.com", ...}
11. pipeline.Chain.Run(ctx, rc)
        └─ forwardStage.Process() → Continue
    ────────────────────────────────────────────────────
12. proxy.upstream dials TLS to api.openai.com:443
        (using the system's real root store, NOT railcore's CA)
13. proxy.upstream writes the request upstream
14. Upstream responds; proxy reads response headers,
    writes them to the client immediately
15. For each chunk read from upstream: write to client, then Flush()
16. When upstream closes (or client disconnects), tear down both sides
```

---

## 6. Error Handling

Posture for this cycle:
- **Fail-open on internal errors per request.** Passthrough is the only behaviour; there is nothing to fail closed *toward* yet. Later sub-projects (#3) will introduce explicit fail-closed paths for policy violations.
- **Loud at startup, quiet in steady state.** Misconfiguration crashes with a clear message at process start; per-request errors are logged but never crash the server.

| Failure | When | Response |
|---|---|---|
| Port in use | Startup | Crash: `port 9443 in use; set RAILCORE_PORT or stop other process` |
| CA missing/corrupted | Startup | Run `trust.Uninstall()` for the old cert, then regenerate. Log warning. |
| CA not trusted by system (best-effort check via `trust.Status`) | Startup | Log warning + print install instructions; proxy still starts (user may have skipped install intentionally). |
| CONNECT to non-:443 port | Per-request | `400 Bad Request`. v1 intercepts standard HTTPS only. |
| Leaf mint failure | Per-request | Close the client connection. Log at WARN. |
| Upstream TLS handshake fails | Per-request | `502 Bad Gateway` with JSON body `{"error":"upstream unreachable","host":...,"detail":...}`. Log at WARN. |
| Request body > 32 MiB | Per-request | `413 Payload Too Large`. |
| Pipeline stage panics | Per-request | `recover()` in `Chain.Run`. Log stack at ERROR. Decision → `Continue` (fail-open). |
| Pipeline stage returns non-nil error | Per-request | Log at WARN. Decision treated as `Continue`. |
| Client disconnects mid-stream | Per-request | Close upstream. No log. |
| Upstream disconnects mid-stream | Per-request | Close client side cleanly. Log at INFO. |

**Logging:** stdlib `log/slog` only — no third-party logger. JSON to stderr. Per-request line at request completion containing `request_id` (uuid), `host`, `method`, `path`, `status`, `bytes_in`, `bytes_out`, `duration_ms`, `decision`. This is operational logging; the audit-log format is sub-project #6's problem.

**Explicitly deferred:** cert-pinning workarounds (discovered during acceptance testing, will drive scope of later sub-projects), graceful shutdown of in-flight requests (#5), retry logic (AI tools own this).

---

## 7. Testing Strategy

TDD discipline: every behaviour below has a failing test written before the code that satisfies it.

### 7.1 Unit tests

| Package | Critical tests |
|---|---|
| `internal/ca` | Generate writes files with correct perms (`0600` key, `0644` cert); reload produces identical cert; `MintLeaf` SAN matches host; leaf chains to root; cache returns same `*tls.Certificate` across calls for same host; `-race` clean under concurrent `MintLeaf`. |
| `internal/trust` | Build constraints route to the right impl; each `Install` returns `ErrNeedsManual` with a non-empty command string when it cannot auto-install. Actual trust-store mutation only runs in opt-in integration tests (see 7.3). |
| `internal/pipeline` | `Chain.Run` with zero stages → `Continue`. N stages called in order. `Block` halts chain. Panic recovered → `Continue`, logged. Error returned → `Continue`, logged. Concurrent `Run` invocations isolated (one `RequestCtx`'s annotations do not bleed into another). |
| `internal/proxy` | CONNECT to non-:443 → `400`. Oversized body → `413`. Pipeline `Block` → `403`, no upstream dial. Pipeline `Continue` → exactly one upstream dial. Response streaming flushes incrementally (fake upstream writes 3 chunks separated by sleeps; fake client verifies each chunk arrives before the next is written). |

### 7.2 In-process integration tests

Under `test/integration/`. Each test spins up:
- A fake upstream via `httptest.NewTLSServer`.
- The Railcore proxy on `localhost:0` (random port) configured to trust the fake upstream's cert in its upstream dial.
- A real `net/http.Client` using `http.ProxyURL(proxyURL)` and the Railcore CA in `RootCAs`.

Scenarios:
1. HTTP/1.1 GET passthrough.
2. HTTP/2 GET passthrough (ALPN negotiates `h2`).
3. POST with JSON body, byte-exact upstream.
4. SSE streaming: upstream sends 5 events with 50ms gaps; client receives each within 100ms of upstream send (proves no buffering).
5. Pipeline-registered always-Block stage: client gets `403`, upstream's request counter stays at `0`.
6. Pipeline-registered always-panic stage: client gets a successful response (fail-open).
7. 100 parallel requests: all succeed; `goleak` check at test end confirms no goroutine leaks.

### 7.3 Acceptance test — real Cursor → real OpenAI

Performed once, manually, on Linux:

1. `make build && sudo ./railcore-install-ca` (or follow the manual command path).
2. Start proxy: `./railcore proxy --port 9443`.
3. Configure Cursor with `http.proxy = http://localhost:9443`.
4. In Cursor, trigger a code completion that hits OpenAI.
5. Verify Railcore stderr shows one request line with `host=api.openai.com`, `status=200`, `decision=continue`.
6. Verify Cursor returned a usable completion.

If this passes, sub-project #1 is done.

### 7.4 Not in scope

- Real macOS / Windows trust-store install verification by hand. CI covers compile + `-race` unit tests on those OSes; in-CI integration tests exercise the real `security` / `certutil` calls. Manual real-tool acceptance on Mac/Windows is a follow-up, not a blocker.
- Performance/latency budget enforcement. A `go test -bench` benchmark is added but not gated. The < 50ms target is meaningful once real detection stages exist; gating it now would be premature.

---

## 8. CI

Single GitHub Actions workflow `.github/workflows/ci.yml`, on push and PR.

**Matrix:** `ubuntu-latest`, `macos-latest`, `windows-latest`. Go version pinned to `1.23`.

**Per-OS job steps:**

1. `actions/checkout@v4`
2. `actions/setup-go@v5` with module cache.
3. `go vet ./...`
4. `go build ./...` (proves all platforms compile, including build-tagged `trust_*.go`).
5. `go test -race -count=1 ./...` (unit + in-process integration tests).
6. Trust-store integration test, gated by `RAILCORE_INTEGRATION=1`: installs and uninstalls the CA on the runner. Cleanup step uninstalls on success or failure.
7. Upload binary as a CI artifact (`railcore-{os}-{arch}`). Not a release.

**Blocking merge:**
- All steps green on all three OSes.
- `golangci-lint` with `errcheck`, `gosimple`, `govet`, `staticcheck`, `unused` enabled. No style nitpickers.
- `gofmt -l . | wc -l == 0`.

**Advisory (non-blocking):**
- `govulncheck`. Failure produces a warning, not a red build, until a triage process exists.

**Deferred to other sub-projects / launch prep:**
- Release workflow (Homebrew, apt, winget, signed binaries) — sub-project #5 / launch.
- Code coverage thresholds — measured if cheap, but not gated this early.
- Dependabot configuration — add after first dependency is introduced.
- Container image — not applicable; Railcore is a local proxy.

---

## 9. Done Definition

Sub-project #1 is complete when:

1. All unit and in-process integration tests in §7.1 and §7.2 pass on all three platforms in CI.
2. CI is green on `ubuntu-latest`, `macos-latest`, `windows-latest`.
3. The Linux acceptance test in §7.3 passes by hand: Cursor configured to use Railcore as its HTTPS proxy successfully completes a real OpenAI request, and the request appears in Railcore's stderr log with `decision=continue`.
4. The design doc and implementation are committed to the repo. README is a placeholder (full README is launch-prep work).

When these four hold, sub-project #2 (request parsing + secret detection) can begin building on this foundation.

---

## 10. Acceptance Result (Task 17)

**Date:** 2026-05-17 (Linux, dev machine)

**Tools exercised:**

| Tool | Result | Notes |
|---|---|---|
| `curl --proxy --cacert` to `api.openai.com` | ✓ pass | HEAD / returned 421 as expected. Confirmed CONNECT + TLS interception + system-trust-store upstream dial all work. |
| Claude Code (via `HTTPS_PROXY` + `NODE_EXTRA_CA_CERTS`) | ✓ pass | End-to-end AI completion flowed through Railcore. Proxy log showed `host=api.anthropic.com decision=continue status=200`. |
| Antigravity (Google) | ✗ partial / blocked | Honors `HTTPS_PROXY` but bundled Google + Microsoft SDKs pin certificates on `oauth2.googleapis.com`, `lh3.googleusercontent.com`, `antigravity-unleash.goog`, `*.events.data.microsoft.com`, `*.exp-tas.com`. Auth bootstrap fails under MITM; Gemini API request is never attempted. |

**Implications:**

- Sub-project #1 meets its done definition: an AI coding tool successfully completes a real-world AI request through Railcore (Claude Code → Anthropic API).
- **Cert pinning is the #1 critical risk from [part1.md](../../../part1.md) §9.1, now confirmed in the wild on Antigravity.** Practical mitigation is a future "API-key proxy mode" or selective passthrough for pinned endpoints — out of scope for sub-project #1, but a known constraint for future product strategy.
- Cross-tool positioning is real: Cursor-class and Claude-Code-class tools work today; bundled-SDK tools like Antigravity require vendor cooperation or a different interception strategy.
