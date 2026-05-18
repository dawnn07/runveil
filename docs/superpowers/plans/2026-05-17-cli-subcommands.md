# CLI Subcommands Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add four developer-facing CLI subcommands (`init`, `status`, `test-policy`, `version`) to the `railcore` binary while preserving the existing `proxy` subcommand verbatim. Refactor `cmd/railcore/` to subcommand-per-file layout.

**Architecture:** Reorganize `cmd/railcore/main.go` into a thin dispatcher + per-subcommand files in the same package. New subcommands call existing APIs from `internal/ca/`, `internal/trust/`, and `internal/policy/` directly — no new internal packages, no new dependencies. CLI behavior is tested at the integration level by execing the built binary; pure helpers get in-package unit tests.

**Tech Stack:** Go 1.25 stdlib only (`flag`, `os`, `os/exec`, `net`, `time`). Existing internal packages (`internal/ca`, `internal/trust`, `internal/policy`) unchanged.

**Spec:** [`docs/superpowers/specs/2026-05-17-cli-subcommands-design.md`](../specs/2026-05-17-cli-subcommands-design.md)

---

## File Map

| File | Purpose |
|---|---|
| `cmd/railcore/main.go` | **Rewrite:** dispatch + global usage + version variable |
| `cmd/railcore/proxy.go` | **Create:** `runProxy(args []string)` (existing logic extracted from main.go) |
| `cmd/railcore/helpers.go` | **Create:** `defaultPort()`, `defaultDataDir()` (shared by `init`, `proxy`, `status`) |
| `cmd/railcore/init.go` | **Create:** `runInit(args []string)` + `writeStarterPolicy(path string, force bool) error` |
| `cmd/railcore/init_test.go` | **Create:** in-package unit tests for `writeStarterPolicy` |
| `cmd/railcore/status.go` | **Create:** `runStatus(args []string)` + `proxyRunning(addr string) bool` |
| `cmd/railcore/status_test.go` | **Create:** in-package unit test for `proxyRunning` |
| `cmd/railcore/test_policy.go` | **Create:** `runTestPolicy(args []string)` |
| `cmd/railcore/version.go` | **Create:** `runVersion()` |
| `test/integration/cli_test.go` | **Create:** integration tests via `os/exec` |

**Dependency direction:** unchanged. All new code is in `package main` under `cmd/railcore/`.

---

## Task 1: Refactor — extract proxy + helpers from main.go

**Files:**
- Modify (rewrite): `cmd/railcore/main.go`
- Create: `cmd/railcore/proxy.go`
- Create: `cmd/railcore/helpers.go`

This is a non-functional refactor. All existing tests must still pass with no observable behavior change.

- [ ] **Step 1: Read the current `cmd/railcore/main.go`**

Run:
```bash
cat cmd/railcore/main.go
```

Confirm the file contains the `proxy` subcommand inline plus `defaultPort()` and `defaultDataDir()` helpers. (If the file structure has drifted, adapt step 2 accordingly.)

- [ ] **Step 2: Create `cmd/railcore/helpers.go`**

```go
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

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
```

- [ ] **Step 3: Create `cmd/railcore/proxy.go`**

Move the existing proxy logic from `main.go` into a new file. The function signature is `func runProxy(args []string)`. Everything inside `main()` after the "proxy" subcommand match goes here, with `flag.NewFlagSet("proxy", flag.ExitOnError).Parse(args)` replacing the `fs.Parse(os.Args[2:])` call.

Create `cmd/railcore/proxy.go`:

```go
package main

import (
	"context"
	"errors"
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
	"railcore/internal/policy"
	"railcore/internal/proxy"
	"railcore/internal/stage/pathscan"
	"railcore/internal/stage/secretscan"
	"railcore/internal/trust"
)

func runProxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	port := fs.Int("port", defaultPort(), "TCP port to listen on (overrides RAILCORE_PORT)")
	dataDir := fs.String("data-dir", defaultDataDir(), "directory for CA + state")
	blockOnDetect := fs.Bool("block-on-detect", false, "return 403 on High-severity secret findings (default WARN only). Ignored when a policy file is in effect.")
	policyPath := fs.String("policy", "", "path to a YAML policy file (default: <data-dir>/policy.yaml if it exists)")
	_ = fs.Parse(args)

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	caInst, err := ca.GenerateOrLoad(filepath.Join(*dataDir, "ca"))
	if err != nil {
		logger.Error("ca init failed", "err", err.Error())
		os.Exit(1)
	}

	if err := trust.New().Install(caInst.RootPath()); err != nil {
		logger.Warn("trust-store auto-install did not complete",
			"err", err.Error(),
			"manual_steps", trust.ManualInstructions(caInst.RootPath()))
	}

	loadedPolicy, policyMode, resolvedPath := resolvePolicy(*policyPath, *dataDir, logger)

	effectiveBlock := *blockOnDetect || os.Getenv("RAILCORE_BLOCK_ON_DETECT") == "1"
	if loadedPolicy != nil && effectiveBlock {
		logger.Warn("--block-on-detect ignored because a policy file is in effect",
			"policy_path", resolvedPath)
	}

	chain := pipeline.NewChain().WithLogger(logger)
	chain.Register(pathscan.New(pathscan.Config{Policy: loadedPolicy}, logger))
	chain.Register(secretscan.New(secretscan.Config{
		BlockOnDetect: effectiveBlock,
		Policy:        loadedPolicy,
	}, logger))

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

	startupArgs := []any{
		"addr", addr,
		"ca_path", caInst.RootPath(),
		"policy_mode", policyMode,
		"block_on_detect", effectiveBlock,
	}
	if resolvedPath != "" {
		startupArgs = append(startupArgs, "policy_path", resolvedPath, "rules", len(loadedPolicy.Rules))
	}
	logger.Info("railcore proxy listening", startupArgs...)

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

func resolvePolicy(flagPath, dataDir string, logger *slog.Logger) (*policy.Policy, string, string) {
	if flagPath != "" {
		p, err := policy.LoadFromFile(flagPath)
		if err != nil {
			logger.Error("policy load failed (--policy)", "path", flagPath, "err", err.Error())
			os.Exit(1)
		}
		return p, "file", flagPath
	}

	defaultPath := filepath.Join(dataDir, "policy.yaml")
	if _, err := os.Stat(defaultPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "flag", ""
		}
		logger.Error("policy stat failed", "path", defaultPath, "err", err.Error())
		os.Exit(1)
	}

	p, err := policy.LoadFromFile(defaultPath)
	if err != nil {
		logger.Error("policy load failed (default path)", "path", defaultPath, "err", err.Error())
		os.Exit(1)
	}
	return p, "file", defaultPath
}
```

Note: this is the existing logic, moved verbatim from main.go. The imports list moves with it.

- [ ] **Step 4: Rewrite `cmd/railcore/main.go`**

Replace the file contents entirely:

```go
// Package main is the Railcore CLI entrypoint.
//
// Subcommands live in sibling files: proxy.go, init.go, status.go,
// test_policy.go, version.go. helpers.go holds shared utilities.
package main

import (
	"fmt"
	"os"
)

// version is the binary version string. May be overridden at build
// time via -ldflags "-X main.version=$(git describe)".
var version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		runInit(os.Args[2:])
	case "proxy":
		runProxy(os.Args[2:])
	case "status":
		runStatus(os.Args[2:])
	case "test-policy":
		runTestPolicy(os.Args[2:])
	case "version", "--version", "-v":
		runVersion()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %q\n\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `usage: railcore <command> [flags...]

Commands:
  init           First-run setup: generate CA, install trust, write starter policy.
  proxy          Start the forward HTTPS proxy (foreground).
  status         Show config + running-proxy state.
  test-policy    Validate a YAML policy file.
  version        Print binary version.

Run "railcore <command> --help" for command-specific flags.
`)
}
```

This file references `runInit`, `runStatus`, `runTestPolicy`, `runVersion` — these are stubbed in subsequent tasks. The file won't compile YET.

- [ ] **Step 5: Add stub functions to unblock compilation**

Create temporary stubs in their target files so `go build` succeeds before subsequent tasks add real implementations.

Create `cmd/railcore/init.go`:
```go
package main

import (
	"fmt"
	"os"
)

func runInit(args []string) {
	fmt.Fprintln(os.Stderr, "init: not implemented yet")
	os.Exit(1)
}
```

Create `cmd/railcore/status.go`:
```go
package main

import (
	"fmt"
	"os"
)

func runStatus(args []string) {
	fmt.Fprintln(os.Stderr, "status: not implemented yet")
	os.Exit(1)
}
```

Create `cmd/railcore/test_policy.go`:
```go
package main

import (
	"fmt"
	"os"
)

func runTestPolicy(args []string) {
	fmt.Fprintln(os.Stderr, "test-policy: not implemented yet")
	os.Exit(1)
}
```

Create `cmd/railcore/version.go`:
```go
package main

import "fmt"

func runVersion() {
	fmt.Printf("railcore %s\n", version)
}
```

- [ ] **Step 6: Build and run existing tests**

```bash
go build ./...
go test -race -count=1 ./...
go vet ./...
```

Expected: build succeeds; all existing 203 tests still pass (the proxy subcommand's behavior is unchanged); vet clean.

- [ ] **Step 7: Commit**

```bash
git add cmd/railcore/
git commit -m "refactor(cmd): extract proxy logic + helpers; add subcommand stubs"
```

---

## Task 2: Version subcommand

`runVersion` was already added as a stub in Task 1 and is actually functional. This task adds the integration test.

**Files:**
- (no file changes — `version.go` is already complete from Task 1)
- Create: `test/integration/cli_test.go` (new file with test harness + first test)

- [ ] **Step 1: Create the integration test harness**

Create `test/integration/cli_test.go`:

```go
// Integration tests for the railcore CLI. Builds the binary once into
// a temp directory at TestMain, then execs it with controlled args
// and an isolated --data-dir per test. Captures stdin/stdout/stderr.
package integration

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// railcoreBin holds the absolute path to the built railcore binary.
// Set by TestMain via go build; reused across tests.
var railcoreBin string

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "railcore-bin-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: MkdirTemp: %v\n", err)
		os.Exit(2)
	}
	defer os.RemoveAll(tmpDir)

	binName := "railcore"
	binPath := filepath.Join(tmpDir, binName)

	repoRoot := findRepoRootForCLITests()
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/railcore")
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: go build: %v\n%s", err, string(out))
		os.Exit(2)
	}
	railcoreBin = binPath
	os.Exit(m.Run())
}

func findRepoRootForCLITests() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	dir := wd
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "."
}

// runCLI execs the railcore binary with the given args and returns
// stdout, stderr, and the exit code. exitCode is -1 if the process
// could not be started.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(railcoreBin, args...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	stdout = stdoutBuf.String()
	stderr = stderrBuf.String()

	if err == nil {
		return stdout, stderr, 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return stdout, stderr, ee.ExitCode()
	}
	return stdout, stderr, -1
}

func TestCLI_Version(t *testing.T) {
	for _, alias := range []string{"version", "--version", "-v"} {
		t.Run(alias, func(t *testing.T) {
			stdout, stderr, code := runCLI(t, alias)
			if code != 0 {
				t.Errorf("exit code = %d, want 0; stderr=%q", code, stderr)
			}
			want := "railcore 0.1.0\n"
			if stdout != want {
				t.Errorf("stdout = %q, want %q", stdout, want)
			}
			if stderr != "" {
				t.Errorf("stderr should be empty, got %q", stderr)
			}
		})
	}
}
```

- [ ] **Step 2: Run the test**

```bash
go test -race -count=1 -run TestCLI_Version ./test/integration/...
```

Expected: PASS for all three aliases (`version`, `--version`, `-v`).

- [ ] **Step 3: Commit**

```bash
git add test/integration/cli_test.go
git commit -m "test(cli): integration harness + version subcommand"
```

---

## Task 3: Test-policy subcommand

**Files:**
- Modify (replace stub): `cmd/railcore/test_policy.go`
- Modify: `test/integration/cli_test.go` (append tests)

- [ ] **Step 1: Append failing tests**

Append to `test/integration/cli_test.go`. **Also add `"strings"` to the file's import list** — these new tests are the first to use `strings.Contains`.

```go

func TestCLI_TestPolicy_MissingArg(t *testing.T) {
	_, stderr, code := runCLI(t, "test-policy")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "test-policy") {
		t.Errorf("stderr should mention test-policy; got %q", stderr)
	}
}

func TestCLI_TestPolicy_MissingFile(t *testing.T) {
	_, stderr, code := runCLI(t, "test-policy", "/nonexistent/path/to/x.yaml")
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "/nonexistent/path/to/x.yaml") {
		t.Errorf("stderr should mention the path; got %q", stderr)
	}
}

func TestCLI_TestPolicy_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
rules:
  - name: r
    match: {all: true}
    action: warn
`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	stdout, stderr, code := runCLI(t, "test-policy", path)
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, path) || !strings.Contains(stdout, "ok") || !strings.Contains(stdout, "1 rules") {
		t.Errorf("stdout = %q, want path + ok + 1 rules", stdout)
	}
}

func TestCLI_TestPolicy_Invalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	// Combining path with pattern is rejected by the loader.
	if err := os.WriteFile(path, []byte(`
version: 1
rules:
  - name: bad
    match: {path: "**/foo/**", pattern: aws_*}
    action: block
`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	_, stderr, code := runCLI(t, "test-policy", path)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "path") {
		t.Errorf("stderr should mention 'path' from the loader error; got %q", stderr)
	}
}
```

- [ ] **Step 2: Confirm tests fail**

```bash
go test -race -count=1 -run TestCLI_TestPolicy ./test/integration/...
```

Expected: failures — the stub returns "not implemented yet" and exits 1 regardless of args.

- [ ] **Step 3: Replace `cmd/railcore/test_policy.go`**

```go
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"railcore/internal/policy"
)

func runTestPolicy(args []string) {
	fs := flag.NewFlagSet("test-policy", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "usage: railcore test-policy <path>\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "test-policy: <path> argument is required")
		fs.Usage()
		os.Exit(2)
	}
	path := fs.Arg(0)

	p, err := policy.LoadFromFile(path)
	if err != nil {
		// Distinguish "not found" for a cleaner message.
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "test-policy: %s: file not found\n", path)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	fmt.Printf("%s: ok (%d rules)\n", path, len(p.Rules))
}
```

- [ ] **Step 4: Run the tests and confirm pass**

```bash
go test -race -count=1 -run TestCLI_TestPolicy ./test/integration/...
```

Expected: all 4 test-policy tests pass.

- [ ] **Step 5: Commit**

```bash
git add cmd/railcore/test_policy.go test/integration/cli_test.go
git commit -m "feat(cli): test-policy subcommand wrapping policy loader"
```

---

## Task 4: Init subcommand

**Files:**
- Modify (replace stub): `cmd/railcore/init.go`
- Create: `cmd/railcore/init_test.go`
- Modify: `test/integration/cli_test.go` (append tests)

- [ ] **Step 1: Append integration tests**

Append to `test/integration/cli_test.go`:

```go

func TestCLI_Init_FreshDataDir(t *testing.T) {
	dir := t.TempDir()
	stdout, stderr, code := runCLI(t, "init", "--data-dir", dir)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca", "ca.crt")); err != nil {
		t.Errorf("CA cert not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "policy.yaml")); err != nil {
		t.Errorf("policy.yaml not created: %v", err)
	}
	if !strings.Contains(stdout, "railcore proxy") {
		t.Errorf("stdout should include next-steps hint; got %q", stdout)
	}
}

func TestCLI_Init_Idempotent(t *testing.T) {
	dir := t.TempDir()
	if _, _, code := runCLI(t, "init", "--data-dir", dir); code != 0 {
		t.Fatalf("first init failed")
	}
	// Capture first policy file content.
	first, err := os.ReadFile(filepath.Join(dir, "policy.yaml"))
	if err != nil {
		t.Fatalf("read policy after first init: %v", err)
	}
	// Second init: should not error, policy file unchanged.
	stdout, stderr, code := runCLI(t, "init", "--data-dir", dir)
	if code != 0 {
		t.Fatalf("second init: exit %d; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "already") {
		t.Errorf("stdout should mention CA already present; got %q", stdout)
	}
	second, err := os.ReadFile(filepath.Join(dir, "policy.yaml"))
	if err != nil {
		t.Fatalf("read policy after second init: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("policy file changed between idempotent inits")
	}
}

func TestCLI_Init_RefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	// Pre-write a custom policy.
	custom := "version: 1\nrules:\n  - name: custom\n    match: {all: true}\n    action: block\n"
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(custom), 0o600); err != nil {
		t.Fatalf("write custom policy: %v", err)
	}
	stdout, _, code := runCLI(t, "init", "--data-dir", dir)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "skipping") {
		t.Errorf("stdout should mention skipping the existing policy; got %q", stdout)
	}
	got, _ := os.ReadFile(policyPath)
	if string(got) != custom {
		t.Errorf("existing policy was overwritten:\nwant: %s\ngot:  %s", custom, string(got))
	}
}

func TestCLI_Init_ForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	custom := "version: 1\nrules:\n  - name: custom\n    match: {all: true}\n    action: block\n"
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(custom), 0o600); err != nil {
		t.Fatalf("write custom policy: %v", err)
	}
	_, stderr, code := runCLI(t, "init", "--data-dir", dir, "--force")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	got, _ := os.ReadFile(policyPath)
	if string(got) == custom {
		t.Errorf("policy was NOT overwritten despite --force")
	}
	if !strings.Contains(string(got), "default-warn") {
		t.Errorf("policy should be the starter template; got %s", string(got))
	}
}
```

- [ ] **Step 2: Confirm tests fail**

```bash
go test -race -count=1 -run TestCLI_Init ./test/integration/...
```

Expected: failures — init stub returns "not implemented".

- [ ] **Step 3: Replace `cmd/railcore/init.go`**

```go
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"railcore/internal/ca"
	"railcore/internal/trust"
)

// starterPolicyTemplate is written to <data-dir>/policy.yaml by init
// when no policy file is present. Includes one active rule and several
// commented-out examples that illustrate the schema.
const starterPolicyTemplate = `version: 1

rules:
  # Warn on every finding. Edit this file to customize what railcore does
  # with detected secrets and tool-use file paths.
  - name: default-warn
    match: {all: true}
    action: warn

  # --- Examples (uncomment to enable) -----------------------------------

  # Block AWS, GitHub, and Stripe keys.
  # - name: block-cloud-keys
  #   match: {pattern: aws_*}
  #   action: block
  # - name: block-github-tokens
  #   match: {pattern: github_*}
  #   action: block

  # Block agent file access to sensitive paths.
  # - name: block-payments
  #   match: {path: "**/payments/**"}
  #   action: block
  # - name: block-aws-config
  #   match: {path: "**/.aws/**"}
  #   action: block
`

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "directory for CA + state")
	force := fs.Bool("force", false, "overwrite existing policy.yaml and re-install CA trust (does NOT regenerate the CA)")
	_ = fs.Parse(args)

	// Step 1: CA — idempotent.
	caDir := filepath.Join(*dataDir, "ca")
	caExists := caCertExists(caDir)
	caInst, err := ca.GenerateOrLoad(caDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: CA setup failed: %v\n", err)
		os.Exit(1)
	}
	if caExists {
		fmt.Printf("CA: already present at %s\n", caInst.RootPath())
	} else {
		fmt.Printf("CA: generated at %s\n", caInst.RootPath())
	}

	// Step 2: trust store install (best-effort).
	installer := trust.New()
	if err := installer.Install(caInst.RootPath()); err != nil {
		if errors.Is(err, trust.ErrNeedsManual) {
			fmt.Printf("trust store: manual install required. Run:\n\n%s\n",
				trust.ManualInstructions(caInst.RootPath()))
		} else {
			fmt.Printf("trust store: install failed: %v\nYou can run manually:\n\n%s\n",
				err, trust.ManualInstructions(caInst.RootPath()))
		}
	} else {
		fmt.Println("trust store: installed")
	}

	// Step 3: starter policy.
	policyPath := filepath.Join(*dataDir, "policy.yaml")
	if err := writeStarterPolicy(policyPath, *force); err != nil {
		fmt.Fprintf(os.Stderr, "init: write policy: %v\n", err)
		os.Exit(1)
	}

	// Step 4: next-steps summary.
	fmt.Print(`
railcore is set up. Start the proxy with:
  railcore proxy
Then configure your AI tool to use http://localhost:9443 as its HTTPS proxy.
`)
}

// writeStarterPolicy creates or overwrites the starter policy.yaml.
// When the file exists and force is false, prints a "skipping" notice
// and returns nil — the caller treats this as success.
func writeStarterPolicy(path string, force bool) error {
	if _, err := os.Stat(path); err == nil {
		if !force {
			fmt.Printf("policy: %s already exists; pass --force to overwrite (skipping)\n", path)
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(starterPolicyTemplate), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Printf("policy: wrote starter at %s\n", path)
	return nil
}

// caCertExists reports whether ca.crt is already present in caDir.
func caCertExists(caDir string) bool {
	_, err := os.Stat(filepath.Join(caDir, "ca.crt"))
	return err == nil
}
```

- [ ] **Step 4: Create unit test for `writeStarterPolicy`**

Create `cmd/railcore/init_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteStarterPolicy_FreshFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := writeStarterPolicy(path, false); err != nil {
		t.Fatalf("writeStarterPolicy: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), "default-warn") {
		t.Errorf("starter policy missing default-warn rule; got %s", string(data))
	}
	info, _ := os.Stat(path)
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Errorf("perms = %o, want 0644", mode)
	}
}

func TestWriteStarterPolicy_ExistingFileWithoutForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	original := []byte("custom content")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := writeStarterPolicy(path, false); err != nil {
		t.Errorf("writeStarterPolicy returned error: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(original) {
		t.Errorf("file was overwritten without --force; got %q", string(got))
	}
}

func TestWriteStarterPolicy_ExistingFileWithForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	original := []byte("custom content")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := writeStarterPolicy(path, true); err != nil {
		t.Errorf("writeStarterPolicy with force: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) == string(original) {
		t.Errorf("file was not overwritten despite --force")
	}
	if !strings.Contains(string(got), "default-warn") {
		t.Errorf("overwritten content should be the starter template")
	}
}
```

- [ ] **Step 5: Run all init tests**

```bash
go test -race -count=1 -run "TestWriteStarterPolicy|TestCLI_Init" ./cmd/railcore/... ./test/integration/...
```

Expected: all unit + integration tests pass.

- [ ] **Step 6: Verify starter policy actually parses via the real loader**

Add this test to the END of `test/integration/cli_test.go`:

```go

func TestCLI_Init_StarterPolicyParses(t *testing.T) {
	dir := t.TempDir()
	if _, _, code := runCLI(t, "init", "--data-dir", dir); code != 0 {
		t.Fatalf("init failed")
	}
	// Run test-policy on the written file to confirm it's a valid policy.
	stdout, stderr, code := runCLI(t, "test-policy", filepath.Join(dir, "policy.yaml"))
	if code != 0 {
		t.Fatalf("test-policy on starter: exit %d, stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "ok") || !strings.Contains(stdout, "1 rules") {
		t.Errorf("stdout = %q, want 'ok (1 rules)'", stdout)
	}
}
```

Run:

```bash
go test -race -count=1 -run TestCLI_Init_StarterPolicyParses ./test/integration/...
```

Expected: PASS.

- [ ] **Step 7: Run the full test suite to ensure no regressions**

```bash
go test -race -count=1 ./...
go vet ./...
```

Expected: all green.

- [ ] **Step 8: Commit**

```bash
git add cmd/railcore/init.go cmd/railcore/init_test.go test/integration/cli_test.go
git commit -m "feat(cli): init subcommand with idempotent CA + starter policy"
```

---

## Task 5: Status subcommand

**Files:**
- Modify (replace stub): `cmd/railcore/status.go`
- Create: `cmd/railcore/status_test.go`
- Modify: `test/integration/cli_test.go` (append tests)

- [ ] **Step 1: Append integration tests**

Append to `test/integration/cli_test.go`:

```go

func TestCLI_Status_NoDataDir(t *testing.T) {
	dir := t.TempDir()
	stdout, _, code := runCLI(t, "status", "--data-dir", dir)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "exists:      no") {
		t.Errorf("stdout should report CA not present; got %q", stdout)
	}
}

func TestCLI_Status_AfterInit(t *testing.T) {
	dir := t.TempDir()
	if _, _, code := runCLI(t, "init", "--data-dir", dir); code != 0 {
		t.Fatalf("init failed")
	}
	stdout, _, code := runCLI(t, "status", "--data-dir", dir)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	for _, want := range []string{"CA:", "exists:      yes", "Policy:", "parses:      yes", "Proxy:", "running:"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q; got:\n%s", want, stdout)
		}
	}
}

func TestCLI_Status_PolicyParseError(t *testing.T) {
	dir := t.TempDir()
	// Run init first to set up CA.
	if _, _, code := runCLI(t, "init", "--data-dir", dir); code != 0 {
		t.Fatalf("init failed")
	}
	// Overwrite with a broken policy.
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte("not: valid: yaml: :"), 0o600); err != nil {
		t.Fatalf("write broken policy: %v", err)
	}
	stdout, _, code := runCLI(t, "status", "--data-dir", dir)
	if code != 0 {
		t.Errorf("exit code = %d, want 0 (status is informational)", code)
	}
	if !strings.Contains(stdout, "parses:      no") {
		t.Errorf("stdout should report parses: no; got %q", stdout)
	}
}

func TestCLI_Status_ProxyRunningDetected(t *testing.T) {
	// Bind a TCP listener and pass its port to status.
	ln, err := listenOnRandomPort()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	dir := t.TempDir()
	stdout, _, code := runCLI(t, "status", "--data-dir", dir, "--port", fmt.Sprintf("%d", port))
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "running:     yes") {
		t.Errorf("stdout should report running: yes; got %q", stdout)
	}
}

func TestCLI_Status_ProxyNotRunning(t *testing.T) {
	dir := t.TempDir()
	// Pick an unused port by binding briefly then releasing.
	ln, err := listenOnRandomPort()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	stdout, _, code := runCLI(t, "status", "--data-dir", dir, "--port", fmt.Sprintf("%d", port))
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "running:     no") {
		t.Errorf("stdout should report running: no; got %q", stdout)
	}
}

// listenOnRandomPort binds 127.0.0.1:0 and returns the listener.
func listenOnRandomPort() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}
```

Add `"net"` and `"fmt"` to the test file's imports if not already present.

- [ ] **Step 2: Confirm tests fail**

```bash
go test -race -count=1 -run TestCLI_Status ./test/integration/...
```

Expected: status stub fails most assertions.

- [ ] **Step 3: Replace `cmd/railcore/status.go`**

```go
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"railcore/internal/policy"
)

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "directory for CA + state")
	port := fs.Int("port", defaultPort(), "TCP port to probe for a running proxy")
	_ = fs.Parse(args)

	caPath := filepath.Join(*dataDir, "ca", "ca.crt")
	caExists := fileExists(caPath)

	policyPath := filepath.Join(*dataDir, "policy.yaml")
	policyExists := fileExists(policyPath)
	policyParses, policyMsg, ruleCount := checkPolicy(policyPath, policyExists)

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	running := proxyRunning(addr)

	fmt.Println("railcore status")
	fmt.Println()
	fmt.Println("CA:")
	fmt.Printf("  path:        %s\n", caPath)
	fmt.Printf("  exists:      %s\n", yesNo(caExists))
	fmt.Println()
	fmt.Println("Policy:")
	fmt.Printf("  path:        %s\n", policyPath)
	fmt.Printf("  exists:      %s\n", yesNo(policyExists))
	if policyExists {
		if policyParses {
			fmt.Printf("  parses:      yes (%d rules)\n", ruleCount)
		} else {
			fmt.Printf("  parses:      no (%s)\n", policyMsg)
		}
	}
	fmt.Println()
	fmt.Println("Proxy:")
	fmt.Printf("  port:        %d\n", *port)
	fmt.Printf("  running:     %s\n", yesNo(running))

	if !caExists {
		fmt.Println()
		fmt.Println("Run 'railcore init' first.")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func checkPolicy(path string, exists bool) (parses bool, errMsg string, ruleCount int) {
	if !exists {
		return false, "", 0
	}
	p, err := policy.LoadFromFile(path)
	if err != nil {
		return false, err.Error(), 0
	}
	return true, "", len(p.Rules)
}

// proxyRunning reports whether a TCP listener is accepting connections
// at addr. 200ms timeout. Any successful handshake counts.
func proxyRunning(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
```

- [ ] **Step 4: Create unit test for `proxyRunning`**

Create `cmd/railcore/status_test.go`:

```go
package main

import (
	"net"
	"testing"
)

func TestProxyRunning_Live(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	if !proxyRunning(ln.Addr().String()) {
		t.Errorf("proxyRunning should return true for a bound listener")
	}
}

func TestProxyRunning_Dead(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // immediately release

	if proxyRunning(addr) {
		t.Errorf("proxyRunning should return false for an unbound address")
	}
}
```

- [ ] **Step 5: Run all status tests**

```bash
go test -race -count=1 -run "TestProxyRunning|TestCLI_Status" ./cmd/railcore/... ./test/integration/...
```

Expected: all pass.

- [ ] **Step 6: Full test suite**

```bash
go test -race -count=1 ./...
go vet ./...
```

Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add cmd/railcore/status.go cmd/railcore/status_test.go test/integration/cli_test.go
git commit -m "feat(cli): status subcommand with files + parse + TCP port check"
```

---

## Task 6: Dispatch + help/unknown subcommand integration tests

**Files:**
- Modify: `test/integration/cli_test.go` (append)

- [ ] **Step 1: Append the remaining dispatch tests**

```go

func TestCLI_UnknownSubcommand(t *testing.T) {
	_, stderr, code := runCLI(t, "this-is-not-a-real-command")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "unknown subcommand") {
		t.Errorf("stderr should mention 'unknown subcommand'; got %q", stderr)
	}
	if !strings.Contains(stderr, "this-is-not-a-real-command") {
		t.Errorf("stderr should echo the bad subcommand; got %q", stderr)
	}
}

func TestCLI_NoArgs(t *testing.T) {
	_, stderr, code := runCLI(t /* no args */)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "usage:") {
		t.Errorf("stderr should contain usage; got %q", stderr)
	}
}

func TestCLI_Help(t *testing.T) {
	for _, alias := range []string{"help", "--help", "-h"} {
		t.Run(alias, func(t *testing.T) {
			_, stderr, code := runCLI(t, alias)
			if code != 0 {
				t.Errorf("exit code = %d, want 0", code)
			}
			if !strings.Contains(stderr, "Commands:") {
				t.Errorf("stderr should contain 'Commands:'; got %q", stderr)
			}
		})
	}
}
```

- [ ] **Step 2: Run the new tests**

```bash
go test -race -count=1 -run "TestCLI_UnknownSubcommand|TestCLI_NoArgs|TestCLI_Help" ./test/integration/...
```

Expected: all pass against the existing `printUsage` and dispatch code from Task 1.

- [ ] **Step 3: Run the full test suite for confidence**

```bash
go test -race -count=1 ./...
go vet ./...
gofmt -l .
```

Expected: all green; vet clean; no gofmt diffs.

- [ ] **Step 4: Commit**

```bash
git add test/integration/cli_test.go
git commit -m "test(cli): dispatch tests for unknown subcommand, help, no-args"
```

---

## Task 7: Manual acceptance test

**Files:** none modified during the test itself; result recorded in spec at end.

- [ ] **Step 1: Build**

```bash
make build
```

- [ ] **Step 2: Run `railcore init`**

```bash
./railcore init
```

Verify stdout includes:
- A CA line (either "generated at" or "already present at" ~/.railcore/ca/ca.crt).
- A trust-store line (either "installed" or the manual-install commands).
- A policy line (either "wrote starter" or "already exists; ... (skipping)").
- The next-steps block with "railcore proxy".

- [ ] **Step 3: Inspect the starter policy**

```bash
cat ~/.railcore/policy.yaml
```

Verify it contains `default-warn` rule + commented examples.

- [ ] **Step 4: Run `railcore status` (proxy not running)**

```bash
./railcore status
```

Expected output includes:
```
CA:
  ...
  exists:      yes
Policy:
  ...
  exists:      yes
  parses:      yes (1 rules)
Proxy:
  port:        9443
  running:     no
```

- [ ] **Step 5: Run `railcore test-policy ~/.railcore/policy.yaml`**

Expected: `/home/dawn/.railcore/policy.yaml: ok (1 rules)`. Exit code 0.

- [ ] **Step 6: Start the proxy in another terminal**

```bash
./railcore proxy
```

Wait for the "railcore proxy listening" log line.

- [ ] **Step 7: Re-run `railcore status`**

In the original terminal:

```bash
./railcore status
```

Expected: `running:     yes`.

- [ ] **Step 8: Edit policy and re-test**

```bash
sed -i 's/# - name: block-cloud-keys/- name: block-cloud-keys/' ~/.railcore/policy.yaml
sed -i 's/#   match: {pattern: aws_\*}/  match: {pattern: aws_*}/' ~/.railcore/policy.yaml
sed -i 's/#   action: block/  action: block/' ~/.railcore/policy.yaml
./railcore test-policy ~/.railcore/policy.yaml
```

Expected: `ok (2 rules)` or `ok (N rules)` reflecting the additional active rule.

Revert the edits afterward (or just `./railcore init --force` to restore the starter).

- [ ] **Step 9: Stop the proxy and record the result**

Stop the proxy with Ctrl-C in its terminal. Append §11 to the spec doc:

```markdown

---

## 11. Acceptance Result

**Date:** YYYY-MM-DD (fill in)

- `railcore init` on a fresh machine: CA generated, trust install attempted (manual fallback printed when needed), starter policy.yaml written. ✓
- `railcore init` idempotent on re-run: prints "already present" + "skipping". ✓
- `railcore status` reports CA + policy + proxy state correctly before and after starting the proxy. ✓
- `railcore test-policy` validates the starter policy successfully. ✓
- Editing policy.yaml to uncomment an example rule and re-running `test-policy` reports the new rule count. ✓

**Status:** Pass. Sub-project #5 done definition §7 satisfied.
```

- [ ] **Step 10: Commit**

```bash
git add docs/superpowers/specs/2026-05-17-cli-subcommands-design.md
git commit -m "docs(spec): record sub-project #5 acceptance result"
```

---

## Self-Review Notes

After all tasks:

1. **Spec coverage:**
   - §3 Code layout → Task 1.
   - §4.1 `init` → Task 4.
   - §4.2 `proxy` (extracted unchanged) → Task 1.
   - §4.3 `status` → Task 5.
   - §4.4 `test-policy` → Task 3.
   - §4.5 `version` → Task 2.
   - §4.6 Help & unknown commands → Tasks 1 (dispatch + printUsage) and 6 (tests).
   - §5 Error handling → all tasks (assertions check exit codes + stderr content).
   - §6.1 Integration tests → Tasks 2-6.
   - §6.2 In-package unit tests → Tasks 4 (writeStarterPolicy) and 5 (proxyRunning).
   - §6.3 Manual acceptance → Task 7.
   - §7 Done definition → Tasks 1-6 (test passing) + Task 7 (manual acceptance).

2. **Placeholders:** none. Each step has complete code or exact commands.

3. **Type consistency:**
   - `runInit`, `runProxy`, `runStatus`, `runTestPolicy`, `runVersion` — all functions in `package main`, all use signature `func(args []string)` (except `runVersion` which takes no args). Consistent across `main.go` dispatch and per-subcommand files.
   - `defaultPort()` and `defaultDataDir()` — defined in `helpers.go`, used by `init`, `proxy`, `status`. Same package, no exports needed.
   - `version` var is `0.1.0` literal in `main.go`. `runVersion()` references `version`. Consistent.
   - `writeStarterPolicy(path string, force bool) error` — same signature in `init.go` (implementation) and `init_test.go` (test).
   - `proxyRunning(addr string) bool` — same signature in `status.go` and `status_test.go`.
   - The starter policy template is a single `const starterPolicyTemplate = ...` in `init.go` — referenced once during write. No duplication.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-17-cli-subcommands.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
