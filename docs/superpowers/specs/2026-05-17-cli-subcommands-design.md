# Sub-project #5 — CLI Subcommands

**Status:** Design approved, pending spec review
**Date:** 2026-05-17
**Sub-project of:** Railcore MVP (see `part1.md`, `part2.md` in repo root)
**Builds on:** [Sub-project #4](2026-05-17-path-based-rules-design.md) (path-based rules), which builds on #1-3.

---

## 1. Purpose and Scope

Give Railcore a developer-friendly CLI surface around the existing `proxy` subcommand. The current binary only knows `railcore proxy`; a first-time user has no `init` workflow, no diagnostic check, and no way to validate a policy file before restarting. This sub-project adds the missing pieces that turn a working proxy into a polished local tool.

**In scope:**

- `railcore init` — non-interactive first-run setup: generate the local CA, attempt OS trust-store install (with manual fallback), write an annotated starter `policy.yaml` if absent. `--force` overwrites an existing policy.
- `railcore proxy` — unchanged from sub-projects #1-4. Extracted from `main.go` into its own file as part of the layout refactor.
- `railcore status` — one-shot diagnostic report (read-only): CA path + exists, policy path + parses, proxy port + TCP-detect running. Always exits 0.
- `railcore test-policy <path>` — validate a YAML policy file via the existing loader. Exit 0 on success, 1 on validation error. Useful as a pre-commit hook.
- `railcore version` — print the embedded version string.
- Code layout refactor: subcommand-per-file under `cmd/railcore/`.

**Out of scope (deferred):**

- **`railcore start` / `railcore stop` + daemon mode.** Forking, PID files, signal handling are an OS-specific rabbit hole. Operators wanting background execution use `systemd`/`launchd`/`screen`/`nohup`.
- **`railcore logs` subcommand.** Requires a persistent audit log file — that's sub-project #6's territory.
- **Interactive prompts.** Decided in brainstorming: non-interactive default with `--force` escape hatch.
- **`--json` machine-readable output flag** for `status`. YAGNI for v1; add later if asked for.
- **Persistent `~/.railcore/config.yaml` for CLI defaults.** CLI flags + env vars from sub-projects #1-3 already suffice.
- **Shell completion files** (bash/zsh/fish). Easy follow-up if requested.
- **CA regeneration via `--force`.** Deliberately blocked — regenerating a trusted CA invalidates every trust-store entry pointing at the previous one. Users wanting a fresh start delete `~/.railcore/ca/` manually.

---

## 2. Decisions Locked in During Brainstorming

| Decision | Choice | Rationale |
|---|---|---|
| `init` interactivity | **Non-interactive by default; `--force` to overwrite policy.** | Idiomatic for dev tools. Scriptable (CI/dotfile installers). Prompts are annoying after the first run. |
| Starter `policy.yaml` content | **Annotated template** — active `default-warn` rule + commented-out examples for AWS keys, GitHub tokens, payments paths. | Self-teaching first-run UX. Users uncomment one line to see real behavior. |
| `status` depth | **Files + parse + TCP port check.** | "Is my proxy actually up?" is the #1 question. Runtime stats (request counts) would need a new admin endpoint — deferred. |
| Code organization | **Subcommand-per-file under `cmd/railcore/`.** | Files stay small + focused. Same package = shared helpers without exports. Standard Go convention for `cmd/` binaries. |
| Daemon mode | **Out of scope.** | Use `systemd`/`launchd`/`screen`/`nohup` for background execution. PID files + double-fork is its own design problem. |
| `logs` subcommand | **Out of scope.** | Audit log file exists only after sub-project #6. |

---

## 3. Code Layout

`main.go` becomes a thin dispatcher. Each subcommand gets its own file.

```
railcore/
├── cmd/
│   └── railcore/
│       ├── main.go             # MODIFY — dispatch + global usage + version const
│       ├── proxy.go            # NEW — extracted from main.go (existing proxy logic)
│       ├── init.go             # NEW — railcore init
│       ├── status.go           # NEW — railcore status
│       ├── test_policy.go      # NEW — railcore test-policy <path>
│       ├── version.go          # NEW — railcore version
│       └── helpers.go          # NEW — shared helpers: defaultPort, defaultDataDir
```

No new packages. No new dependencies. Everything stays in `package main` under `cmd/railcore/`.

### 3.1 `main.go` becomes a dispatcher

```go
package main

import (
	"fmt"
	"os"
)

// version is the binary version string. Hardcoded for now; can be set
// at build time via `-ldflags "-X main.version=$(git describe)"`.
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

func printUsage() { /* writes usage block to stderr */ }
```

### 3.2 Existing `proxy` code moves

Today's `main.go` contains the proxy subcommand inline. After this sub-project:

- `proxy.go` exports `runProxy(args []string)` containing flag parsing, CA load, trust install, policy resolution, chain registration, listener setup, signal handling.
- `helpers.go` holds `defaultPort()` and `defaultDataDir()` (shared by `init`, `proxy`, `status`).
- `resolvePolicy(...)` from sub-project #3 stays in `proxy.go` — it's only called during proxy startup.

### 3.3 Layout invariants

- Each subcommand file is < 150 LOC.
- All subcommand entry points are `func runXxx(args []string)` taking the post-subcommand args (so `os.Args[2:]`).
- No subcommand file imports another. All shared logic is in `helpers.go`.

---

## 4. Subcommand Specifications

### 4.1 `railcore init`

**Purpose:** Idempotent first-run setup.

**Flags:**

| Flag | Default | Meaning |
|---|---|---|
| `--data-dir PATH` | `~/.railcore` | Where the CA and policy live. |
| `--force` | `false` | Overwrite existing `policy.yaml` and re-install CA into trust store. **Does NOT regenerate the CA itself.** |

**Behavior, in order:**

1. Generate CA via `ca.GenerateOrLoad(<data-dir>/ca)`. Idempotent: if a CA exists, prints `CA already present at <path>`. `--force` does NOT regenerate the CA.
2. Install CA into OS trust store via `trust.New().Install(caPath)`. On success: `trust store: installed via <method>`. On `ErrNeedsManual`: print the manual install commands from `trust.ManualInstructions(caPath)`.
3. If `<data-dir>/policy.yaml` doesn't exist OR `--force` is set, write the starter template:

```yaml
version: 1

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
```

4. Print next-steps to stdout:

```
railcore is set up. Start the proxy with:
  railcore proxy
Then configure your AI tool to use http://localhost:9443 as its HTTPS proxy.
```

**Exit codes:** 0 on success (including the trust-install-needs-manual-fallback case). Non-zero only on hard failures (filesystem write error, CA generation panic).

### 4.2 `railcore proxy`

**Unchanged from sub-projects #1-4.** Lives in `proxy.go` after the layout refactor. All existing flags (`--port`, `--data-dir`, `--block-on-detect`, `--policy`) remain identical.

### 4.3 `railcore status`

**Purpose:** One-shot diagnostic. Read-only.

**Flags:**

| Flag | Default | Meaning |
|---|---|---|
| `--data-dir PATH` | `~/.railcore` | Where CA and policy live. |
| `--port N` | `9443` (or `$RAILCORE_PORT`) | Port to probe for a running proxy. |

**Output (plain text to stdout):**

```
railcore status

CA:
  path:        /home/dawn/.railcore/ca/ca.crt
  exists:      yes

Policy:
  path:        /home/dawn/.railcore/policy.yaml
  exists:      yes
  parses:      yes (1 rules)

Proxy:
  port:        9443
  running:     yes
```

Field-by-field:

- **CA:** `exists: yes/no`. If no, print `Run 'railcore init' first.` as a footer hint.
- **Policy:** `exists: yes/no`. If yes: also `parses: yes (N rules)` or `parses: no (<loader error>)`.
- **Proxy:** TCP dial to `127.0.0.1:<port>` with 200ms timeout. `running: yes` on successful handshake, `running: no` otherwise. We don't authenticate that it's our proxy — any listener counts.

**Exit codes:** 0 always. The status report itself never fails (it just reports state).

### 4.4 `railcore test-policy <path>`

**Purpose:** Validate a YAML policy file. Suitable for CI / pre-commit hooks.

**Args:** `<path>` is required. No default.

**Behavior:**

- Call `policy.LoadFromFile(path)`.
- On success: print `<path>: ok (N rules)` to stdout. Exit 0.
- On failure: print the loader's full error to stderr. Exit 1.

**Example:**

```
$ railcore test-policy ~/.railcore/policy.yaml
/home/dawn/.railcore/policy.yaml: ok (1 rules)

$ railcore test-policy /tmp/broken.yaml
policy: rule "block-aws": match.path cannot be combined with secret-finding conditions (pattern/severity) in this version
exit status 1
```

### 4.5 `railcore version`

```
$ railcore version
railcore 0.1.0
```

Aliases: `--version`, `-v`. All print the same single line. Exit 0.

### 4.6 Help & unknown commands

| Invocation | Behavior |
|---|---|
| `railcore` (no args) | Usage to stderr. Exit 2. |
| `railcore help` / `--help` / `-h` | Usage to stderr. Exit 0. |
| `railcore <unknown>` | `unknown subcommand: "<x>"` to stderr + usage. Exit 2. |
| `railcore <known> --help` | Subcommand-specific flag list via `flag.FlagSet`'s default. Exit 0 (since `flag.ExitOnError` prints usage and exits when given `--help`). |

---

## 5. Error Handling

CLI tools have a different posture from the proxy. Subcommands are one-shot and either succeed or fail loudly.

### 5.1 General principles

- **All user-facing errors go to stderr.** stdout is reserved for the requested output.
- **Exit codes are meaningful:**
  - `0` — success.
  - `1` — operation failed (test-policy invalid, init couldn't write file).
  - `2` — usage error (unknown subcommand, missing required arg, bad flag).
- **Error messages name the thing**, not just the operation. `policy file not found: /path/to/foo.yaml` (good) vs `read failed` (useless).

### 5.2 Per-subcommand failure modes

| Subcommand | Failure | Behavior |
|---|---|---|
| `init` | Data dir not writable | `init: cannot create <path>: <err>`. Exit 1. |
| `init` | CA generation panics | `init: CA generation failed: <err>`. Exit 1. |
| `init` | Policy exists without `--force` | `init: policy file exists at <path>; pass --force to overwrite (skipping)`. Continue with rest of init. Exit 0. |
| `init` | Trust-store install returns `ErrNeedsManual` | Print manual instructions. Exit 0 (graceful degradation). |
| `init` | Trust-store install returns any other error | Print error + manual instructions. Exit 0 (still graceful). |
| `status` | Data dir doesn't exist | Print `CA: exists: no` + hint `Run 'railcore init' first.` Exit 0. |
| `status` | Policy parses with errors | Print `parses: no (<error>)`. Exit 0. |
| `status` | TCP dial times out / fails | Print `running: no`. Exit 0. |
| `test-policy` | Missing file | `test-policy: <path>: file not found`. Exit 1. |
| `test-policy` | YAML / validation error | Loader error verbatim. Exit 1. |
| `test-policy` | Missing path arg | `flag.ExitOnError` → usage. Exit 2. |
| `version` | (never fails) | — |
| Top-level | Unknown subcommand | `unknown subcommand: "<x>"` + usage. Exit 2. |

### 5.3 Why trust-install failure is exit 0

`init`'s auto-install is best-effort. Returning non-zero would suggest "init failed" when actually the CA is generated, the policy is written, and the user just needs to run one extra command. Printing the manual instructions and exiting 0 keeps `init` idempotent and friendly to CI/dotfile scripts. The same posture as sub-project #1's proxy startup.

### 5.4 Why `--force` does NOT regenerate the CA

Regenerating a CA invalidates every trust-store entry pointing at the previous certificate. A user might have installed the CA system-wide, configured AI tools with it, etc. — regenerating silently would break all of that. If a user really wants to start over, they delete `~/.railcore/ca/` manually and re-run `init`. This is intentional friction.

---

## 6. Testing Strategy

CLI behavior is testable at the integration level — the binary IS the API. A new `test/integration/cli_test.go` file holds most tests; a couple of in-package unit tests cover pure helpers.

### 6.1 Integration tests — `test/integration/cli_test.go`

**Test harness:** `TestMain` builds the binary once into a temp file. Each test execs that binary with controlled args and an isolated `t.TempDir()` for `--data-dir`. Captures stdin/stdout/stderr and asserts content + exit code.

**`init`:**

- `TestCLI_Init_FreshDataDir` — empty dir → `init --data-dir <tmp>` creates `<tmp>/ca/ca.crt` and `<tmp>/policy.yaml`. stdout contains "Next steps". Exit 0.
- `TestCLI_Init_Idempotent` — run `init` twice; second time reports "CA already present", policy unchanged (checksum equal). Both exit 0.
- `TestCLI_Init_RefusesOverwriteWithoutForce` — pre-write custom `policy.yaml`. `init` does NOT touch it. stdout mentions "(skipping)".
- `TestCLI_Init_ForceOverwrites` — `init --force` overwrites pre-existing policy with the starter template.
- `TestCLI_Init_StarterPolicyParses` — after `init`, call `policy.LoadFromFile` from the test on the written file. Must succeed and produce exactly 1 rule (the `default-warn`).

**`status`:**

- `TestCLI_Status_NoDataDir` — fresh empty dir → `status --data-dir <tmp>` prints `CA: exists: no`. Exit 0.
- `TestCLI_Status_AfterInit` — `init` first, then `status`. Prints `CA: exists: yes`, `Policy: parses: yes (1 rules)`. Exit 0.
- `TestCLI_Status_PolicyParseError` — write a deliberately broken `policy.yaml`. `status` prints the loader error in the `parses:` line. Exit 0.
- `TestCLI_Status_ProxyRunningDetected` — bind a `net.Listener` on `127.0.0.1:0`, run `status --port <bound>`. Prints `running: yes`. Exit 0.
- `TestCLI_Status_ProxyNotRunning` — pick an unbound port. Prints `running: no`. Exit 0.

**`test-policy`:**

- `TestCLI_TestPolicy_Valid` — `init` first, then `test-policy <tmp>/policy.yaml`. stdout: `<path>: ok (1 rules)`. Exit 0.
- `TestCLI_TestPolicy_Invalid` — write a YAML with a typo'd action; `test-policy <path>` prints loader error to stderr, exits 1.
- `TestCLI_TestPolicy_MissingFile` — `/nonexistent.yaml` → `file not found` to stderr, exits 1.
- `TestCLI_TestPolicy_MissingArg` — no path arg → flag parser exits 2.

**`version`:**

- `TestCLI_Version` — `version`, `--version`, `-v` all print `railcore 0.1.0\n` and exit 0.

**Dispatch:**

- `TestCLI_UnknownSubcommand` — `railcore foo` → `unknown subcommand: "foo"` to stderr, exit 2.
- `TestCLI_NoArgs` — usage to stderr, exit 2.
- `TestCLI_Help` — `help` / `--help` / `-h` print usage, exit 0.

That's roughly 17 integration tests.

### 6.2 In-package unit tests

A couple of helpers benefit from direct testing without process exec:

- `cmd/railcore/init_test.go` — test `writeStarterPolicy(path string, force bool) error` directly. Verifies file content matches the expected template, perms are 0644, error if `(exists && !force)`.
- `cmd/railcore/status_test.go` — test `proxyRunning(addr string) bool` against an `httptest.NewServer` (returns true) and an unbound port (returns false).

### 6.3 Manual acceptance test

After all the above passes:

1. `make build` on a fresh machine.
2. `./railcore init` (no flags). Verify `~/.railcore/ca/ca.crt` and `~/.railcore/policy.yaml` exist.
3. `cat ~/.railcore/policy.yaml` — confirm annotated template.
4. `./railcore status` — confirm "CA: exists: yes, Policy: parses: yes (1 rules), Proxy: running: no".
5. `./railcore test-policy ~/.railcore/policy.yaml` — confirm `ok (1 rules)`.
6. Start `./railcore proxy` in another shell. Re-run `status` — confirm "Proxy: running: yes".
7. Edit `policy.yaml` to uncomment the `block-aws` example. Run `test-policy` — confirm still parses.

Record in §11.

### 6.4 What's NOT tested

- The proxy command's behavior — already covered by sub-projects #1-4 tests. We test only that `runProxy` is invoked when `os.Args[1] == "proxy"`.
- CA trust-store install — covered by sub-project #1's `RAILCORE_INTEGRATION=1` opt-in test.
- Policy loader correctness — covered by sub-project #3's loader tests. `test-policy` is just a thin wrapper.

---

## 7. Done Definition

Sub-project #5 is complete when:

1. All unit and integration tests in §6.1 and §6.2 pass on all three platforms in CI.
2. CI matrix stays green on `ubuntu-latest`, `macos-latest`, `windows-latest`.
3. The manual acceptance test in §6.3 passes on a real machine.
4. The design doc and implementation are committed to the repo.

When these four hold, sub-project #6 (audit logging) can add a `railcore logs` subcommand following the same per-file convention without restructuring `cmd/railcore/`.
