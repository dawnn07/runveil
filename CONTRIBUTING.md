# Contributing to Runveil

Thank you for considering a contribution. Runveil is a small project
with a security-sensitive surface area — the bar is "your patch makes
the tool clearly better without making it less safe."

## Before you start

For non-trivial changes, open an issue first to discuss the approach.
This saves both of us from a PR that has to be redone. Trivial
changes (typos, small bug fixes, documentation) — go straight to PR.

## Build & test

```sh
git clone https://github.com/dawnn07/runveil.git
cd runveil
go build ./cmd/runveil
go test ./... -race
```

The `-race` flag is mandatory — there's a lot of concurrent work in
the proxy path and we don't merge PRs whose tests fail under it.

For tests that drive the proxy end-to-end:

```sh
go test ./test/integration/... -v
```

These spawn a real `runveil` binary as a subprocess. Slow (10–30s) but
catch a lot.

## Code style

Follow standard Go style. We run `golangci-lint` in CI (config:
`.golangci.yml`). Run it locally before pushing:

```sh
golangci-lint run
```

Some specifics:

- Prefer the standard library. New direct dependencies need a real
  justification.
- Errors are wrapped with `fmt.Errorf("doing X: %w", err)`. Don't lose
  the cause.
- No naked `panic` in non-test code. The proxy stays up.
- Logging is via `slog`. No `fmt.Println` for runtime messages.
- Comments explain *why*, not *what*. Don't restate the code.

## Commit style

We follow [Conventional Commits](https://www.conventionalcommits.org/).
Types we use: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`.

Examples:

```
feat(proxy): support HTTP/2 upstream
fix(audit): close log file on graceful shutdown
test(policy): cover glob-path matching edge cases
```

Keep commits focused. A PR can have multiple commits if they're
logically separable — but each commit should build and pass tests on
its own.

## Security-sensitive areas

If your PR touches any of these, expect close scrutiny:

- CA generation / installation (`internal/ca`, `internal/trust`)
- TLS handshake handling in the proxy (`internal/proxy`)
- Audit log writer (`internal/audit`)
- Policy evaluation (`internal/policy`)

For these, please include tests that demonstrate the new behaviour
and that any existing behaviour you preserved is still preserved.

If you're adding a new detector, please include test data with realistic
positives and negatives. Detectors that produce too many false positives
get reverted.

## What we won't merge

- Code without tests (unless it's docs / config)
- Anything that silently weakens the security model (e.g. broader file
  permissions, weaker defaults, fewer warnings)
- Features that require runveil to phone home or send telemetry
- New CLI flags whose purpose is "make it work for my specific setup"
  — those should be config file options, environment variables, or
  upstream changes to the thing that's not working

## Reporting bugs

Use GitHub Issues for non-security bugs. Include:

- Your OS + Go version
- The `runveil version` output
- A minimal reproduction
- What you expected vs. what you got

For security issues, see [SECURITY.md](SECURITY.md).
