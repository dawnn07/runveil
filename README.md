# Runveil

A local-first AI firewall for coding assistants. Runveil is a forward
HTTPS proxy that intercepts TLS to inspect what your AI tool sends to
Claude, OpenAI, and other LLM APIs — then applies policy (allow, warn,
block) before the request leaves your machine.

The goal is to give individual developers a place to put rules like:

- "Block any request that contains an AWS access key."
- "Warn me if a tool tries to read `**/.ssh/**` or `**/payments/**`."
- "Log every request my AI editor makes, so I can audit it later."

Everything runs locally. Runveil has no cloud dependency and no
telemetry. Audit records are written to a file on disk; that's it.

## Status

Alpha. The detector set, policy schema, and CLI flags can still change.
Used in production by the author; not yet recommended for production by
strangers.

## Install

### Prebuilt binary (recommended)

Download the archive for your platform from the
[latest release](https://github.com/dawnn07/runveil/releases/latest),
extract it, and move the `runveil` binary onto your `$PATH`:

```sh
# example: Linux x86_64
tar xzf runveil_*_linux_amd64.tar.gz
sudo mv runveil /usr/local/bin/
```

Builds are published for Linux, macOS, and Windows (amd64 + arm64).
Each release also ships a `SHA256SUMS` file you can verify against.

### From source

Requires Go 1.25.

```sh
git clone https://github.com/dawnn07/runveil.git
cd runveil
go build ./cmd/runveil
```

A `runveil` binary appears in the repo root. Move it onto `$PATH` or
run it from there.

## First-time setup

```sh
./runveil init
```

This generates a local Certificate Authority under `~/.runveil/ca/`,
installs it into your OS trust store (best-effort — falls back to
printed manual instructions on platforms where it can't auto-install),
and writes a starter `policy.yaml` next to the CA.

## Run the proxy

```sh
./runveil proxy
```

Listens on `127.0.0.1:9443` by default. To send your AI tool through it:

```sh
export HTTPS_PROXY=http://127.0.0.1:9443
# then start Claude Code / Cursor / your SDK in that shell
```

For Node-based tools (Claude Code, Cursor):

```sh
export NODE_EXTRA_CA_CERTS=~/.runveil/ca/ca.crt
```

To see what's flowing through:

```sh
./runveil logs --follow
```

## Always-on (run in the background)

Instead of starting `runveil proxy` by hand each session, install it as a
background service that starts on login and restarts on failure:

```sh
runveil service install
```

This registers a user service (systemd on Linux, launchd on macOS) and
prints two `export` lines. Add them to your shell profile once:

```sh
export HTTPS_PROXY=http://127.0.0.1:9443
export NODE_EXTRA_CA_CERTS=~/.runveil/ca/ca.crt
```

After that, any tool you launch from a fresh shell — `claude`, `cursor`,
your own scripts — flows through runveil automatically. Remove it with:

```sh
runveil service uninstall
```

Note: setting `HTTPS_PROXY` routes *all* HTTPS traffic in that shell
through the proxy, not just your AI tool. The service auto-restarts, but
if you stop it, unset those vars too.

## Writing policy

The starter policy file looks like this:

```yaml
version: 1
rules:
  - name: default-warn
    match: {all: true}
    action: warn
```

Each rule has a `match` clause and an `action`. Rules are evaluated in
order; the first match wins. Actions are `allow`, `warn`, or `block`.

A few useful matchers:

```yaml
rules:
  # Block detected secrets (AWS keys, GitHub tokens, Stripe keys, etc.)
  - name: block-cloud-keys
    match: {pattern: aws_*}
    action: block

  # Block AI tools from reading sensitive files
  - name: block-payments-code
    match: {path: "**/payments/**"}
    action: block

  # Warn on everything else (so it shows up in the audit log)
  - name: catch-all
    match: {all: true}
    action: warn
```

`match.pattern` matches built-in detector names. `match.path` matches
file paths that the agent's tool-use is touching.

After editing, validate:

```sh
./runveil test-policy ~/.runveil/policy.yaml
```

Runveil hot-reloads the policy file — no proxy restart needed.

## Security model

**Runveil installs a local Certificate Authority on your machine** so
it can decrypt the HTTPS traffic flowing through it. This is the only
way to inspect TLS-protected request bodies. It's also the most
security-sensitive thing this tool does.

You should know:

- The CA's **private key is generated locally** (`~/.runveil/ca/ca.key`)
  and never leaves your machine. Runveil does not phone home.
- **Anyone with read access to that key can MITM any HTTPS site to your
  browser.** Treat it like an SSH private key. If your machine is
  multi-user, ensure `~/.runveil/` is mode `0700` (runveil does this
  by default — verify with `ls -la ~/.runveil`).
- The CA is trusted only by **your user's** trust store on this machine.
  It does not affect other users or other machines.
- The two flags `--upstream-override` and `--upstream-ca` are test-only
  knobs that let you redirect upstream traffic to a stub. They are
  documented as dangerous, logged at WARN level when used, and require
  both flags together. Don't use them in production.

To uninstall the CA from your trust store, see your OS's certificate
manager (the same place `runveil init` installed it).

## What's in the box

| Subcommand | What it does |
|---|---|
| `runveil init` | Generate CA, install trust, write starter policy. Idempotent. |
| `runveil proxy` | Run the forward HTTPS proxy. |
| `runveil service` | Install/uninstall the proxy as an always-on background service. |
| `runveil status` | Show config + whether a proxy is currently running. |
| `runveil logs` | Tail the audit log. `--follow` for live. |
| `runveil test-policy` | Validate a policy file without starting the proxy. |
| `runveil version` | Print binary version. |

Run `runveil <command> --help` for flags.

## Detectors

Built-in detectors include:

- **secret-scan** — AWS, GCP, Azure, GitHub, Stripe, Slack, generic
  high-entropy strings
- **path-scan** — file paths the agent is attempting to read/write,
  matched against glob patterns

Detector results are surfaced to policy via `match.pattern`. To add a
detector, see `internal/stage/` and existing implementations as
references.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and PRs welcome.

## Security disclosure

See [SECURITY.md](SECURITY.md). Please **do not** file public issues
for vulnerabilities — report them privately through GitHub's Security
tab (**Report a vulnerability**), as described there.

## License

Apache 2.0 — see [LICENSE](LICENSE).
