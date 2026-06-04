# Railcore

A local-first AI firewall for coding assistants. Railcore is a forward
HTTPS proxy that intercepts TLS to inspect what your AI tool sends to
Claude, OpenAI, and other LLM APIs — then applies policy (allow, warn,
block) before the request leaves your machine.

The goal is to give individual developers a place to put rules like:

- "Block any request that contains an AWS access key."
- "Warn me if a tool tries to read `**/.ssh/**` or `**/payments/**`."
- "Log every request my AI editor makes, so I can audit it later."

Everything runs locally. Railcore has no cloud dependency and no
telemetry. Audit records are written to a file on disk; that's it.

## Status

Alpha. The detector set, policy schema, and CLI flags can still change.
Used in production by the author; not yet recommended for production by
strangers.

## Install

Requires Go 1.25.

```sh
git clone https://github.com/dawnn07/railcore.git
cd railcore
go build ./cmd/railcore
```

A `railcore` binary appears in the repo root. Move it onto `$PATH` or
run it from there.

## First-time setup

```sh
./railcore init
```

This generates a local Certificate Authority under `~/.railcore/ca/`,
installs it into your OS trust store (best-effort — falls back to
printed manual instructions on platforms where it can't auto-install),
and writes a starter `policy.yaml` next to the CA.

## Run the proxy

```sh
./railcore proxy
```

Listens on `127.0.0.1:9443` by default. To send your AI tool through it:

```sh
export HTTPS_PROXY=http://127.0.0.1:9443
# then start Claude Code / Cursor / your SDK in that shell
```

For Node-based tools (Claude Code, Cursor):

```sh
export NODE_EXTRA_CA_CERTS=~/.railcore/ca/ca.crt
```

To see what's flowing through:

```sh
./railcore logs --follow
```

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
./railcore test-policy ~/.railcore/policy.yaml
```

Railcore hot-reloads the policy file — no proxy restart needed.

## Security model

**Railcore installs a local Certificate Authority on your machine** so
it can decrypt the HTTPS traffic flowing through it. This is the only
way to inspect TLS-protected request bodies. It's also the most
security-sensitive thing this tool does.

You should know:

- The CA's **private key is generated locally** (`~/.railcore/ca/ca.key`)
  and never leaves your machine. Railcore does not phone home.
- **Anyone with read access to that key can MITM any HTTPS site to your
  browser.** Treat it like an SSH private key. If your machine is
  multi-user, ensure `~/.railcore/` is mode `0700` (railcore does this
  by default — verify with `ls -la ~/.railcore`).
- The CA is trusted only by **your user's** trust store on this machine.
  It does not affect other users or other machines.
- The two flags `--upstream-override` and `--upstream-ca` are test-only
  knobs that let you redirect upstream traffic to a stub. They are
  documented as dangerous, logged at WARN level when used, and require
  both flags together. Don't use them in production.

To uninstall the CA from your trust store, see your OS's certificate
manager (the same place `railcore init` installed it).

## What's in the box

| Subcommand | What it does |
|---|---|
| `railcore init` | Generate CA, install trust, write starter policy. Idempotent. |
| `railcore proxy` | Run the forward HTTPS proxy. |
| `railcore status` | Show config + whether a proxy is currently running. |
| `railcore logs` | Tail the audit log. `--follow` for live. |
| `railcore test-policy` | Validate a policy file without starting the proxy. |
| `railcore version` | Print binary version. |

Run `railcore <command> --help` for flags.

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
for vulnerabilities — email the address listed there instead.

## License

Apache 2.0 — see [LICENSE](LICENSE).
