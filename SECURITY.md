# Security Policy

Runveil intercepts HTTPS traffic and installs a local Certificate
Authority. Bugs in this code path can result in the loss of TLS
guarantees for the user's browser, AI tools, and shell. We take
reports seriously.

## Reporting a Vulnerability

**Please do not file public GitHub issues for security vulnerabilities.**

Report privately through GitHub's [Private Vulnerability
Reporting](https://github.com/dawnn07/runveil/security/advisories/new)
(repository **Security** tab → **Report a vulnerability**). This keeps
the report confidential until a fix is coordinated.

Include:

- A description of the issue
- A minimal reproduction (config, commands, expected vs. actual behaviour)
- Your assessment of severity, if you have one
- Your name / handle, if you'd like to be credited

You'll get an acknowledgement within 72 hours. Disclosure timing will
be coordinated with you; the default is 90 days from the initial report
to public disclosure, but we'll move faster if a fix is available
sooner.

## Scope

In scope:

- The forward proxy (`runveil proxy`) — request handling, TLS
  interception, certificate generation, header forwarding
- The CA setup (`runveil init`) — key generation, file permissions,
  OS trust store installation
- The detector stages (`internal/stage/*`) — secret scanning, path
  scanning, anything that processes request bodies
- The policy engine — rule evaluation, action enforcement, hot-reload
- The audit log writer — record format, file permissions, disk handling

Out of scope:

- The `--upstream-override` and `--upstream-ca` flags. These are
  test-only knobs that let you redirect upstream traffic to a stub.
  They are documented as dangerous, logged at WARN level when used,
  refuse to start without both flags together, and are intended only
  for the project's own integration tests. Using them in production is
  your problem, not ours.
- Third-party tools that talk to runveil (Claude Code, Cursor, etc.).
  Report issues there to those projects.
- Vulnerabilities that require the attacker to already have write
  access to the user's home directory or root on the machine. (At that
  point the attacker can install any CA they want — runveil is not
  the weak link.)

## What a fix typically looks like

A CVE-worthy bug in runveil is patched, a release tagged, and the
release notes call out the issue. Older releases are not patched —
upgrade to the fixed version.

If you're packaging runveil for a distro, please subscribe to the
GitHub releases feed.
