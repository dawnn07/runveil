# Policy guide

A **policy** tells Runveil what to do with each AI request it inspects:
let it through, warn, strip the sensitive parts, or block it. This page
documents the full policy format, every match condition and action, the
complete list of built-in detectors, and ready-to-use examples.

---

## What a policy does

For every request that Runveil can inspect, it produces zero or more
**findings** (a detected secret, or a sensitive file read) and then asks
the policy what to do. The policy is a small YAML file of ordered
**rules**; the first rule that matches a finding decides the action.

Runveil only inspects the prompt content of **recognised AI endpoints**:

| Vendor | Endpoints inspected |
| --- | --- |
| OpenAI | `api.openai.com/v1/chat/completions`, `/v1/responses` |
| Anthropic | `api.anthropic.com/v1/messages` |

Requests to any other host still pass through the proxy and are audited,
but their bodies are **not** scanned, so no policy rule fires on them.

---

## Where a policy lives

Runveil loads its policy from one of two sources:

**Local file** — pass `--policy <path>`:

```bash
runveil proxy --policy ./runveil-policy.yaml
```

If `--policy` is omitted, Runveil looks for `<data-dir>/policy.yaml`
(default data dir `~/.runveil`). With no policy at all, Runveil runs in
**warn-only** mode (it logs findings but never blocks).

**Control plane (central distribution)** — pass `--policy-url`:

```bash
runveil proxy \
  --policy-url https://control-plane.example.com/v1/policy \
  --policy-url-auth-header Authorization
```

The agent fetches the policy assigned to its org and re-polls every
`--policy-url-interval` (default `30s`). The auth token comes from
enrollment (`RUNVEIL_DEVICE_TOKEN`) or `RUNVEIL_POLICY_TOKEN`.

**Hot reload:** a local `--policy` file is watched and re-applied on
change; a `--policy-url` is re-polled. You do not need to restart the
proxy to change rules.

> A policy served by the control plane is the *same* YAML described here —
> the control plane only distributes the bytes; the agent validates and
> enforces them.

---

## How evaluation works

* Rules are tried **top to bottom; the first match wins.**
* If **no** rule matches a finding, the default action is **`warn`**.
* A request can produce several findings; each is decided independently.
  If any finding resolves to `block`, the whole request is blocked (403).
* There are **two kinds of finding**, and which conditions can match them
  differs:
  * **Secret findings** — a secret detected in the prompt. Matched by
    `pattern` and/or `severity`.
  * **File-path events** — an AI tool (e.g. Claude Code's `Read`) touching
    a file path. Matched by `path`.
  * A rule with only `pattern`/`severity` is **skipped** for path events;
    a rule with only `path` is skipped for secret findings; `all: true`
    matches both.

---

## Policy file format

```yaml
version: 1                 # required, must be 1
rules:                     # required, at least one rule
  - name: block-aws-keys   # required, unique within the file
    match:                 # required, at least one condition
      severity: high
    action: block          # required: allow | block | warn | redact
    note: "optional human note"
```

Validation is strict: an unknown field, a missing `version`, an empty
`rules` list, a duplicate `name`, an empty `match`, or an invalid
`action` makes the whole policy fail to load (and, in control-plane mode,
the agent keeps the last good policy).

---

## Match conditions

A `match` block must contain **at least one** of these:

| Condition | Matches | Example |
| --- | --- | --- |
| `severity` | A secret finding of this severity: `high`, `medium`, or `low`. | `severity: high` |
| `pattern` | A secret finding whose **detector name** matches this glob (see the detector list below). Globs the *name*, not the secret value. | `pattern: aws_*` |
| `all` | Everything — every secret finding and every path event. | `all: true` |
| `path` | A file-path event whose path matches this `**` doublestar glob. | `path: "**/.env"` |

**Combination rules:**

* `all: true` cannot be combined with any other condition.
* `path` cannot be combined with `pattern` or `severity` (path events and
  secret findings are different event kinds).
* `pattern` and `severity` **can** be combined (both must match).

```yaml
# pattern + severity together: only High-severity AWS findings
- name: aws-high
  match: { pattern: aws_*, severity: high }
  action: block
```

---

## Actions

| Action | Effect | Forwarded upstream? |
| --- | --- | --- |
| `allow` | Suppress the finding — treat the request as clean for this match. | Yes |
| `warn` | Record the finding (audit) but take no other action. **This is the default** when no rule matches. | Yes |
| `redact` | **Mask the matched secret** in the request body, then send the masked request. | Yes (masked) |
| `block` | Return **HTTP 403** to the client. The request is **never sent** upstream. | No |

### Choosing `block` vs `redact`

`block` returns a 403 *before* forwarding — great for discrete calls
(scripts, CI, a one-shot `curl`). But **conversational tools resend their
whole history on every turn** (e.g. Claude Code). Once a secret is in the
transcript, every following request re-includes it and is blocked again,
wedging the session until you clear history.

For interactive AI tools, prefer **`redact`** (the tool keeps working and
the secret never leaves the machine) or `warn`. Reserve `block` for
non-conversational flows.

---

## Detector reference

Every secret detector Runveil ships with. Use the **Name** column as the
`pattern` value (globs like `slack_*` or `private_key_*` are supported).

### AWS

| Name | Severity | Catches |
| --- | --- | --- |
| `aws_access_key_id` | High | AWS access key ID (`AKIA…`) |
| `aws_secret_access_key` | High | AWS secret access key |
| `aws_session_token` | High | AWS session token |

### GitHub

| Name | Severity | Catches |
| --- | --- | --- |
| `github_pat_classic` | High | Classic personal access token (`ghp_…`) |
| `github_pat_fine_grained` | High | Fine-grained PAT (`github_pat_…`) |
| `github_oauth_token` | High | OAuth token (`gho_…`) |
| `github_app_token` | High | App user/server token (`ghu_…` / `ghs_…`) |

### GitLab

| Name | Severity | Catches |
| --- | --- | --- |
| `gitlab_pat` | High | Personal access token (`glpat-…`) |

### Stripe

| Name | Severity | Catches |
| --- | --- | --- |
| `stripe_secret_live` | High | Live secret key (`sk_live_…`) |
| `stripe_restricted_live` | High | Live restricted key (`rk_live_…`) |

### OpenAI / Anthropic

| Name | Severity | Catches |
| --- | --- | --- |
| `openai_api_key` | High | OpenAI API key (`sk-…` / `sk-proj-…`) |
| `anthropic_api_key` | High | Anthropic API key (`sk-ant-…`) |

### Google

| Name | Severity | Catches |
| --- | --- | --- |
| `google_api_key` | High | Google API key (`AIza…`) |
| `google_oauth_client_secret` | High | OAuth client secret (`GOCSPX-…`) |
| `google_service_account_json` | High | Service-account JSON (with `private_key`) |

### Slack

| Name | Severity | Catches |
| --- | --- | --- |
| `slack_bot_token` | High | Bot token (`xoxb-…`) |
| `slack_user_token` | High | User token (`xoxp-…`) |
| `slack_app_token` | High | App-level token (`xapp-…`) |
| `slack_webhook_url` | Medium | Incoming webhook URL |

### Discord

| Name | Severity | Catches |
| --- | --- | --- |
| `discord_bot_token` | High | Bot token |
| `discord_webhook_url` | Medium | Webhook URL |

### Package registries

| Name | Severity | Catches |
| --- | --- | --- |
| `npm_token` | High | npm access token (`npm_…`) |
| `pypi_token` | High | PyPI upload token (`pypi-…`) |

### Private keys

| Name | Severity | Catches |
| --- | --- | --- |
| `private_key_rsa` | High | PEM RSA private key |
| `private_key_openssh` | High | OpenSSH private key |
| `private_key_ec` | High | PEM EC private key |
| `private_key_pkcs8` | High | PKCS#8 private key |

### Other

| Name | Severity | Catches |
| --- | --- | --- |
| `jwt` | Medium | JSON Web Token |
| `db_url_with_password` | Medium | Database URL with an inline password |
| `generic_high_entropy_assignment` | Low | High-entropy value assigned to a secret-looking key |

> Detector patterns are derived from public catalogs (secretlint,
> gitleaks, trufflehog) and tightened to reduce false positives.

---

## Examples

### Block every High-severity secret

```yaml
version: 1
rules:
  - name: block-high
    match: { severity: high }
    action: block
```

### Redact instead (recommended for chat tools)

```yaml
version: 1
rules:
  - name: redact-high
    match: { severity: high }
    action: redact
```

### Warn only — observe without interfering

```yaml
version: 1
rules:
  - name: warn-everything
    match: { all: true }
    action: warn
```

### Allow one detector, block the rest

First-match-wins lets an `allow` rule whitelist a detector type before a
broad `block`:

```yaml
version: 1
rules:
  - name: allow-openai-keys      # tolerate OpenAI keys (e.g. a test fixture)
    match: { pattern: openai_api_key }
    action: allow
  - name: block-other-high
    match: { severity: high }
    action: block
```

### Block a family of detectors with a glob

```yaml
version: 1
rules:
  - name: block-aws
    match: { pattern: aws_* }     # all three aws_* detectors
    action: block
```

### Block reading sensitive files

`path` rules act on file-read tool events (e.g. an agent opening a file):

```yaml
version: 1
rules:
  - name: block-dotenv-reads
    match: { path: "**/.env" }
    action: block
  - name: block-high-secrets
    match: { severity: high }
    action: block
```

### A realistic layered policy

```yaml
version: 1
rules:
  - name: never-send-private-keys
    match: { pattern: private_key_* }
    action: block
  - name: redact-other-high
    match: { severity: high }
    action: redact
  - name: warn-medium
    match: { severity: medium }
    action: warn
```

---

## Gotchas

* **`pattern` globs the detector *name*, not the secret value.** You can
  allow/block by detector type (`aws_*`, `private_key_*`), but you cannot
  whitelist one specific key string.
* **Only recognised AI endpoints are scanned** (see the table at the top).
  Traffic to other hosts is audited but never triggers a rule.
* **`block` + conversational tools wedges the session** — use `redact` or
  `warn` for Claude Code and similar; see *Choosing block vs redact*.
* **A bad policy is rejected whole** — fix the YAML and save again; in
  control-plane mode the agent keeps enforcing the last valid policy.
