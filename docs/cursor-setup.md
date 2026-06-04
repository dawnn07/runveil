# Using Runveil with Cursor

Runveil inspects every AI request your tools make through it. Cursor in **BYOK** (Bring Your Own Key) mode sends prompts directly to OpenAI or Anthropic — Runveil sits in front, applies your policy, and writes an audit record per request.

This guide gets you wired up in five minutes.

> **What about non-BYOK?**
> When BYOK is off, Cursor routes prompts through `api2.cursor.sh` (its own backend). Runveil still sees that traffic at the host level (audit logs `host=api2.cursor.sh decision=continue`) but cannot decrypt the payload — Cursor pins its certificate. To get full policy enforcement, use BYOK.

---

## 1. Start Runveil

```bash
runveil init                          # first run only
runveil proxy --port 9443
```

Leave it running. In another terminal:

```bash
runveil logs --follow
```

This streams audit records live so you can watch what Cursor sends.

## 2. Switch Cursor to BYOK

1. Open Cursor → **Settings** (gear icon).
2. **Models** tab → toggle on **"Use your own API key"**.
3. Paste an **OpenAI key**, an **Anthropic key**, or both. (Cursor lets you switch the active provider per chat.)

If your provider is missing from the UI, update Cursor to the latest release — older builds hide BYOK behind a feature flag.

## 3. Point Cursor at the proxy

Cursor does **not** honor the `HTTPS_PROXY` environment variable. The proxy URL must be set in-app:

1. Cursor → **Settings** → **Beta** → **Custom Proxy URL**.
2. Set the value to `http://127.0.0.1:9443`.
3. Save and restart Cursor.

(If the **Beta** section doesn't show **Custom Proxy URL**, check **Settings → Network**. The label has moved between Cursor releases. Search the settings dialog for "proxy".)

## 4. Trust the Runveil CA

Cursor is an Electron app and uses Chromium's certificate store. On most Linux distros, `runveil init` already trusts the CA system-wide. If you see TLS errors in Cursor:

**Linux (Debian/Ubuntu):**
```bash
sudo cp ~/.runveil/ca/ca.crt /usr/local/share/ca-certificates/runveil.crt
sudo update-ca-certificates
```

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.runveil/ca/ca.crt
```

**Windows:**
```powershell
certutil -addstore "Root" "$env:USERPROFILE\.runveil\ca\ca.crt"
```

Restart Cursor after installing the cert.

## 5. Verify

In Cursor, open chat and ask a benign question ("explain a binary search"). In your `runveil logs --follow` terminal you should see a record like:

```
HH:MM:SS  ✓  POST  api.openai.com        /v1/chat/completions          200  240ms  continue
```

Now try something policy should block. With this rule in `~/.runveil/policy.yaml`:

```yaml
version: 1
rules:
  - name: block-payments
    match: { path: "**/payments/**" }
    action: block
  - name: default-warn
    match: { all: true }
    action: warn
```

(Note: specific blocks must come **before** the catch-all warn — first match wins.)

Restart `runveil proxy` to pick up the change. In Cursor's Composer, ask it to read a file at `~/anywhere/payments/anything.txt`. Cursor's tool call should fail with a 403 error from the proxy, and the audit line shows:

```
HH:MM:SS  ✗  POST  api.openai.com        /v1/chat/completions          403  18ms   block    findings=1 [block-payments]
```

That's it. Cursor + Runveil is now governing every prompt your IDE sends.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Cursor shows "tunnel connection failed" | Runveil not running or wrong port. Check `runveil status`. |
| Cursor shows certificate errors | CA not trusted by system store. Re-run step 4 and restart Cursor. |
| Audit log empty | Cursor still using its own backend. Confirm BYOK is on AND the Custom Proxy URL is set. |
| Records appear with `vendor=""` | Cursor hit an endpoint Runveil doesn't have a parser for. File an issue with the host + path from the audit record. |
