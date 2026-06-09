# Runveil docs

Runveil is a forward HTTPS proxy that scans the AI requests leaving a
developer machine, applies a **policy** (allow / warn / redact / block),
and emits an audit trail. It catches secrets and sensitive file reads
before they reach an AI vendor.

Start here:

* **[Policy guide](policy-guide.md)** — the full policy grammar, every
  match condition and action, the complete detector reference, and
  copy-paste examples.
* [Cursor setup](cursor-setup.md) — point Cursor at the proxy.
