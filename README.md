# secretsync

**Declarative secret sealing & sync for GitOps.** Encrypt Kubernetes Secret
values into a manifest that is **safe to commit to git**, and unseal them only
where the private key lives. Authenticated encryption, pure Python standard
library, no external crypto package.

Part of the **Cognis Neural Suite**.

---

## Why

Plaintext Secrets in git are a top supply-chain mistake, but most teams want
their secrets *in* the GitOps repo alongside everything else. secretsync seals
each value so the committed form is opaque and tamper-evident, then unseals it
in-cluster — dependency-free, so it works in air-gapped and self-hosted setups.

## Commands

```bash
# Generate a sealing key (private .sealkey + public label .sealpub).
python -m secretsync keygen --out ss

# Seal a Secret manifest, or inline values.
python -m secretsync seal secret.json --key ss.sealkey
python -m secretsync seal --key ss.sealkey --set DB_PASSWORD=hunter2 --name app

# Unseal (requires the private key).
python -m secretsync unseal sealed.json --key ss.sealkey

# Rotate to a new key (decrypt-with-old, seal-with-new).
python -m secretsync rotate sealed.json --old-key ss.sealkey --new-key ss2.sealkey

# Run as a local MCP server (stdio JSON-RPC).
python -m secretsync mcp
```

## What sets secretsync apart

- **Authenticated encryption.** Encrypt-then-MAC (HMAC-SHA256) means a wrong key
  or any tampering fails *closed* on unseal — you never get a silently corrupt
  Secret.
- **Per-value sealing.** Each value gets its own nonce/keystream; the sealed
  manifest contains zero plaintext.
- **Key rotation built in.** Re-seal under a new key without writing plaintext
  to disk.
- **MCP-native** (`seal` / `unseal`) and an opt-in local-fleet AI hook (default
  OFF) that flags secret keys that look like long-lived credentials.
- **Pairs with the GitOps suite** — seal with secretsync, detect drift with
  [gitopsd](https://github.com/cognis-digital/gitopsd).

> Note: this is a portable, self-hosted sealing scheme built on stdlib
> primitives. For regulated environments with HSM/KMS requirements, treat it as
> the git-safe transport layer and keep your root key in your existing KMS.

## Tests

```bash
python -m pytest -q     # or: python -m unittest discover -s tests
```

## Interoperability

`secretsync` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## Integrations

Forward `secretsync`'s findings to STIX/MISP/Sigma/Splunk/Elastic/Slack/webhooks via
[`cognis-connect`](https://github.com/cognis-digital/cognis-connect). See **[INTEGRATIONS.md](INTEGRATIONS.md)**.

## License

Cognis Open Collaboration License (COCL) 1.0 — see [`LICENSE`](LICENSE).
© 2026 Cognis Digital LLC. Original Cognis work; no third-party code, names, or
branding.

<!-- cognis:domains:start -->
## Domains

**Primary domain:** Cyber & Security  ·  **JTF MERIDIAN division:** NULLBYTE · SPECTER

**Topics:** `cognis` `security` `infosec` `cybersecurity` `blue-team`

Part of the **Cognis Neural Suite** — 300+ source-available tools organized across 12 domains under the JTF MERIDIAN command structure. See the [suite on GitHub](https://github.com/cognis-digital) and [jtf-meridian](https://github.com/cognis-digital/jtf-meridian) for how the pieces fit together.
<!-- cognis:domains:end -->

## Usage — step by step

`secretsync` seals Kubernetes Secret values into a manifest **safe to commit to git**, and unseals them only where the private key lives.

1. **Install** (pure stdlib, Python 3.10+):
   ```bash
   pip install "git+https://github.com/cognis-digital/secretsync.git"
   ```
2. **Generate a sealing key** — a private `.sealkey` (kept in-cluster) and a public `.sealpub` label:
   ```bash
   secretsync keygen --out ss
   ```
3. **Seal** a Secret manifest, or inline values, into a commit-safe SealedSecret:
   ```bash
   secretsync seal secret.json --key ss.sealkey --out sealed.json
   secretsync seal --key ss.sealpub --set DB_PASSWORD=hunter2 --name app --out sealed.json
   ```
4. **Use the sealed object** — `peek` describes it without decrypting, `verify` checks every value's MAC, and `unseal` (private key only) recovers the Secret:
   ```bash
   secretsync peek   sealed.json
   secretsync verify sealed.json --key ss.sealkey
   secretsync unseal sealed.json --key ss.sealkey --out secret.json
   ```
5. **Automate** — rotate to a new key, or seal an arbitrary file, in a pipeline:
   ```bash
   secretsync rotate sealed.json --old-key ss.sealkey --new-key ss2.sealkey --out sealed.json
   secretsync seal-file config.bin --key ss.sealkey --out config.sealed.json
   ```
   Or run it as a local MCP server (stdio JSON-RPC): `secretsync mcp`.
