# secretsync — Usage Guide

A practical reference for every command. secretsync is standard-library Python;
nothing here needs network access or a cluster.

## Concepts

- **Sealing key** — a 32-byte master key. The private `.sealkey` *unseals*; the
  public `.sealpub` only labels which key sealed a file (it cannot decrypt).
- **SealedSecret** — a manifest where each Secret value is individually
  encrypted (nonce + ciphertext + MAC). Safe to commit to git.
- **SealedBlob** — the same protection for an arbitrary file (kubeconfig, TLS
  key, license).
- **Authenticated encryption** — encrypt-then-MAC (HMAC-SHA256). A wrong key or
  any tampering fails *closed* on unseal/verify.

## Commands

### keygen
```bash
python -m secretsync keygen --out ss
# -> ss.sealkey (private, chmod 600), ss.sealpub (public label)
```

### seal / unseal
```bash
# From a Secret manifest:
python -m secretsync seal secret.json --key ss.sealkey --out sealed.json
# From inline values:
python -m secretsync seal --key ss.sealkey --set DB_PASSWORD=hunter2 --name app
# Back to a Secret (needs the private key):
python -m secretsync unseal sealed.json --key ss.sealkey
```

### peek — review without the key
```bash
python -m secretsync peek sealed.json
# Shows kind, key_id, and the value KEY names — never plaintext.
```
Use this in PR review: a reviewer without the private key can still confirm
*which* keys are present and *which* sealing key was used.

### verify — integrity gate
```bash
python -m secretsync verify sealed.json --key ss.sealkey
# Exit 0 if every value's MAC checks out; non-zero on tamper / wrong key.
```
`verify` never decrypts into output, so it is safe to run in logs/CI.

### seal-file / unseal-file — arbitrary blobs
```bash
python -m secretsync seal-file kubeconfig --key ss.sealkey --out kubeconfig.sealed.json
python -m secretsync unseal-file kubeconfig.sealed.json --key ss.sealkey --out kubeconfig
```

### merge — combine SealedSecrets
```bash
python -m secretsync merge a.json b.json c.json --key ss.sealkey --out all.json
# Union of values, re-sealed; later files win on key collisions.
```

### rotate — change keys without exposing plaintext
```bash
python -m secretsync keygen --out ss2
python -m secretsync rotate sealed.json --old-key ss.sealkey --new-key ss2.sealkey
```

## MCP server

```bash
python -m secretsync mcp
```
Exposes `seal`, `unseal`, `peek`, and `verify` over stdio JSON-RPC for agentic
workflows (Cognis.Studio, Claude Desktop, Cursor).

## CI gate example

```bash
# Fail the pipeline if a committed sealed file is tampered or sealed with the
# wrong key:
python -m secretsync verify deploy/secrets.sealed.json --key $CI_SEAL_KEY || exit 1
```

## Threat model note

This is a portable, self-hosted sealing scheme built on stdlib primitives. For
regulated environments with HSM/KMS requirements, treat secretsync as the
git-safe transport layer and keep the master key in your existing KMS.
