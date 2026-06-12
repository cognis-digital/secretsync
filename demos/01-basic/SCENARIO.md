# Demo 01 — Seal a Secret so it's safe to commit

`secret.json` is a normal Kubernetes Secret with two plaintext values. We seal
it so the encrypted form can live in git, then unseal it where the private key
lives.

## Run it

```bash
# 1. Generate a sealing key (private .sealkey + public label .sealpub).
python -m secretsync keygen --out /tmp/ss

# 2. Seal the Secret -> a SealedSecret manifest (safe to commit).
python -m secretsync seal demos/01-basic/secret.json --key /tmp/ss.sealkey \
    --out /tmp/sealed.json

# 3. Or seal inline values directly.
python -m secretsync seal --key /tmp/ss.sealkey \
    --set DB_PASSWORD=hunter2 --set API_TOKEN=tok_live_x --name app-secrets

# 4. Unseal in the cluster (needs the private key).
python -m secretsync unseal /tmp/sealed.json --key /tmp/ss.sealkey

# 5. Rotate to a new key without exposing plaintext to disk.
python -m secretsync keygen --out /tmp/ss2
python -m secretsync rotate /tmp/sealed.json --old-key /tmp/ss.sealkey \
    --new-key /tmp/ss2.sealkey
```

## What you get

The `SealedSecret` contains only `nonce`/`ct`/`tag` per value — **no plaintext**.
Encryption is authenticated (encrypt-then-MAC), so any tampering or a wrong key
fails closed on unseal. The public `.sealpub` only labels which key sealed a
file; it cannot decrypt.
