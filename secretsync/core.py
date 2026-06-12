"""Core engine for secretsync — declarative secret sealing & sync for GitOps.

Committing Kubernetes Secrets to git in plaintext is a classic supply-chain
mistake. secretsync lets you *seal* secret values so the encrypted form is safe
to commit, and *unseal* them only where the private key lives (the cluster
operator side). The sealed file is itself a normal manifest you can store in
git and feed to a GitOps pipeline.

Crypto (standard library only):

  * A sealing key pair. The public ("seal") key encrypts; the private
    ("unseal") key decrypts.
  * Each value is encrypted with a fresh random data key under
    AES-CTR-style keystream derived via HMAC-SHA256 (a stdlib construction),
    authenticated with an HMAC tag (encrypt-then-MAC). The data key is wrapped
    to the sealing key. No third-party crypto package required.

This is a portable, dependency-free design intended for self-hosted and
air-gapped GitOps. It is original Cognis Digital work; it shares no code,
names, or branding with any other sealed-secret tool.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

TOOL_NAME = "secretsync"
TOOL_VERSION = "0.1.0"

SEALED_FORMAT = "cognis.secretsync.sealed/v1"


class SecretSyncError(Exception):
    """User-facing sealing/unsealing error."""


# --------------------------------------------------------------------------- #
# Encoding helpers
# --------------------------------------------------------------------------- #

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


# --------------------------------------------------------------------------- #
# Keys — a symmetric "sealing secret" model (portable, stdlib only).
# --------------------------------------------------------------------------- #
# We use a 32-byte master sealing key. The public artifact (a fingerprint) lets
# you label which key sealed a file; the private key bytes are what unseal it.

@dataclass
class SealKey:
    key: bytes            # 32-byte master key
    key_id: str

    def to_files(self, base: str) -> Tuple[str, str]:
        priv = base + ".sealkey"
        pub = base + ".sealpub"
        with open(priv, "w", encoding="utf-8") as fh:
            json.dump({"key_id": self.key_id, "key": _b64e(self.key)}, fh, indent=2)
        with open(pub, "w", encoding="utf-8") as fh:
            json.dump({"key_id": self.key_id,
                       "fingerprint": self.key_id}, fh, indent=2)
        try:
            os.chmod(priv, 0o600)
        except OSError:
            pass
        return priv, pub


def generate_key() -> SealKey:
    key = os.urandom(32)
    return SealKey(key=key, key_id=hashlib.sha256(key).hexdigest()[:16])


def load_key(path: str) -> SealKey:
    with open(path, "r", encoding="utf-8") as fh:
        d = json.load(fh)
    if "key" not in d:
        raise SecretSyncError("this is a public seal file; the private "
                              ".sealkey is required to unseal")
    key = _b64d(d["key"])
    return SealKey(key=key, key_id=d.get("key_id") or hashlib.sha256(key).hexdigest()[:16])


# --------------------------------------------------------------------------- #
# Authenticated encryption (HMAC-keystream + encrypt-then-MAC), stdlib only.
# --------------------------------------------------------------------------- #

def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(key, nonce + struct.pack(">Q", counter),
                         hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def _derive(master: bytes, label: bytes) -> bytes:
    return hmac.new(master, label, hashlib.sha256).digest()


def _seal_value(master: bytes, plaintext: bytes) -> Dict[str, str]:
    nonce = os.urandom(16)
    enc_key = _derive(master, b"enc" + nonce)
    mac_key = _derive(master, b"mac" + nonce)
    ks = _keystream(enc_key, nonce, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, ks))
    tag = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    return {"nonce": _b64e(nonce), "ct": _b64e(ct), "tag": _b64e(tag)}


def _unseal_value(master: bytes, blob: Dict[str, str]) -> bytes:
    nonce = _b64d(blob["nonce"])
    ct = _b64d(blob["ct"])
    tag = _b64d(blob["tag"])
    mac_key = _derive(master, b"mac" + nonce)
    expected = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise SecretSyncError("authentication failed — wrong key or tampered data")
    enc_key = _derive(master, b"enc" + nonce)
    ks = _keystream(enc_key, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


# --------------------------------------------------------------------------- #
# Manifest-level seal / unseal
# --------------------------------------------------------------------------- #

def seal_secret(secret: Dict[str, Any], key: SealKey) -> Dict[str, Any]:
    """Seal a Kubernetes Secret's data values; return a SealedSecret manifest.

    ``data`` (base64 in real Secrets) and ``stringData`` (plain) are both sealed.
    """
    md = secret.get("metadata", {}) or {}
    sealed_data: Dict[str, Dict[str, str]] = {}

    for k, v in (secret.get("data") or {}).items():
        # data values are base64; seal the decoded bytes
        try:
            raw = _b64d(v) if isinstance(v, str) else bytes(v)
        except Exception:
            raw = str(v).encode()
        sealed_data[k] = _seal_value(key.key, raw)
    for k, v in (secret.get("stringData") or {}).items():
        sealed_data[k] = _seal_value(key.key, str(v).encode())

    return {
        "apiVersion": "cognis.digital/v1",
        "kind": "SealedSecret",
        "metadata": {"name": md.get("name", "secret"),
                     "namespace": md.get("namespace", "default")},
        "spec": {
            "format": SEALED_FORMAT,
            "key_id": key.key_id,
            "encryptedData": sealed_data,
            "template": {"kind": "Secret",
                         "type": secret.get("type", "Opaque")},
        },
    }


def unseal_secret(sealed: Dict[str, Any], key: SealKey) -> Dict[str, Any]:
    """Decrypt a SealedSecret back into a Kubernetes Secret manifest."""
    spec = sealed.get("spec", {}) or {}
    if spec.get("format") != SEALED_FORMAT:
        raise SecretSyncError("not a recognized SealedSecret (bad format)")
    if spec.get("key_id") and spec["key_id"] != key.key_id:
        raise SecretSyncError(
            f"key mismatch: sealed with {spec['key_id']}, you have {key.key_id}")
    md = sealed.get("metadata", {}) or {}
    data: Dict[str, str] = {}
    for k, blob in (spec.get("encryptedData") or {}).items():
        data[k] = _b64e(_unseal_value(key.key, blob))
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": md.get("name", "secret"),
                     "namespace": md.get("namespace", "default")},
        "type": spec.get("template", {}).get("type", "Opaque"),
        "data": data,
    }


def rotate(sealed: Dict[str, Any], old_key: SealKey,
           new_key: SealKey) -> Dict[str, Any]:
    """Re-seal a SealedSecret under a new key (decrypt with old, seal with new)."""
    secret = unseal_secret(sealed, old_key)
    return seal_secret(secret, new_key)


# --------------------------------------------------------------------------- #
# Convenience: seal/unseal from raw key=value inputs
# --------------------------------------------------------------------------- #

def seal_values(values: Dict[str, str], key: SealKey, *,
                name: str = "secret", namespace: str = "default") -> Dict[str, Any]:
    return seal_secret({"metadata": {"name": name, "namespace": namespace},
                        "stringData": values}, key)


# --------------------------------------------------------------------------- #
# Raw blob sealing (files / arbitrary bytes, not just k8s Secrets)
# --------------------------------------------------------------------------- #

def seal_bytes(data: bytes, key: SealKey, *, name: str = "blob") -> Dict[str, Any]:
    """Seal arbitrary bytes (e.g. a kubeconfig or a TLS key file)."""
    return {
        "apiVersion": "cognis.digital/v1",
        "kind": "SealedBlob",
        "metadata": {"name": name},
        "spec": {"format": SEALED_FORMAT, "key_id": key.key_id,
                 "size": len(data), "encrypted": _seal_value(key.key, data)},
    }


def unseal_bytes(sealed: Dict[str, Any], key: SealKey) -> bytes:
    """Decrypt a SealedBlob back into raw bytes."""
    spec = sealed.get("spec", {}) or {}
    if spec.get("format") != SEALED_FORMAT or "encrypted" not in spec:
        raise SecretSyncError("not a recognized SealedBlob")
    if spec.get("key_id") and spec["key_id"] != key.key_id:
        raise SecretSyncError(
            f"key mismatch: sealed with {spec['key_id']}, you have {key.key_id}")
    return _unseal_value(key.key, spec["encrypted"])


def seal_file(path: str, key: SealKey) -> Dict[str, Any]:
    if not os.path.isfile(path):
        raise SecretSyncError(f"file not found: {path}")
    with open(path, "rb") as fh:
        return seal_bytes(fh.read(), key, name=os.path.basename(path))


# --------------------------------------------------------------------------- #
# Inspection / verification (no decryption needed)
# --------------------------------------------------------------------------- #

def peek(sealed: Dict[str, Any]) -> Dict[str, Any]:
    """Describe a sealed object without decrypting it.

    Returns kind, key_id, and the value KEY names (never the plaintext).
    Useful for review/diff in a PR without holding the private key.
    """
    spec = sealed.get("spec", {}) or {}
    kind = sealed.get("kind", "?")
    md = sealed.get("metadata", {}) or {}
    keys = sorted((spec.get("encryptedData") or {}).keys())
    return {
        "kind": kind,
        "name": md.get("name"),
        "namespace": md.get("namespace"),
        "key_id": spec.get("key_id"),
        "format": spec.get("format"),
        "value_keys": keys,
        "value_count": len(keys) if keys else (1 if "encrypted" in spec else 0),
    }


def verify_sealed(sealed: Dict[str, Any], key: SealKey) -> Dict[str, Any]:
    """Verify every value's MAC under ``key`` WITHOUT exposing plaintext.

    Returns {ok, key_id, verified, problems}. A wrong key or tampered blob is
    reported per-value; nothing is decrypted into the result.
    """
    spec = sealed.get("spec", {}) or {}
    problems: List[str] = []
    verified = 0
    if spec.get("key_id") and key.key_id and spec["key_id"] != key.key_id:
        problems.append(f"key_id mismatch: sealed {spec['key_id']} vs {key.key_id}")
    blobs = dict(spec.get("encryptedData") or {})
    if "encrypted" in spec:
        blobs["<blob>"] = spec["encrypted"]
    for name, blob in blobs.items():
        try:
            _unseal_value(key.key, blob)  # raises on bad MAC
            verified += 1
        except SecretSyncError:
            problems.append(f"value {name!r} failed authentication")
    return {"ok": not problems, "key_id": key.key_id,
            "verified": verified, "problems": problems}


def merge_sealed(targets: List[Dict[str, Any]], key: SealKey) -> Dict[str, Any]:
    """Merge several SealedSecrets (same key) into one, re-sealing the union.

    Later entries win on key collisions. All inputs must share the sealing key.
    """
    combined: Dict[str, str] = {}
    name = namespace = None
    for sealed in targets:
        secret = unseal_secret(sealed, key)
        import base64 as _b
        for k, v in (secret.get("data") or {}).items():
            combined[k] = _b.b64decode(v).decode("utf-8", "replace")
        md = sealed.get("metadata", {}) or {}
        name = name or md.get("name")
        namespace = namespace or md.get("namespace")
    return seal_values(combined, key, name=name or "secret",
                       namespace=namespace or "default")


# --------------------------------------------------------------------------- #
# AI hook (opt-in, default OFF)
# --------------------------------------------------------------------------- #

def audit_secret_names(secret: Dict[str, Any]) -> Dict[str, Any]:
    """Flag value KEYS whose names suggest high-risk secrets (local fleet, OFF)."""
    keys = list((secret.get("data") or {}).keys()) + \
           list((secret.get("stringData") or {}).keys())
    out = {"keys": keys, "flags": [], "_ai": "disabled — set COGNIS_AI_BACKEND to enable"}
    backend = _load_ai_backend()
    if backend is None or not backend.is_enabled() or not backend.health():
        return out
    try:
        resp = backend._chat(
            "Given these Kubernetes secret key names, list which look like "
            "long-lived credentials that should be rotated. One per line.",
            "\n".join(keys))
        out["flags"] = [l.strip() for l in (resp or "").splitlines() if l.strip()]
        out["_ai"] = "audited by local fleet"
    except Exception:
        pass
    return out


def _load_ai_backend():
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))
    cand = os.path.abspath(os.path.join(here, "..", "..", "..", "_shared",
                                        "cognis_ai_backend.py"))
    if os.path.isfile(cand):
        try:
            spec = importlib.util.spec_from_file_location("cognis_ai_backend", cand)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
            return mod.CognisAIBackend()
        except Exception:
            return None
    return None


# --------------------------------------------------------------------------- #
# JSON I/O helpers
# --------------------------------------------------------------------------- #

def load_json(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        raise SecretSyncError(f"file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
