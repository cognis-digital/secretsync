"""Command-line interface for secretsync."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from secretsync import TOOL_NAME, TOOL_VERSION
from secretsync.core import (
    SecretSyncError,
    generate_key,
    load_json,
    load_key,
    rotate,
    seal_secret,
    seal_values,
    unseal_secret,
)


def _emit(text: str, out: Optional[str]) -> None:
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        print(f"wrote {out}", file=sys.stderr)
    else:
        print(text)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Declarative secret sealing & sync for GitOps — encrypt "
                    "secrets into manifests safe to commit; unseal in-cluster.")
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    k = sub.add_parser("keygen", help="Generate a sealing key.")
    k.add_argument("--out", default="secretsync", help="Base path for key files.")

    s = sub.add_parser("seal", help="Seal a Secret manifest (or --set values).")
    s.add_argument("secret", nargs="?", help="Secret manifest JSON (or omit and use --set).")
    s.add_argument("--key", required=True, help="Sealing key (.sealkey or .sealpub).")
    s.add_argument("--set", action="append", default=[], metavar="K=V",
                   help="Inline value(s) to seal (repeatable).")
    s.add_argument("--name", default="secret")
    s.add_argument("--namespace", default="default")
    s.add_argument("--out", help="Write the SealedSecret here.")

    u = sub.add_parser("unseal", help="Unseal a SealedSecret back to a Secret.")
    u.add_argument("sealed")
    u.add_argument("--key", required=True, help="Private key (.sealkey).")
    u.add_argument("--out")

    r = sub.add_parser("rotate", help="Re-seal under a new key.")
    r.add_argument("sealed")
    r.add_argument("--old-key", required=True)
    r.add_argument("--new-key", required=True)
    r.add_argument("--out")

    sub.add_parser("mcp", help="Run as an MCP server (stdio JSON-RPC).")
    return p


def _run_keygen(a) -> int:
    try:
        kp = generate_key()
        priv, pub = kp.to_files(a.out)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"secretsync keygen — key_id={kp.key_id}")
    print(f"  private (unseal): {priv}")
    print(f"  public  (label) : {pub}")
    return 0


def _run_seal(a) -> int:
    try:
        key = load_key(a.key)
    except (OSError, SecretSyncError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        if a.set:
            values = {}
            for item in a.set:
                if "=" not in item:
                    raise SecretSyncError(f"--set expects K=V, got {item!r}")
                k, v = item.split("=", 1)
                values[k] = v
            sealed = seal_values(values, key, name=a.name, namespace=a.namespace)
        elif a.secret:
            sealed = seal_secret(load_json(a.secret), key)
        else:
            raise SecretSyncError("provide a secret manifest or --set K=V")
    except (OSError, SecretSyncError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _emit(json.dumps(sealed, indent=2), a.out)
    return 0


def _run_unseal(a) -> int:
    try:
        secret = unseal_secret(load_json(a.sealed), load_key(a.key))
    except (OSError, SecretSyncError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _emit(json.dumps(secret, indent=2), a.out)
    return 0


def _run_rotate(a) -> int:
    try:
        out = rotate(load_json(a.sealed), load_key(a.old_key), load_key(a.new_key))
    except (OSError, SecretSyncError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _emit(json.dumps(out, indent=2), a.out)
    return 0


def _run_mcp() -> int:
    from secretsync.mcp_server import run_mcp_server
    run_mcp_server()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "keygen":
        return _run_keygen(args)
    if args.command == "seal":
        return _run_seal(args)
    if args.command == "unseal":
        return _run_unseal(args)
    if args.command == "rotate":
        return _run_rotate(args)
    if args.command == "mcp":
        return _run_mcp()
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
