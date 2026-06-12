"""secretsync MCP server — stdio JSON-RPC 2.0. Standard library only.

    {"command": "python", "args": ["-m", "secretsync", "mcp"]}
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional

from secretsync import TOOL_NAME, TOOL_VERSION
from secretsync.core import (
    SecretSyncError,
    load_json,
    load_key,
    seal_secret,
    seal_values,
    unseal_secret,
)

PROTOCOL_VERSION = "2024-11-05"

_TOOLS = [
    {
        "name": "seal",
        "description": "Seal plaintext values into a SealedSecret manifest that "
                       "is safe to commit to git.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string", "description": "Key file path."},
                           "values": {"type": "object",
                                      "description": "Map of name -> plaintext."},
                           "name": {"type": "string"},
                           "namespace": {"type": "string"}},
            "required": ["key", "values"], "additionalProperties": False,
        },
    },
    {
        "name": "unseal",
        "description": "Decrypt a SealedSecret manifest back into a Kubernetes "
                       "Secret using the private sealing key.",
        "inputSchema": {
            "type": "object",
            "properties": {"sealed": {"type": "string", "description": "SealedSecret JSON path."},
                           "key": {"type": "string", "description": "Private key path."}},
            "required": ["sealed", "key"], "additionalProperties": False,
        },
    },
]


def _result(req_id, result): return {"jsonrpc": "2.0", "id": req_id, "result": result}
def _error(req_id, code, msg): return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": msg}}


def _call_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    if name == "seal":
        key = args.get("key")
        values = args.get("values")
        if not isinstance(key, str) or not isinstance(values, dict):
            raise ValueError("`key` (string) and `values` (object) are required")
        sealed = seal_values({k: str(v) for k, v in values.items()},
                             load_key(key),
                             name=args.get("name") or "secret",
                             namespace=args.get("namespace") or "default")
        return {"content": [{"type": "text", "text": json.dumps(sealed, indent=2)}],
                "isError": False}
    if name == "unseal":
        sealed, key = args.get("sealed"), args.get("key")
        if not isinstance(sealed, str) or not isinstance(key, str):
            raise ValueError("`sealed` and `key` (strings) are required")
        secret = unseal_secret(load_json(sealed), load_key(key))
        return {"content": [{"type": "text", "text": json.dumps(secret, indent=2)}],
                "isError": False}
    raise ValueError(f"unknown tool: {name}")


def handle_request(req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params") or {}
    is_notification = "id" not in req
    if method == "initialize":
        res = _result(req_id, {"protocolVersion": PROTOCOL_VERSION,
                               "capabilities": {"tools": {"listChanged": False}},
                               "serverInfo": {"name": TOOL_NAME, "version": TOOL_VERSION}})
        return None if is_notification else res
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "ping":
        return None if is_notification else _result(req_id, {})
    if method == "tools/list":
        return _result(req_id, {"tools": _TOOLS})
    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments") or {}
        try:
            return _result(req_id, _call_tool(name, args))
        except (ValueError, OSError, SecretSyncError, json.JSONDecodeError) as exc:
            return _error(req_id, -32602, str(exc))
        except Exception as exc:  # pragma: no cover
            return _error(req_id, -32603, f"internal error: {exc}")
    if is_notification:
        return None
    return _error(req_id, -32601, f"method not found: {method}")


def run_mcp_server(stdin=None, stdout=None) -> None:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            stdout.write(json.dumps(_error(None, -32700, "parse error")) + "\n")
            stdout.flush()
            continue
        response = handle_request(req)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()


if __name__ == "__main__":
    run_mcp_server()
