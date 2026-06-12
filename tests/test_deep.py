"""Deep tests for secretsync — crypto, tamper, rotate, key mismatch, MCP."""

import base64
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secretsync import (
    generate_key, load_key, rotate, seal_secret, seal_values, unseal_secret,
    audit_secret_names,
)
from secretsync.core import SecretSyncError, _seal_value, _unseal_value
from secretsync import mcp_server

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET = os.path.join(REPO_ROOT, "demos", "01-basic", "secret.json")


class TestPrimitive(unittest.TestCase):
    def test_value_roundtrip(self):
        key = generate_key()
        blob = _seal_value(key.key, b"hello world")
        self.assertEqual(_unseal_value(key.key, blob), b"hello world")

    def test_tamper_detected(self):
        key = generate_key()
        blob = _seal_value(key.key, b"data")
        ct = bytearray(base64.b64decode(blob["ct"]))
        ct[0] ^= 0xFF
        blob["ct"] = base64.b64encode(bytes(ct)).decode()
        with self.assertRaises(SecretSyncError):
            _unseal_value(key.key, blob)

    def test_wrong_key_fails(self):
        k1, k2 = generate_key(), generate_key()
        blob = _seal_value(k1.key, b"x")
        with self.assertRaises(SecretSyncError):
            _unseal_value(k2.key, blob)


class TestManifest(unittest.TestCase):
    def test_data_and_stringdata(self):
        key = generate_key()
        secret = {"metadata": {"name": "s"},
                  "data": {"A": base64.b64encode(b"aaa").decode()},
                  "stringData": {"B": "bbb"}}
        sealed = seal_secret(secret, key)
        back = unseal_secret(sealed, key)
        self.assertEqual(base64.b64decode(back["data"]["A"]), b"aaa")
        self.assertEqual(base64.b64decode(back["data"]["B"]), b"bbb")

    def test_key_id_mismatch(self):
        k1, k2 = generate_key(), generate_key()
        sealed = seal_values({"x": "y"}, k1)
        with self.assertRaises(SecretSyncError):
            unseal_secret(sealed, k2)

    def test_not_sealed_format(self):
        with self.assertRaises(SecretSyncError):
            unseal_secret({"spec": {"format": "nope"}}, generate_key())


class TestRotate(unittest.TestCase):
    def test_rotate_changes_key_keeps_value(self):
        old, new = generate_key(), generate_key()
        sealed = seal_values({"P": "pw"}, old)
        rotated = rotate(sealed, old, new)
        self.assertEqual(rotated["spec"]["key_id"], new.key_id)
        back = unseal_secret(rotated, new)
        self.assertEqual(base64.b64decode(back["data"]["P"]).decode(), "pw")
        # old key can no longer open it
        with self.assertRaises(SecretSyncError):
            unseal_secret(rotated, old)


class TestKeyFiles(unittest.TestCase):
    def test_public_file_cannot_unseal(self):
        with tempfile.TemporaryDirectory() as tmp:
            kp = generate_key()
            base = os.path.join(tmp, "k")
            kp.to_files(base)
            with self.assertRaises(SecretSyncError):
                load_key(base + ".sealpub")


class TestMcp(unittest.TestCase):
    def test_seal_unseal_via_mcp(self):
        with tempfile.TemporaryDirectory() as tmp:
            kp = generate_key()
            base = os.path.join(tmp, "k")
            kp.to_files(base)
            r = mcp_server.handle_request({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "seal",
                           "arguments": {"key": base + ".sealkey",
                                         "values": {"TOKEN": "abc"}}}})
            sealed = json.loads(r["result"]["content"][0]["text"])
            sp = os.path.join(tmp, "s.json")
            with open(sp, "w") as fh:
                json.dump(sealed, fh)
            r2 = mcp_server.handle_request({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "unseal",
                           "arguments": {"sealed": sp, "key": base + ".sealkey"}}})
            secret = json.loads(r2["result"]["content"][0]["text"])
            self.assertEqual(base64.b64decode(secret["data"]["TOKEN"]).decode(), "abc")

    def test_list(self):
        tl = mcp_server.handle_request({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
        self.assertEqual({t["name"] for t in tl["result"]["tools"]}, {"seal", "unseal"})


class TestAiHook(unittest.TestCase):
    def test_off_by_default(self):
        for v in ("COGNIS_AI_BACKEND", "COGNIS_AI_ENDPOINT"):
            os.environ.pop(v, None)
        out = audit_secret_names({"stringData": {"DB_PASSWORD": "x"}})
        self.assertTrue(out["_ai"].startswith("disabled"))
        self.assertIn("DB_PASSWORD", out["keys"])


if __name__ == "__main__":
    unittest.main()
