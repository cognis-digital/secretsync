"""Feature tests for secretsync — blobs, peek, verify, merge, file I/O, CLI, MCP."""

import base64
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secretsync import (
    generate_key, merge_sealed, peek, seal_bytes, seal_file, seal_values,
    unseal_bytes, unseal_secret, verify_sealed,
)
from secretsync.core import SecretSyncError
from secretsync.cli import main
from secretsync import mcp_server


class TestSealBytes(unittest.TestCase):
    def test_bytes_roundtrip(self):
        key = generate_key()
        sealed = seal_bytes(b"\x00\x01binary\xff", key, name="kc")
        self.assertEqual(sealed["kind"], "SealedBlob")
        self.assertEqual(unseal_bytes(sealed, key), b"\x00\x01binary\xff")

    def test_blob_no_plaintext(self):
        key = generate_key()
        sealed = seal_bytes(b"topsecret-value", key)
        self.assertNotIn("topsecret-value", json.dumps(sealed))

    def test_blob_wrong_key(self):
        sealed = seal_bytes(b"x", generate_key())
        with self.assertRaises(SecretSyncError):
            unseal_bytes(sealed, generate_key())

    def test_blob_not_recognized(self):
        with self.assertRaises(SecretSyncError):
            unseal_bytes({"spec": {"format": "nope"}}, generate_key())

    def test_seal_file(self):
        key = generate_key()
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "kubeconfig")
            with open(p, "wb") as fh:
                fh.write(b"apiVersion: v1\nkind: Config\n")
            sealed = seal_file(p, key)
            self.assertEqual(sealed["metadata"]["name"], "kubeconfig")
            self.assertEqual(unseal_bytes(sealed, key), b"apiVersion: v1\nkind: Config\n")

    def test_seal_file_missing(self):
        with self.assertRaises(SecretSyncError):
            seal_file("/no/such/file", generate_key())


class TestPeek(unittest.TestCase):
    def test_peek_lists_keys_not_values(self):
        key = generate_key()
        sealed = seal_values({"DB_PASSWORD": "p", "API_TOKEN": "t"}, key)
        info = peek(sealed)
        self.assertEqual(info["value_keys"], ["API_TOKEN", "DB_PASSWORD"])
        self.assertEqual(info["value_count"], 2)
        self.assertEqual(info["key_id"], key.key_id)
        # no plaintext anywhere in the peek output
        self.assertNotIn("p", info["value_keys"])

    def test_peek_blob(self):
        info = peek(seal_bytes(b"x", generate_key(), name="b"))
        self.assertEqual(info["kind"], "SealedBlob")
        self.assertEqual(info["value_count"], 1)


class TestVerify(unittest.TestCase):
    def test_verify_good(self):
        key = generate_key()
        sealed = seal_values({"A": "1", "B": "2"}, key)
        res = verify_sealed(sealed, key)
        self.assertTrue(res["ok"])
        self.assertEqual(res["verified"], 2)

    def test_verify_wrong_key(self):
        sealed = seal_values({"A": "1"}, generate_key())
        res = verify_sealed(sealed, generate_key())
        self.assertFalse(res["ok"])

    def test_verify_tampered(self):
        key = generate_key()
        sealed = seal_values({"A": "1"}, key)
        ct = bytearray(base64.b64decode(sealed["spec"]["encryptedData"]["A"]["ct"]))
        ct[0] ^= 0xFF
        sealed["spec"]["encryptedData"]["A"]["ct"] = base64.b64encode(bytes(ct)).decode()
        res = verify_sealed(sealed, key)
        self.assertFalse(res["ok"])
        self.assertTrue(any("authentication" in p for p in res["problems"]))


class TestMerge(unittest.TestCase):
    def test_merge_union(self):
        key = generate_key()
        a = seal_values({"A": "1"}, key, name="app")
        b = seal_values({"B": "2"}, key, name="app")
        merged = merge_sealed([a, b], key)
        secret = unseal_secret(merged, key)
        got = {k: base64.b64decode(v).decode() for k, v in secret["data"].items()}
        self.assertEqual(got, {"A": "1", "B": "2"})

    def test_merge_later_wins(self):
        key = generate_key()
        a = seal_values({"K": "old"}, key)
        b = seal_values({"K": "new"}, key)
        secret = unseal_secret(merge_sealed([a, b], key), key)
        self.assertEqual(base64.b64decode(secret["data"]["K"]).decode(), "new")


class TestCliFeatures(unittest.TestCase):
    def test_peek_verify_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "k")
            self.assertEqual(main(["keygen", "--out", base]), 0)
            sealed = os.path.join(tmp, "s.json")
            self.assertEqual(main(["seal", "--key", base + ".sealkey",
                                   "--set", "X=y", "--out", sealed]), 0)
            self.assertEqual(main(["peek", sealed]), 0)
            self.assertEqual(main(["verify", sealed, "--key", base + ".sealkey"]), 0)

    def test_seal_unseal_file_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "k")
            main(["keygen", "--out", base])
            src = os.path.join(tmp, "data.bin")
            with open(src, "wb") as fh:
                fh.write(b"payload-bytes")
            blob = os.path.join(tmp, "blob.json")
            self.assertEqual(main(["seal-file", src, "--key", base + ".sealkey",
                                   "--out", blob]), 0)
            out = os.path.join(tmp, "restored.bin")
            self.assertEqual(main(["unseal-file", blob, "--key", base + ".sealkey",
                                   "--out", out]), 0)
            with open(out, "rb") as fh:
                self.assertEqual(fh.read(), b"payload-bytes")

    def test_merge_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "k")
            main(["keygen", "--out", base])
            s1 = os.path.join(tmp, "s1.json")
            s2 = os.path.join(tmp, "s2.json")
            main(["seal", "--key", base + ".sealkey", "--set", "A=1", "--out", s1])
            main(["seal", "--key", base + ".sealkey", "--set", "B=2", "--out", s2])
            self.assertEqual(main(["merge", s1, s2, "--key", base + ".sealkey"]), 0)

    def test_verify_fails_nonzero_on_wrong_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            k1, k2 = os.path.join(tmp, "k1"), os.path.join(tmp, "k2")
            main(["keygen", "--out", k1])
            main(["keygen", "--out", k2])
            sealed = os.path.join(tmp, "s.json")
            main(["seal", "--key", k1 + ".sealkey", "--set", "X=y", "--out", sealed])
            self.assertEqual(main(["verify", sealed, "--key", k2 + ".sealkey"]), 1)


class TestMcpFeatures(unittest.TestCase):
    def test_peek_and_verify_tools(self):
        tl = mcp_server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = {t["name"] for t in tl["result"]["tools"]}
        self.assertEqual(names, {"seal", "unseal", "peek", "verify"})

    def test_verify_via_mcp(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_key()
            base = os.path.join(tmp, "k")
            key.to_files(base)
            sealed = seal_values({"T": "v"}, key)
            sp = os.path.join(tmp, "s.json")
            with open(sp, "w") as fh:
                json.dump(sealed, fh)
            r = mcp_server.handle_request({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "verify",
                           "arguments": {"sealed": sp, "key": base + ".sealkey"}}})
            self.assertFalse(r["result"]["isError"])


if __name__ == "__main__":
    unittest.main()
