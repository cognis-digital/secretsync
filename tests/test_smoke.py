"""Smoke tests for secretsync. Standard library only."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secretsync import (
    TOOL_NAME, TOOL_VERSION, generate_key, seal_secret, unseal_secret,
)
from secretsync.cli import main

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET = os.path.join(REPO_ROOT, "demos", "01-basic", "secret.json")


class TestMetadata(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "secretsync")
        self.assertTrue(TOOL_VERSION)


class TestSealRoundTrip(unittest.TestCase):
    def test_seal_then_unseal(self):
        key = generate_key()
        secret = {"metadata": {"name": "s"}, "stringData": {"K": "v3ry-secret"}}
        sealed = seal_secret(secret, key)
        self.assertEqual(sealed["kind"], "SealedSecret")
        # ciphertext must NOT contain the plaintext
        blob = json.dumps(sealed)
        self.assertNotIn("v3ry-secret", blob)
        back = unseal_secret(sealed, key)
        import base64
        self.assertEqual(base64.b64decode(back["data"]["K"]).decode(), "v3ry-secret")


class TestCli(unittest.TestCase):
    def test_keygen_seal_unseal_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "k")
            self.assertEqual(main(["keygen", "--out", base]), 0)
            sealed = os.path.join(tmp, "sealed.json")
            self.assertEqual(main(["seal", SECRET, "--key", base + ".sealkey",
                                   "--out", sealed]), 0)
            unsealed = os.path.join(tmp, "secret.json")
            self.assertEqual(main(["unseal", sealed, "--key", base + ".sealkey",
                                   "--out", unsealed]), 0)

    def test_no_command_exits_2(self):
        self.assertEqual(main([]), 2)


if __name__ == "__main__":
    unittest.main()
