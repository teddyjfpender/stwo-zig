"""Authentication and parser rejection checks for the mainnet importer."""

import importlib.util
import json
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "mainnet", Path(__file__).parents[1] / "mainnet.py"
)
mainnet = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mainnet)


class MainnetImportTests(unittest.TestCase):
    def test_valid_preimage(self):
        key = mainnet.digest(b"hello")
        self.assertEqual(
            mainnet.preimages(json.dumps({key: b"hello".hex()})),
            [(key, b"hello".hex())],
        )

    def test_authentication(self):
        with self.assertRaisesRegex(ValueError, "authentication"):
            mainnet.preimages(json.dumps({"0" * 64: "01"}))

    def test_duplicate_key(self):
        key = mainnet.digest(b"hello")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            mainnet.preimages('{"' + key + '":"68656c6c6f","' + key + '":"68656c6c6f"}')

    def test_normalized_duplicate(self):
        # Find a leading-zero digest so both spellings authenticate individually.
        for n in range(10000):
            value = n.to_bytes(4, "big")
            key = mainnet.digest(value)
            if key.startswith("0"):
                break
        with self.assertRaisesRegex(ValueError, "duplicate"):
            mainnet.preimages(
                json.dumps({key: value.hex(), key.lstrip("0"): value.hex()})
            )

    def test_size_and_identity(self):
        with self.assertRaisesRegex(ValueError, "identity"):
            mainnet.checked(b"wrong", {"bytes": 5, "sha256": "0" * 64})
        with self.assertRaisesRegex(ValueError, "size"):
            mainnet.preimages("{}")

    def test_missing_source_section(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            mainnet.replay("fn unrelated() {}", 120794432)


if __name__ == "__main__":
    unittest.main()
