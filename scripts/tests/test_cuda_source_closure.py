from __future__ import annotations

import unittest
from pathlib import Path

from scripts.cuda_source_closure import (
    AUTHORITIES,
    build_manifest,
    validate_expected_closure,
)


ROOT = Path(__file__).resolve().parents[2]
CUDA = ROOT / "src" / "backends" / "cuda"


class CudaSourceClosureTests(unittest.TestCase):
    def test_declared_authorities_match_immutable_closure_pins(self) -> None:
        for authority in AUTHORITIES:
            with self.subTest(authority=authority["name"]):
                validate_expected_closure(
                    authority,
                    build_manifest(authority),
                )

    def test_manifest_rewrite_cannot_repin_edited_vendor_bytes(self) -> None:
        authority = {
            "name": "fixture",
            "expected_closure": {
                "file_count": 2,
                "byte_count": 19,
                "closure_sha256": "ab" * 32,
            },
        }
        exact = {
            "file_count": 2,
            "byte_count": 19,
            "closure_sha256": "ab" * 32,
        }
        validate_expected_closure(authority, exact)
        for field, drift in (
            ("file_count", 3),
            ("byte_count", 20),
            ("closure_sha256", "cd" * 32),
        ):
            edited = dict(exact)
            edited[field] = drift
            with self.subTest(field=field), self.assertRaisesRegex(
                SystemExit,
                "differs from the closure pinned",
            ):
                validate_expected_closure(authority, edited)

    def test_native_relation_owns_id_free_projected_tuple_extension(self) -> None:
        native = (CUDA / "native" / "relation" / "layout.cuh").read_text(
            encoding="utf-8"
        )
        authority = (CUDA / "vendor" / "upstream" / "relation_fused.cuh").read_text(
            encoding="utf-8"
        )
        self.assertIn("if (kind == 8u || kind == 9u)", native)
        self.assertIn("sources[argument + word][row]", native)
        self.assertNotIn("ProjectedColumnsNoId", authority)


if __name__ == "__main__":
    unittest.main()
