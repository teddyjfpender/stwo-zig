from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import cuda_external_authority as external

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

    def test_external_projection_verifies_host_and_kernel_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "authority"
            kernel = root / external.KERNEL_SUBTREE
            kernel.mkdir(parents=True)
            (root / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
            (kernel / "kernel.cu").write_text(
                "__global__ void k() {}\n",
                encoding="utf-8",
            )
            host_manifest = Path(temporary) / "host.json"
            kernel_manifest = Path(temporary) / "kernel.json"
            host_value = external.closure(root)
            host_value.update({"authority": "host", "upstream": {"fixture": "host"}})
            kernel_value = external.closure(kernel)
            kernel_value.update(
                {"authority": "kernels", "upstream": {"fixture": "kernel"}}
            )
            for path, value in (
                (host_manifest, host_value),
                (kernel_manifest, kernel_value),
            ):
                value["schema"] = "stwo-zig-cuda-source-closure-v1"
                path.write_text(json.dumps(value), encoding="utf-8")
            pin_fields = (
                "authority",
                "file_count",
                "byte_count",
                "closure_sha256",
                "upstream",
            )
            with mock.patch.multiple(
                external,
                HOST_MANIFEST=host_manifest,
                KERNEL_MANIFEST=kernel_manifest,
                HOST_MANIFEST_SHA256=hashlib.sha256(
                    host_manifest.read_bytes()
                ).hexdigest(),
                KERNEL_MANIFEST_SHA256=hashlib.sha256(
                    kernel_manifest.read_bytes()
                ).hexdigest(),
                HOST_PIN={key: host_value[key] for key in pin_fields},
                KERNEL_PIN={key: kernel_value[key] for key in pin_fields},
            ):
                receipt = external.verify_projection(root)
                self.assertEqual(2, receipt["host_file_count"])
                self.assertEqual(1, receipt["kernel_file_count"])
                (kernel / "kernel.cu").write_text("changed\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    external.AuthorityError,
                    "kernel authority differs|host authority differs",
                ):
                    external.verify_projection(root)

    def test_native_relation_owns_id_free_projected_tuple_extension(self) -> None:
        native = (CUDA / "native" / "relation" / "layout.cuh").read_text(
            encoding="utf-8"
        )
        authority = (
            CUDA
            / "authority/active/relation_fused.cuh"
        ).read_text(encoding="utf-8")
        self.assertIn("if (kind == 8u || kind == 9u)", native)
        self.assertIn("sources[argument + word][row]", native)
        self.assertNotIn("ProjectedColumnsNoId", authority)


if __name__ == "__main__":
    unittest.main()
