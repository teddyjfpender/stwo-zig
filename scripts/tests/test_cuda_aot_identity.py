from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from cuda_build_lib.aot_identity import source_closure_identity  # noqa: E402
from cuda_build_lib.builder import BuildError, validate_aot_manifest  # noqa: E402


NATIVE_AOT = ROOT / "src/backends/cuda/aot/native"


class CudaAotIdentityTests(unittest.TestCase):
    def test_native_aot_closure_identity_binds_headers_not_entry_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cuda_root = Path(temporary) / "cuda"
            native_aot = cuda_root / "aot/native"
            native_headers = cuda_root / "native/transcript"
            native_aot.mkdir(parents=True)
            native_headers.mkdir(parents=True)
            header = native_headers / "state.cuh"
            header.write_text("#define STATE_WORDS 14\n", encoding="utf-8")
            source_a = native_aot / "statement_aaaaaaaaaaaaaaaa.cu"
            source_b = native_aot / "statement_bbbbbbbbbbbbbbbb.cu"
            source_bytes = '#include "../../native/transcript/state.cuh"\n'
            source_a.write_text(source_bytes, encoding="utf-8")
            source_b.write_text(source_bytes, encoding="utf-8")

            before = source_closure_identity(native_aot, source_a)
            self.assertEqual(
                before,
                source_closure_identity(native_aot, source_b),
            )
            header.write_text("#define STATE_WORDS 15\n", encoding="utf-8")
            after = source_closure_identity(native_aot, source_a)

        self.assertNotEqual(before, after)

    def test_native_aot_identity_rejects_source_or_contract_drift(self) -> None:
        manifest = json.loads(
            (NATIVE_AOT / "aot_manifest.json").read_text(encoding="utf-8")
        )
        entry = next(item for item in manifest if item["label"] == "constant_qm31")
        isolated = [entry]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = NATIVE_AOT / entry["file"]
            shutil.copy2(source, root / source.name)
            validate_aot_manifest(root, isolated)

            (root / source.name).write_bytes(source.read_bytes() + b"\\n")
            with self.assertRaisesRegex(BuildError, "stale Native identities"):
                validate_aot_manifest(root, isolated)

            shutil.copy2(source, root / source.name)
            changed = json.loads(json.dumps(isolated))
            changed[0]["semantic_contract"] += ";changed"
            with self.assertRaisesRegex(BuildError, "stale Native identities"):
                validate_aot_manifest(root, changed)

    def test_recorded_witness_identity_rejects_source_and_cache_drift(self) -> None:
        manifest = json.loads(
            (NATIVE_AOT / "aot_manifest.json").read_text(encoding="utf-8")
        )
        entry = next(item for item in manifest if item["label"] == "add_ap_opcode")
        self.assertEqual("recorded_witness_v1", entry["abi_schema"])
        self.assertEqual(
            "sha256-source-and-blake3-program-v1",
            entry["identity_scheme"],
        )
        isolated = [entry]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = NATIVE_AOT / entry["file"]
            shutil.copy2(source, root / source.name)
            validate_aot_manifest(root, isolated)

            (root / source.name).write_bytes(source.read_bytes() + b"\n")
            with self.assertRaisesRegex(
                BuildError,
                "stale recorded-witness identities",
            ):
                validate_aot_manifest(root, isolated)

            shutil.copy2(source, root / source.name)
            changed = json.loads(json.dumps(isolated))
            changed[0]["kernel_name"] = "stwo_jit_witness_0000000000000001"
            with self.assertRaisesRegex(
                BuildError,
                "stale recorded-witness identities",
            ):
                validate_aot_manifest(root, changed)


if __name__ == "__main__":
    unittest.main()
