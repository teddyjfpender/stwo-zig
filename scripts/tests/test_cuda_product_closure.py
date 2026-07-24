from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import cuda_product_closure as closure  # noqa: E402


class CudaProductClosureTests(unittest.TestCase):
    def fixture(self, root: Path, *, define_active: bool) -> dict[str, Path]:
        paths = {
            "abi": root / "abi",
            "native": root / "native",
            "source": root / "source",
            "host_authority": root / "host_authority",
            "runtime_stages": root / "runtime" / "stages",
        }
        for path in paths.values():
            path.mkdir(parents=True)
        (paths["abi"] / "stages").mkdir()
        (paths["abi"] / "stages" / "proof.zig").write_text(
            'pub extern "c" fn stwo_active() callconv(.c) i32;\n',
            encoding="utf-8",
        )
        (paths["runtime_stages"] / "proof.zig").write_text(
            "const launch = abi.stwo_active;\n",
            encoding="utf-8",
        )
        (paths["host_authority"] / "raw.rs").write_text(
            "extern \"C\" {\n    pub fn stwo_active() -> i32;\n}\n",
            encoding="utf-8",
        )
        native_source = 'extern "C" int stwo_active() { return 0; }\n'
        if not define_active:
            native_source = 'extern "C" int stwo_other() { return 0; }\n'
        (paths["native"] / "proof.cu").write_text(native_source, encoding="utf-8")
        return paths

    def policy(self) -> dict[str, object]:
        return {
            "abi": {
                "rust_authority": "raw.rs",
                "generated_symbols": [],
                "zig_owned_symbols": [],
                "staged_stage_modules": [],
                "forbidden_symbol_fragments": ["_legacy_"],
            }
        }

    def ordinary(self) -> dict[str, object]:
        return {
            "product_sources": [],
            "resident_candidates": [],
        }

    def validate_fixture(
        self,
        paths: dict[str, Path],
    ) -> dict[str, int]:
        with mock.patch.multiple(
            closure,
            ABI=paths["abi"],
            NATIVE=paths["native"],
            SOURCE=paths["source"],
            HOST_AUTHORITY=paths["host_authority"],
            RUNTIME_STAGES=paths["runtime_stages"],
        ):
            return closure.validate_abi(self.policy(), self.ordinary())

    def test_zero_staged_modules_is_valid_when_every_symbol_is_implemented(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.fixture(Path(temporary), define_active=True)
            result = self.validate_fixture(paths)
        self.assertEqual(1, result["active_symbols"])
        self.assertEqual(0, result["staged_symbols"])
        self.assertEqual(1, result["wrapped_stage_symbols"])

    def test_zero_staged_modules_rejects_an_unimplemented_active_symbol(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.fixture(Path(temporary), define_active=False)
            with self.assertRaisesRegex(
                closure.ProductClosureError,
                "no selected implementation.*stwo_active",
            ):
                self.validate_fixture(paths)


if __name__ == "__main__":
    unittest.main()
