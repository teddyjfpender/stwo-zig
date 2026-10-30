"""CPU semantic gate for actual CUDA body; deliberately not a GPU benchmark."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class NativeAccessBatchInverseTest(unittest.TestCase):
    def test_actual_row_body_against_scalar_inverse(self):
        compiler = shutil.which("clang++")
        if compiler is None:
            self.skipTest("clang++ required for the CUDA-body host arithmetic gate")
        with tempfile.TemporaryDirectory(prefix="native-access-inverse-") as temporary:
            directory = Path(temporary)
            # The arithmetic header only needs CUDA declaration annotations.
            # Host invocation does not simulate CUDA scheduling or performance.
            (directory / "cuda_runtime_api.h").write_text("#pragma once\n")
            executable = directory / "gate"
            subprocess.run([
                compiler, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                "-I", str(directory),
                str(ROOT / "src/integrations/riscv_cuda/tests/resident_native_access_batch_inverse_test.cpp"),
                "-o", str(executable),
            ], check=True, cwd=ROOT, timeout=60)
            result = subprocess.run([str(executable)], check=True, text=True,
                                    capture_output=True, timeout=60)
            self.assertIn("PASS 950 access fraction cases", result.stdout)


if __name__ == "__main__":
    unittest.main()
