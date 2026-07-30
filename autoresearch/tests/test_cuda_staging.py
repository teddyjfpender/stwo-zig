import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from stwo_perf import __main__ as cli
from stwo_perf import manifest as manifest_mod
from stwo_perf import runner


class CudaStagingTests(unittest.TestCase):
    # TRACKS §8 routing resolves the board from the manifest's own group list,
    # so these use the repository manifest rather than a bare namespace.
    @classmethod
    def setUpClass(cls):
        cls.manifest = manifest_mod.load(Path(__file__).resolve().parents[2])

    def test_cuda_backend_diff_routes_to_disabled_cuda_board(self):
        args = SimpleNamespace(board=None)
        with mock.patch.object(
            runner,
            "changed_paths",
            return_value=["src/backends/cuda/runtime/session.zig"],
        ):
            self.assertEqual(cli._resolve_board(args, self.manifest), "core_cuda")

    def test_native_cuda_integration_diff_routes_to_cuda_board(self):
        args = SimpleNamespace(board=None)
        with mock.patch.object(
            runner,
            "changed_paths",
            return_value=["src/integrations/native_cuda/wide_fibonacci/mod.zig"],
        ):
            self.assertEqual(cli._resolve_board(args, self.manifest), "core_cuda")

    def test_explicit_board_still_wins(self):
        args = SimpleNamespace(board="core_cpu")
        with mock.patch.object(runner, "changed_paths") as changed:
            self.assertEqual(cli._resolve_board(args, self.manifest), "core_cpu")
            changed.assert_not_called()


if __name__ == "__main__":
    unittest.main()
