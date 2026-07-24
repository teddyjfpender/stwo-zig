import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli"))
from stwo_perf import __main__ as cli
from stwo_perf import runner


class CudaStagingTests(unittest.TestCase):
    def test_cuda_backend_diff_routes_to_disabled_cuda_board(self):
        args = SimpleNamespace(board=None)
        manifest = SimpleNamespace(root=Path("/repo"))
        with mock.patch.object(
            runner,
            "changed_paths",
            return_value=["src/backends/cuda/runtime/session.zig"],
        ):
            self.assertEqual(cli._resolve_board(args, manifest), "core_cuda")

    def test_native_cuda_integration_diff_routes_to_cuda_board(self):
        args = SimpleNamespace(board=None)
        manifest = SimpleNamespace(root=Path("/repo"))
        with mock.patch.object(
            runner,
            "changed_paths",
            return_value=["src/integrations/native_cuda/wide_fibonacci/mod.zig"],
        ):
            self.assertEqual(cli._resolve_board(args, manifest), "core_cuda")

    def test_explicit_board_still_wins(self):
        args = SimpleNamespace(board="core_cpu")
        manifest = SimpleNamespace(root=Path("/repo"))
        with mock.patch.object(runner, "changed_paths") as changed:
            self.assertEqual(cli._resolve_board(args, manifest), "core_cpu")
            changed.assert_not_called()


if __name__ == "__main__":
    unittest.main()
