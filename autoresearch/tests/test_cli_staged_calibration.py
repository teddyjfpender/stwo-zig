import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "autoresearch" / "cli"))

from stwo_perf import __main__ as cli, runner  # noqa: E402


class StagedCalibrationCliTest(unittest.TestCase):
    @staticmethod
    def args(**overrides):
        values = {
            "aa": True,
            "board": "riscv",
            "out": None,
            "scope": "s3",
            "workload_class": "small",
            "dimension": "time",
            "guards": "auto",
            "predecessor": None,
            "staged_calibration": True,
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_staged_calibration_is_aa_only(self):
        with mock.patch.object(cli.manifest_mod, "load") as load:
            load.return_value.root = Path.cwd()
            self.assertEqual(cli.cmd_run(self.args(aa=False)), 1)

    def test_staged_calibration_is_restricted_to_staged_boards(self):
        with mock.patch.object(cli.manifest_mod, "load") as load:
            load.return_value.root = Path.cwd()
            self.assertEqual(cli.cmd_run(self.args(board="core_cpu")), 1)

    def test_cuda_staged_calibration_uses_disabled_board_path(self):
        receipt = {
            "workload_class": "wide",
            "board": "core_cuda",
            "workload": "cuda_wf_log18x37",
            "rounds": 7,
            "aa_r": 1.0,
            "half_width": 0.01,
            "dispersion": 0.012,
            "anchor_prove_ms": 8.0,
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock = root / "judge.lock"
            lock.write_text("held")
            manifest = SimpleNamespace(root=root)
            with (
                mock.patch.object(cli.manifest_mod, "load", return_value=manifest),
                mock.patch.object(
                    runner, "acquire_judge_lock", return_value=lock
                ),
                mock.patch.object(
                    runner, "evaluate_aa", return_value=receipt
                ) as evaluate,
            ):
                self.assertEqual(
                    cli.cmd_run(self.args(board="core_cuda")),
                    0,
                )
            self.assertTrue(evaluate.call_args.kwargs["allow_staged"])
            self.assertEqual(
                evaluate.call_args.kwargs["board"],
                "core_cuda",
            )

    def test_writes_reviewable_calibration_receipt(self):
        receipt = {
            "workload_class": "small",
            "board": "riscv",
            "workload": "portfolio[2]",
            "rounds": 3,
            "aa_r": 1.0,
            "half_width": 0.01,
            "dispersion": 0.012,
            "anchor_prove_ms": 12.5,
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "calibration.json"
            lock = root / "judge.lock"
            lock.write_text("held")
            manifest = SimpleNamespace(root=root)
            with (
                mock.patch.object(cli.manifest_mod, "load", return_value=manifest),
                mock.patch.object(
                    runner, "acquire_judge_lock", return_value=lock
                ) as acquire_lock,
                mock.patch.object(runner, "evaluate_aa", return_value=receipt) as evaluate,
            ):
                self.assertEqual(cli.cmd_run(self.args(out=str(out))), 0)
            self.assertEqual(json.loads(out.read_text()), receipt)
            acquire_lock.assert_called_once_with(root)
            self.assertFalse(lock.exists())
            self.assertTrue(evaluate.call_args.kwargs["allow_staged"])


if __name__ == "__main__":
    unittest.main()
