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

    def test_staged_calibration_is_riscv_only(self):
        with mock.patch.object(cli.manifest_mod, "load") as load:
            load.return_value.root = Path.cwd()
            self.assertEqual(cli.cmd_run(self.args(board="core_cpu")), 1)

    def test_writes_reviewable_calibration_receipt(self):
        receipt = {
            "workload_class": "small",
            "board": "riscv",
            "workload": "portfolio[2]",
            "rounds": 3,
            "aa_r": 1.0,
            "half_width": 0.01,
            "anchor_prove_ms": 12.5,
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "calibration.json"
            manifest = SimpleNamespace(root=root)
            with (
                mock.patch.object(cli.manifest_mod, "load", return_value=manifest),
                mock.patch.object(runner, "evaluate_aa", return_value=receipt) as evaluate,
            ):
                self.assertEqual(cli.cmd_run(self.args(out=str(out))), 0)
            self.assertEqual(json.loads(out.read_text()), receipt)
            self.assertTrue(evaluate.call_args.kwargs["allow_staged"])


if __name__ == "__main__":
    unittest.main()
