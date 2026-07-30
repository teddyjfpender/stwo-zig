import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "autoresearch" / "cli"))

from stwo_perf.manifest import Manifest  # noqa: E402
from stwo_perf import qualification  # noqa: E402


def git(repo, *args):
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True,
    ).stdout.strip()


class QualificationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        git(self.repo, "init")
        git(self.repo, "config", "user.name", "Test")
        git(self.repo, "config", "user.email", "test@example.test")
        (self.repo / "src/core/fields").mkdir(parents=True)
        (self.repo / "src/frontends/riscv").mkdir(parents=True)
        (self.repo / "autoresearch").mkdir()
        (self.repo / "src/core/fields/value.zig").write_text("const value = 1;\n")
        (self.repo / "src/frontends/riscv/value.zig").write_text("const value = 1;\n")
        (self.repo / "autoresearch/policy.txt").write_text("locked\n")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-m", "frontier")
        self.frontier = git(self.repo, "rev-parse", "HEAD")
        self.manifest = Manifest(self.repo, {
            "editable_paths": [{"glob": "src/core/fields/**", "min_rung": "s3"}],
            "locked_paths": ["autoresearch/**"],
            "workload_registry": {
                "classes": {
                    "small": {
                        "scored": True,
                        "resource": {
                            "profile": "standard",
                            "command_timeout_seconds": 60,
                            "wall_clock_cap_seconds": 60,
                        },
                        "sampling": {
                            "warmups": 1, "samples_per_round": 1,
                            "min_rounds": 1, "max_rounds": 1,
                        },
                    },
                },
                "groups": {
                    "native": {
                        "enabled": True, "promotion_eligible": True,
                        "board": "core_cpu", "build_step": "true",
                        "binary": "bin/bench", "report_schema": "native_proof_v6",
                        "workloads": {
                            "wf": {"class": "small", "args": "--x", "native_unit": "rows"},
                        },
                    },
                    "riscv": {
                        "enabled": True, "promotion_eligible": True,
                        "board": "riscv", "build_step": "true",
                        "binary": "bin/riscv", "report_schema": "riscv_proof_v2",
                        "editable_paths": [
                            {"glob": "src/frontends/riscv/**", "min_rung": "s3"},
                        ],
                        "workloads": {
                            "rv": {"class": "small", "args": "--x", "native_unit": "rows"},
                        },
                    },
                },
            },
        })

    def tearDown(self):
        self.tmp.cleanup()

    def _commit_edit(self):
        (self.repo / "src/core/fields/value.zig").write_text("const value = 2;\n")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-m", "candidate")

    def test_receipt_roundtrip_recomputes_git_evidence(self):
        self._commit_edit()
        claim = {"board": "core_cpu", "workload_class": "small",
                 "dimension": "time", "shipping_index": 0.9}
        receipt = qualification.build_receipt(
            self.repo, self.manifest, self.frontier, "alice",
            {name: True for name in qualification.REQUIRED_CHECKS}, claim,
        )
        evidence = qualification.verify_receipt(self.repo, self.manifest, receipt)
        self.assertEqual(evidence.candidate_tree, receipt["candidate_tree"])
        self.assertEqual(receipt["changed_paths"], ["src/core/fields/value.zig"])

    def test_locked_change_is_rejected(self):
        (self.repo / "autoresearch/policy.txt").write_text("tampered\n")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-m", "bad")
        with self.assertRaises(qualification.QualificationError):
            qualification.inspect_tree(self.repo, self.manifest, self.frontier)

    def test_executable_editable_file_is_rejected(self):
        self._commit_edit()
        path = self.repo / "src/core/fields/value.zig"
        path.chmod(0o755)
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-m", "mode")
        with self.assertRaises(qualification.QualificationError):
            qualification.inspect_tree(self.repo, self.manifest, self.frontier)

    def test_patch_size_policy_is_enforced_before_central_build(self):
        self._commit_edit()
        limited = Manifest(self.repo, {
            **self.manifest.raw,
            "qualification_policy": {"max_changed_paths": 100, "max_patch_bytes": 1},
        })
        with self.assertRaisesRegex(qualification.QualificationError, "patch is"):
            qualification.inspect_tree(self.repo, limited, self.frontier)

    def test_board_scoped_frontend_is_allowed_only_for_its_board(self):
        path = self.repo / "src/frontends/riscv/value.zig"
        path.write_text("const value = 2;\n")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-m", "riscv candidate")

        with self.assertRaisesRegex(qualification.QualificationError, "outside"):
            qualification.inspect_tree(self.repo, self.manifest, self.frontier)
        with self.assertRaisesRegex(qualification.QualificationError, "outside"):
            qualification.inspect_tree(
                self.repo,
                self.manifest,
                self.frontier,
                board="core_cpu",
            )
        evidence = qualification.inspect_tree(
            self.repo,
            self.manifest,
            self.frontier,
            board="riscv",
        )
        self.assertEqual(evidence.changed_paths, ["src/frontends/riscv/value.zig"])

        claim = {
            "board": "riscv",
            "workload_class": "small",
            "dimension": "time",
            "shipping_index": 0.9,
        }
        receipt = qualification.build_receipt(
            self.repo,
            self.manifest,
            self.frontier,
            "alice",
            {name: True for name in qualification.REQUIRED_CHECKS},
            claim,
        )
        verified = qualification.verify_receipt(self.repo, self.manifest, receipt)
        self.assertEqual(verified.changed_paths, evidence.changed_paths)

        with self.assertRaisesRegex(
            qualification.QualificationError,
            "source-policy board does not match",
        ):
            qualification.build_receipt(
                self.repo,
                self.manifest,
                self.frontier,
                "alice",
                {name: True for name in qualification.REQUIRED_CHECKS},
                claim,
                board="core_cpu",
            )


if __name__ == "__main__":
    unittest.main()
