"""Policy regression checks using genuine retained CPU/Metal reports."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest

from scripts import riscv_csp_paired_benchmark as rerun


# Historical reports remain in place; moving the runner needs no artifact copy.
EVIDENCE = rerun.ROOT / "autoresearch/notes/2026-09-05-pr198-local-ethereum-plan/evidence"


class ReportAdmissionTest(unittest.TestCase):
    def test_command_imports_from_outside_the_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [sys.executable, str(rerun.ROOT / "scripts/riscv_csp_paired_benchmark.py"), "--help"],
                cwd=directory, capture_output=True, text=True, check=True,
            )
        self.assertIn("--baseline", completed.stdout)
        self.assertIn("--current", completed.stdout)

    def test_cpu_and_metal_reject_changed_csp_policy_and_custody(self):
        case = rerun.contract.canonical_workloads()[0]
        settings = {"workers": 16, "warmups": 1, "samples": 1}
        for backend in ("cpu", "metal"):
            path = EVIDENCE / f"{backend}-v2-full16.json"
            report = json.loads(path.read_text())
            report["measurements"] = report["measurements"][:1]
            head = report["repository_head"]
            rerun.checked_row(report, backend, head, case, settings)
            for target, key, value in (
                ("run", "workers", 8),
                ("run", "recursion_enabled", True),
                ("row", "protocol", {"name": "test"}),
                ("row", "uses_precompile", True),
                ("row", "peak_memory", 0),
                ("receipt", "implementation_commit", "0" * 40),
                ("receipt", "implementation_dirty", True),
                ("receipt", "status", "unverified"),
            ):
                with self.subTest(backend=backend, target=target, key=key):
                    changed = copy.deepcopy(report)
                    locations = {"run": changed["run"], "row": changed["measurements"][0],
                                 "receipt": changed["measurements"][0]["evidence"]["retained_verify_receipt"]}
                    locations[target][key] = value
                    with self.assertRaises(rerun.contract.ABError):
                        rerun.checked_row(changed, backend, head, case, settings)
            if backend == "metal":
                report["measurements"][0]["evidence"]["resident_polynomial_telemetry"]["declines"] = 1
                with self.assertRaises(rerun.contract.ABError):
                    rerun.checked_row(report, backend, head, case, settings)


if __name__ == "__main__":
    unittest.main()
