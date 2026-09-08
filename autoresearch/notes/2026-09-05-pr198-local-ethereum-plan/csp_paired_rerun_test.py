"""Run with python3 from any directory; uses retained diagnostic evidence."""
import copy
import json
from pathlib import Path
import unittest

import csp_paired_rerun as rerun


class ReportAdmissionTest(unittest.TestCase):
    def test_cpu_and_metal_reject_changed_csp_policy_and_custody(self):
        case = rerun.contract.canonical_workloads()[0]
        settings = {"workers": 16, "warmups": 1, "samples": 1}
        for backend in ("cpu", "metal"):
            path = Path(__file__).with_name("evidence") / f"{backend}-v2-full16.json"
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
