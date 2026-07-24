from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = (
    ROOT / "conformance/evidence/cuda/system-architecture-sm89"
)


class CudaStructuralEvidenceTests(unittest.TestCase):
    def test_receipt_is_bound_to_the_retained_structural_report(self) -> None:
        report_bytes = (EVIDENCE / "structural-screen.json").read_bytes()
        report = json.loads(report_bytes)
        receipt = json.loads((EVIDENCE / "receipt.json").read_bytes())

        self.assertEqual(
            receipt["controller"]["report_sha256"],
            hashlib.sha256(report_bytes).hexdigest(),
        )
        self.assertEqual(
            receipt["controller"]["commit"],
            report["provenance"]["repository_commit"],
        )
        self.assertFalse(report["provenance"]["repository_dirty"])
        self.assertFalse(receipt["headline_eligible"])
        self.assertFalse(receipt["activation_eligible"])
        self.assertFalse(report["headline_eligible"])
        self.assertFalse(report["coverage"]["activation_ready"])

        binary = report["provenance"]["binaries"]["candidate"]
        self.assertEqual(
            receipt["product"]["binary_sha256"],
            binary["sha256"],
        )
        self.assertEqual(receipt["device"]["sm"], 89)
        self.assertEqual(
            receipt["device"]["uuid"].removeprefix("GPU-").replace("-", ""),
            report["workloads"][0]["proof_gate"]["device"]["uuid"],
        )

    def test_receipt_rows_match_report_and_remain_fail_closed(self) -> None:
        report = json.loads(
            (EVIDENCE / "structural-screen.json").read_bytes()
        )
        receipt = json.loads((EVIDENCE / "receipt.json").read_bytes())
        retained = {
            workload["id"]: workload
            for workload in receipt["workloads"]
        }
        self.assertEqual(
            set(retained),
            {workload["workload_id"] for workload in report["workloads"]},
        )

        identities = set()
        for workload in report["workloads"]:
            row = retained[workload["workload_id"]]
            gate = workload["proof_gate"]
            metrics = workload["sessions"][0]["metrics"]
            mechanism = metrics["mechanism"]
            identities.add(
                json.dumps(
                    gate["product_identities"]["candidate"],
                    sort_keys=True,
                )
            )
            self.assertEqual(row["proof_sha256"], gate["canonical_sha256"])
            self.assertEqual(row["proof_bytes"], gate["canonical_bytes"])
            self.assertEqual(
                row["artifact_sha256"],
                metrics["proof"]["artifact_sha256"],
            )
            self.assertEqual(row["kernel_launches"], mechanism["kernel_launches"])
            self.assertEqual(row["peak_device_bytes"], mechanism["peak_live_bytes"])
            self.assertEqual(mechanism["cpu_fallbacks_completed"], 0)
            self.assertEqual(mechanism["terminal_d2h_operations"], 1)
            self.assertEqual(mechanism["graph_launches"], 0)
            self.assertEqual(mechanism["sync_calls"], 1)
            self.assertAlmostEqual(
                row["steady_verified_ms"],
                metrics["steady"]["verified_ms"]["median"],
            )
            self.assertAlmostEqual(
                row["steady_resident_ms"],
                metrics["steady"]["resident_ms"]["median"],
            )
            self.assertAlmostEqual(
                row["resident_row_mhz"],
                metrics["steady"]["resident_row_mhz"],
                places=5,
            )

        self.assertEqual(len(identities), 1)
        identity = json.loads(next(iter(identities)))
        self.assertEqual(
            receipt["product"]["commit"],
            identity["implementation_commit"],
        )
        self.assertEqual(
            receipt["product"]["tree"],
            identity["implementation_tree"],
        )
        self.assertEqual(
            receipt["product"]["identity_sha256"],
            identity["identity_sha256"],
        )
        self.assertFalse(identity["implementation_dirty"])
        self.assertTrue(receipt["oracle"]["all_accepted"])
        self.assertEqual(receipt["oracle"]["artifacts_accepted"], 6)


if __name__ == "__main__":
    unittest.main()
