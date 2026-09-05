from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch/benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_stwo_ab_comparison as subject  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


class StwoAbComparisonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.files: dict[str, Path] = {}
        for name in ("input", "baseline-bin", "candidate-bin", "verifier",
                     "baseline-proof", "candidate-proof"):
            path = self.root / name
            path.write_bytes((name + " bytes").encode("ascii"))
            self.files[name] = path

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def identity(self, name: str) -> dict:
        path = self.files[name]
        raw = path.read_bytes()
        return {"path": str(path.absolute()), "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest()}

    def timing(self, wall: int) -> dict:
        return {"wall_ns": wall, "user_ns": wall * 2, "system_ns": wall // 10}

    def trial(self, arm: str, scale: int) -> dict:
        stages = {
            "execution": self.timing(10 * scale),
            "witness_generation": self.timing(20 * scale),
            "proving": self.timing(60 * scale),
            "fresh_verification": self.timing(10 * scale),
        }
        total = {
            field: sum(item[field] for item in stages.values())
            for field in ("wall_ns", "user_ns", "system_ns")
        }
        output = {"bytes": 43, "sha256": digest("output"), "framing": "fixture-v1"}
        return protocol.seal({
            "schema": subject.TRIAL_SCHEMA,
            "arm": arm,
            "status": "fresh-verified-complete",
            "workload": {
                "chain_id": 1,
                "block_number": 24628607,
                "block_hash": digest("block"),
                "input": self.identity("input"),
                "expected_output": output,
                "expected_final_state_sha256": digest("state"),
                "execution_profile": "rv32im-zkvm-ethereum-v1",
                "statement_sha256": digest("statement"),
            },
            "subject": {
                "source": {
                    "commit": "1" * 40,
                    "tree": ("2" if arm == "baseline" else "3") * 40,
                    "dirty": False,
                    "dirty_content_sha256": None,
                },
                "executable": self.identity(f"{arm}-bin"),
                "build_mode": "ReleaseFast",
                "feature_flags": [] if arm == "baseline" else ["bulk-memcpy", "d5-provider"],
                "production_admitted": True,
                "process_count": 4,
                "thread_count": 16,
                "engine_workers": 16,
                "provider_topology": "4x4" if arm == "candidate" else "baseline-4x4",
                "coefficient_retention": "always" if arm == "candidate" else "never",
            },
            "host": {
                "machine_model": "Mac17,7",
                "cpu_model": "Apple M5 Max",
                "memory_bytes": 68_719_476_736,
                "operating_system": "macOS 26.6.2",
                "power_source": "AC Power",
                "thermal_state": "nominal",
                "interference_observed": False,
            },
            "stages": stages,
            "total": total,
            "peak_rss_bytes": 10_000 * scale,
            "proof": {
                "identity": self.identity(f"{arm}-proof"),
                "statement_sha256": digest("statement"),
                "root_sha256": digest(f"{arm} proof root"),
                "security_identity_sha256": digest("security"),
                "conservative_security_bits": 120,
                "canonical_decode": True,
                "roundtrip_exact": True,
            },
            "correctness": {
                "semantic_output": output,
                "final_state_sha256": digest("state"),
                "public_statement_sha256": digest("statement"),
                "expected_output_matched": True,
                "expected_final_state_matched": True,
                "fresh_verified": True,
                "verifier_executable": self.identity("verifier"),
            },
            "attempt_custody": {
                "attempt_count": 1,
                "successful_attempt_index": 0,
                "failed_count": 0,
                "indeterminate_count": 0,
                "terminal_error": None,
            },
            "eligible": True,
        })

    def publish_trial(self, name: str, value: dict) -> Path:
        path = self.root / f"{name}.json"
        path.write_bytes(protocol.canonical_bytes(value))
        return path

    def test_exact_20x_candidate_meets_95_percent_target_and_replays(self) -> None:
        baseline = self.publish_trial("baseline", self.trial("baseline", 20))
        candidate = self.publish_trial("candidate", self.trial("candidate", 1))
        result = subject.build_comparison(baseline, candidate)
        self.assertTrue(result["target"]["met"])
        self.assertEqual(950_000, result["metrics"]["total_wall"]["reduction_ppm"])
        self.assertNotEqual(
            result["correctness"]["baseline_proof_root_sha256"],
            result["correctness"]["candidate_proof_root_sha256"],
        )
        output = self.root / "comparison.json"
        output.write_bytes(protocol.canonical_bytes(result))
        self.assertEqual(result, subject.load_comparison(output))

    def test_invalid_statement_attempt_cannot_be_a_baseline(self) -> None:
        value = self.trial("baseline", 20)
        value["attempt_custody"]["failed_count"] = 1
        value["attempt_custody"]["terminal_error"] = "InvalidStatement"
        value["eligible"] = False
        value = protocol.seal({key: item for key, item in value.items()
                               if key != "content_sha256"})
        with self.assertRaises(subject.StwoComparisonError):
            subject.build_comparison(
                self.publish_trial("invalid", value),
                self.publish_trial("candidate", self.trial("candidate", 1)),
            )

    def test_output_host_security_and_timing_mutations_reject(self) -> None:
        baseline_value = self.trial("baseline", 20)
        candidate_value = self.trial("candidate", 1)
        cases = []
        changed = copy.deepcopy(candidate_value)
        changed["correctness"]["semantic_output"]["sha256"] = digest("wrong")
        cases.append(changed)
        changed = copy.deepcopy(candidate_value)
        changed["host"]["power_source"] = "Battery Power"
        cases.append(changed)
        changed = copy.deepcopy(candidate_value)
        changed["proof"]["security_identity_sha256"] = digest("other security")
        cases.append(changed)
        changed = copy.deepcopy(candidate_value)
        changed["total"]["wall_ns"] += 1
        cases.append(changed)
        baseline = self.publish_trial("baseline", baseline_value)
        for index, changed in enumerate(cases):
            changed = protocol.seal({key: item for key, item in changed.items()
                                     if key != "content_sha256"})
            with self.assertRaises(subject.StwoComparisonError, msg=f"case {index}"):
                subject.build_comparison(
                    baseline, self.publish_trial(f"candidate-{index}", changed),
                )


if __name__ == "__main__":
    unittest.main()
