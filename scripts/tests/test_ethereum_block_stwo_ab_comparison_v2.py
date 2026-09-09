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

import ethereum_block_stwo_ab_comparison_v2 as subject  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


class StwoAbComparisonV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.files: dict[str, Path] = {}
        for name in (
            "input", "baseline-bin", "candidate-bin", "verifier", "baseline-elf",
            "candidate-elf", "baseline-source", "candidate-source", "baseline-proof",
            "candidate-proof", "baseline-verify", "candidate-verify",
        ):
            path = self.root / name
            path.write_bytes((name + " bytes").encode("ascii"))
            self.files[name] = path

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def identity(self, name: str) -> dict:
        path = self.files[name]
        raw = path.read_bytes()
        return {
            "path": str(path.absolute()),
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }

    @staticmethod
    def timing(wall: int) -> dict:
        return {"wall_ns": wall, "user_ns": wall * 2, "system_ns": wall // 10}

    def trial(self, arm: str, scale: int, position: int) -> dict:
        stages = {
            "execution": self.timing(10 * scale),
            "witness_generation": self.timing(20 * scale),
            "proving": self.timing(60 * scale),
            "proof_serialization": self.timing(5 * scale),
            "fresh_verification": self.timing(5 * scale),
        }
        measured = sum(item["wall_ns"] for item in stages.values())
        output = {"bytes": 43, "sha256": digest("output"), "framing": "fixture-v1"}
        program = digest(f"{arm} program")
        proved_statement = digest(f"{arm} proved statement")
        vm_final = digest(f"{arm} VM final state")
        source_name = f"{arm}-source"
        benchmark = {
            "chain_id": 1,
            "block_number": 24628607,
            "block_hash": digest("block"),
            "block_state_root": digest("post-state"),
            "input": self.identity("input"),
            "input_framing": "stwo-request-v2",
            "expected_output": output,
            "benchmark_statement_sha256": "",
            "security_identity_sha256": digest("security"),
            "minimum_security_bits": 120,
        }
        benchmark["benchmark_statement_sha256"] = subject.semantic_statement_sha256(
            benchmark,
        )
        return protocol.seal({
            "schema": subject.TRIAL_SCHEMA,
            "arm": arm,
            "status": "cold-fresh-verified-complete",
            "benchmark": benchmark,
            "arm_binding": {
                "guest_elf": self.identity(f"{arm}-elf"),
                "source_request": self.identity(source_name),
                "source_request_sha256": self.identity(source_name)["sha256"],
                "declared_program_root_sha256": program,
                "proved_root_statement_sha256": proved_statement,
                "vm_final_state_sha256": vm_final,
            },
            "subject": {
                "source": {
                    "commit": "1" * 40,
                    "tree": ("2" if arm == "baseline" else "3") * 40,
                    "dirty": False,
                    "dirty_content_sha256": None,
                },
                "product_executable": self.identity(f"{arm}-bin"),
                "verifier_executable": self.identity("verifier"),
                "build_mode": "ReleaseFast",
                "feature_flags": [] if arm == "baseline" else [
                    "bulk-memcpy", "d5-provider", "stack-swap",
                ],
                "production_admitted": True,
                "process_count": 4,
                "thread_count": 16,
                "engine_workers": 16,
                "provider_topology": "legacy" if arm == "baseline" else "4x4",
                "coefficient_retention": "never" if arm == "baseline" else "always",
            },
            "host": {
                "machine_model": "Mac17,7",
                "cpu_model": "Apple M5 Max",
                "cpu_logical_cores": 18,
                "memory_bytes": 68_719_476_736,
                "operating_system": "macOS 26.6.2",
                "power_source": "AC Power",
                "power_mode": "high",
                "thermal_state": "nominal",
                "performance_warning": False,
                "interference_observed": False,
            },
            "trial_regime": {
                "session_sha256": digest("comparison session"),
                "pair_position": position,
                "cold_process_start": True,
                "cold_artifact_cache": True,
                "cold_proof_cache": True,
                "timing_scope": "process-launch-through-cold-fresh-verification",
            },
            "resource_budget": {
                "cpu_logical_cores_available": 18,
                "max_processes": 4,
                "max_threads": 16,
                "max_engine_workers": 16,
                "memory_limit_bytes": 68_719_476_736,
                "hard_timeout_seconds": 86_400,
            },
            "stages": stages,
            "total": {
                "wall_ns": measured + 7 * scale,
                "user_ns": sum(item["user_ns"] for item in stages.values()),
                "system_ns": sum(item["system_ns"] for item in stages.values()),
                "measured_stage_wall_ns": measured,
                "unattributed_wall_ns": 7 * scale,
            },
            "peak_rss_bytes": 10_000 * scale,
            "proof": {
                "artifact": self.identity(f"{arm}-proof"),
                "proved_root_statement_sha256": proved_statement,
                "root_sha256": digest(f"{arm} proof root"),
                "security_identity_sha256": digest("security"),
                "conservative_security_bits": 120,
                "codec": {
                    "framing": "postcard-v1",
                    "canonical_decode": True,
                    "roundtrip_exact": True,
                },
                "fresh_verification_receipt": self.identity(f"{arm}-verify"),
                "fresh_verified": True,
                "independent_verifier": True,
            },
            "correctness": {
                "semantic_output": output,
                "block_state_root": digest("post-state"),
                "benchmark_statement_sha256": benchmark["benchmark_statement_sha256"],
                "vm_final_state_sha256": vm_final,
                "expected_output_matched": True,
                "block_state_matched": True,
                "benchmark_statement_matched": True,
                "arm_binding_matched": True,
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

    def publish(self, name: str, value: dict) -> Path:
        path = self.root / f"{name}.json"
        path.write_bytes(protocol.canonical_bytes(value))
        return path

    def reseal(self, value: dict) -> dict:
        return protocol.seal({key: item for key, item in value.items()
                              if key != "content_sha256"})

    def test_exact_20x_accepts_distinct_program_statements_and_vm_states(self) -> None:
        baseline_value = self.trial("baseline", 20, 0)
        candidate_value = self.trial("candidate", 1, 1)
        self.assertNotEqual(
            baseline_value["arm_binding"]["proved_root_statement_sha256"],
            candidate_value["arm_binding"]["proved_root_statement_sha256"],
        )
        self.assertNotEqual(
            baseline_value["arm_binding"]["vm_final_state_sha256"],
            candidate_value["arm_binding"]["vm_final_state_sha256"],
        )
        result = subject.build_comparison(
            self.publish("baseline", baseline_value),
            self.publish("candidate", candidate_value),
        )
        self.assertTrue(result["target"]["met"])
        self.assertEqual(950_000, result["metrics"]["total_wall"]["reduction_ppm"])
        output = self.root / "comparison.json"
        output.write_bytes(protocol.canonical_bytes(result))
        self.assertEqual(result, subject.load_comparison(output))

    def test_invalid_statement_attempt_cannot_be_a_baseline(self) -> None:
        baseline = self.trial("baseline", 20, 0)
        baseline["attempt_custody"]["failed_count"] = 1
        baseline["attempt_custody"]["terminal_error"] = "InvalidStatement"
        baseline["eligible"] = False
        with self.assertRaises(subject.StwoComparisonV2Error):
            subject.build_comparison(
                self.publish("invalid", self.reseal(baseline)),
                self.publish("candidate", self.trial("candidate", 1, 1)),
            )

    def test_matched_battery_power_is_admissible(self) -> None:
        baseline = self.trial("baseline", 20, 0)
        candidate = self.trial("candidate", 1, 1)
        for trial in (baseline, candidate):
            trial["host"]["power_source"] = "Battery Power"
        result = subject.build_comparison(
            self.publish("battery-baseline", self.reseal(baseline)),
            self.publish("battery-candidate", self.reseal(candidate)),
        )
        self.assertTrue(result["target"]["met"])
        self.assertEqual("Battery Power", result["host"]["power_source"])

    def test_arm_bound_statement_and_vm_state_must_match_own_proof(self) -> None:
        baseline = self.publish("baseline", self.trial("baseline", 20, 0))
        for index, mutate in enumerate(("proof_statement", "vm_state")):
            candidate = self.trial("candidate", 1, 1)
            if mutate == "proof_statement":
                candidate["proof"]["proved_root_statement_sha256"] = digest("wrong")
            else:
                candidate["correctness"]["vm_final_state_sha256"] = digest("wrong")
            candidate["eligible"] = False
            with self.assertRaises(subject.StwoComparisonV2Error, msg=mutate):
                subject.build_comparison(
                    baseline, self.publish(f"candidate-{index}", self.reseal(candidate)),
                )

    def test_common_semantics_security_environment_and_timing_are_closed(self) -> None:
        baseline = self.publish("baseline", self.trial("baseline", 20, 0))
        cases = []
        changed = self.trial("candidate", 1, 1)
        changed["correctness"]["semantic_output"]["sha256"] = digest("wrong")
        changed["eligible"] = False
        cases.append(changed)
        changed = self.trial("candidate", 1, 1)
        changed["benchmark"]["block_state_root"] = digest("other block state")
        cases.append(changed)
        changed = self.trial("candidate", 1, 1)
        changed["proof"]["security_identity_sha256"] = digest("other security")
        changed["eligible"] = False
        cases.append(changed)
        changed = self.trial("candidate", 1, 1)
        changed["host"]["power_source"] = "Battery Power"
        cases.append(changed)
        changed = self.trial("candidate", 1, 1)
        changed["trial_regime"]["cold_proof_cache"] = False
        changed["eligible"] = False
        cases.append(changed)
        changed = self.trial("candidate", 1, 1)
        changed["total"]["wall_ns"] += 1
        cases.append(changed)
        for index, value in enumerate(cases):
            with self.assertRaises(subject.StwoComparisonV2Error, msg=f"case {index}"):
                subject.build_comparison(
                    baseline, self.publish(f"mutation-{index}", self.reseal(value)),
                )


if __name__ == "__main__":
    unittest.main()
