from __future__ import annotations

import copy
import datetime as dt
import json
from pathlib import Path
from unittest import mock

from scripts.typed_air_r006_capture_lib import reduction
from scripts.typed_air_r006_capture_lib.codec import content_digest
from scripts.typed_air_r006_capture_lib.controller import ProcessResult
from scripts.typed_air_r006_capture_lib.model import PLAN_ATTEMPTS, CaptureError
from scripts.typed_air_r006_capture_lib.orchestration import (
    SNAPSHOT_CLASSIFICATION,
    host_preflight,
)
from scripts.typed_air_r006_capture_lib.pair import (
    PAIR_ATTEMPTS,
    PairCaptureSettings,
    PairPlanSettings,
    build_pair_plan,
    capture_pair,
    validate_pair_plan,
    write_pair_plan_new,
)
from scripts.tests.test_typed_air_r006_capture import (
    R006Fixture,
    preflight_host,
    quiet_evidence,
)


class PairedCaptureTests(R006Fixture):
    def preflight(self) -> dict[str, object]:
        host = preflight_host(logical_cpu_count=10)
        result = host_preflight(
            host_provider=lambda: host,
            quiet_provider=lambda _: quiet_evidence(host),
        )
        result["captured_at_utc"] = "2026-08-15T00:00:00Z"
        result["content_sha256"] = content_digest(result)
        return result

    def pair_plan(self) -> dict[str, object]:
        return build_pair_plan(
            PairPlanSettings(
                repository=self.repository,
                session_id="fixture-r006-pair",
                power_state="AC power; fixture",
                cpu_executable=self.executable,
                metal_executable=self.executable,
                workloads=self.workloads,
                toolchain="zig:fixture",
                target="aarch64-macos",
                cpu_features="apple-m2",
            ),
            source_provider=self.source,
            host_provider=self.host,
            closure_provider=self.closure,
            preflight_provider=self.preflight,
            clock=lambda: dt.datetime(2026, 8, 15, tzinfo=dt.timezone.utc),
        )

    def test_pair_plan_freezes_2080_attempt_cpu_then_metal_interleaving(self) -> None:
        plan = self.pair_plan()
        self.assertEqual(
            plan["schema"],
            "stwo.typed-air.r006-paired-capture-plan.v2",
        )
        self.assertEqual(plan["schema_version"], 2)
        self.assertEqual(PAIR_ATTEMPTS, 2 * PLAN_ATTEMPTS)
        self.assertEqual(len(plan["interleaving"]), PAIR_ATTEMPTS)
        self.assertEqual(
            [item["lane"] for item in plan["interleaving"][:4]],
            ["cpu-native", "metal-hybrid", "cpu-native", "metal-hybrid"],
        )
        self.assertEqual(
            [item["lane_ordinal"] for item in plan["interleaving"][:4]],
            [0, 0, 1, 1],
        )
        self.assertEqual(plan["source"], plan["lanes"]["cpu-native"]["source"])
        self.assertEqual(
            plan["global_exact_work_closure"],
            plan["lanes"]["cpu-native"]["global_exact_work_closure"],
        )
        self.assertEqual(
            plan["lanes"]["cpu-native"]["workloads"],
            plan["lanes"]["metal-hybrid"]["workloads"],
        )

        changed = copy.deepcopy(plan)
        changed["interleaving"][0], changed["interleaving"][1] = (
            changed["interleaving"][1],
            changed["interleaving"][0],
        )
        changed["content_sha256"] = content_digest(changed)
        with self.assertRaisesRegex(CaptureError, "interleaving"):
            validate_pair_plan(
                changed,
                repository=self.repository,
                verify_local=False,
                source_provider=self.source,
            )

        changed = copy.deepcopy(plan)
        changed["lanes"]["metal-hybrid"]["global_exact_work_closure"] = (
            copy.deepcopy(plan["global_exact_work_closure"])
        )
        changed["lanes"]["metal-hybrid"]["global_exact_work_closure"][
            "inventory"
        ]["source_sha256"] = "d" * 64
        changed["lanes"]["metal-hybrid"]["content_sha256"] = content_digest(
            changed["lanes"]["metal-hybrid"]
        )
        changed["content_sha256"] = content_digest(changed)
        with self.assertRaisesRegex(CaptureError, "exact-work closure"):
            validate_pair_plan(
                changed,
                repository=self.repository,
                verify_local=False,
                source_provider=self.source,
            )

    def test_pair_plan_rejects_ephemeral_source_and_inadmissible_preflight(self) -> None:
        ephemeral = {
            "classification": SNAPSHOT_CLASSIFICATION,
            "commit": "6" * 40,
            "tree": "7" * 40,
            "clean": True,
            "ephemeral": True,
            "source_closure_files": 1,
            "source_closure_sha256": "8" * 64,
        }
        settings = PairPlanSettings(
            repository=self.repository,
            session_id="fixture-rejected-pair",
            power_state="AC power; fixture",
            cpu_executable=self.executable,
            metal_executable=self.executable,
            workloads=self.workloads,
            toolchain="zig:fixture",
            target="aarch64-macos",
            cpu_features="apple-m2",
        )
        with self.assertRaisesRegex(CaptureError, "rejects ephemeral"):
            build_pair_plan(
                settings,
                source_provider=lambda _: ephemeral,
                host_provider=self.host,
                closure_provider=self.closure,
                preflight_provider=self.preflight,
            )

        rejected_host = preflight_host(
            logical_cpu_count=10,
            power_source="Battery Power",
        )
        rejected = host_preflight(
            host_provider=lambda: rejected_host,
            quiet_provider=lambda _: quiet_evidence(rejected_host),
        )
        with self.assertRaisesRegex(CaptureError, "inadmissible"):
            build_pair_plan(
                settings,
                source_provider=self.source,
                host_provider=self.host,
                closure_provider=self.closure,
                preflight_provider=lambda: rejected,
            )

    def test_pair_capture_resumes_only_the_durable_fixed_prefix(self) -> None:
        plan = self.pair_plan()
        plan_path = self.scratch / "pair-plan.json"
        bundle = self.scratch / "pair-bundle"
        write_pair_plan_new(plan_path, plan)

        def runner(command, cwd, timeout, environment):
            del timeout, environment
            lane = Path(cwd).name
            lane_plan = plan["lanes"][lane]
            if command[1] == "bench":
                relative = command[command.index("--proof-out") + 1]
                ordinal = int(Path(relative).name.split(".")[0])
                attempt = lane_plan["attempts"][ordinal]
                proof = f"proof:{attempt['workload_id']}".encode("ascii")
                (Path(cwd) / relative).write_bytes(proof)
                return ProcessResult(0, self.report(lane_plan, attempt, proof), b"", 123)
            return ProcessResult(0, b"", b"", 45)

        def capture_one():
            return capture_pair(
                PairCaptureSettings(
                    repository=self.repository,
                    plan_path=plan_path,
                    bundle_path=bundle,
                    execute_frozen_2080_attempt_schedule=True,
                    timeout_seconds=10,
                    max_new_attempts=1,
                ),
                child_runner=runner,
                sleeper=lambda _: None,
                preflight_provider=self.preflight,
                source_provider=self.source,
                closure_provider=self.closure,
            )

        first = capture_one()
        self.assertEqual(first["completed_attempts"], 1)
        self.assertEqual(first["lane_attempts"], {"cpu-native": 1, "metal-hybrid": 0})
        second = capture_one()
        self.assertEqual(second["completed_attempts"], 2)
        self.assertEqual(second["lane_attempts"], {"cpu-native": 1, "metal-hybrid": 1})
        progress = (bundle / "pair-journal.ndjson").read_bytes().splitlines()
        self.assertEqual(len(progress), 3)
        first_record = json.loads(progress[1])
        second_record = json.loads(progress[2])
        self.assertEqual(first_record["lane"], "cpu-native")
        self.assertEqual(second_record["lane"], "metal-hybrid")
        self.assertEqual(first_record["lane_ordinal"], 0)
        self.assertEqual(second_record["lane_ordinal"], 0)

    def synthetic_records(
        self,
        plan: dict[str, object],
    ) -> dict[str, list[dict[str, object]]]:
        result: dict[str, list[dict[str, object]]] = {}
        work = {
            "schema": "stwo.prover.logical-work-profile.v2",
            "source_mask": 0x3F,
            "record_count": 19,
            "producer_ledger_schema_version": 2,
            "producer_counts": [3, 4, 2, 1, 4, 2, 3],
            "producer_coverage_terminal_sealed": True,
            "field_additions": 10_001,
            "field_multiplications": 8_003,
            "field_inversions": 17,
            "fft_butterflies": 4_096,
            "fri_folds": 2_048,
            "merkle_compressions": 1_023,
            "profile_sha256": "3" * 64,
        }
        for lane in ("cpu-native", "metal-hybrid"):
            records: list[dict[str, object]] = []
            for attempt in plan["lanes"][lane]["attempts"]:
                workers = attempt["worker_count"]
                if attempt["comparison_id"] == "aa-calibration" or attempt["arm"] == "reference":
                    verified_ns = 1_000_000_000
                    proving_ns = 600_000_000
                else:
                    speed = 1.0 + 0.7 * (workers - 1)
                    verified_ns = int(1_000_000_000 / speed)
                    proving_ns = int(600_000_000 / speed)
                metrics: dict[str, object] = {
                    "verified_request_ns": verified_ns,
                    "proving_ns": proving_ns,
                    "peak_rss_bytes": 1_000_000_000,
                    "retired_instructions": 1_000_000,
                    "energy_nj": 10_000,
                    "cycles": 2_000_000,
                    "task_disclosure": {"parallel_eligible_ns": 800_000_000},
                    "work_disclosure": copy.deepcopy(work),
                }
                if lane == "metal-hybrid":
                    metrics["metal_disclosure"] = {
                        "base_batch_dispatches": 1,
                        "lookup_batch_dispatches": 1,
                    }
                records.append(
                    {
                        "status": "verified",
                        "process_cpu_ns": 700_000_000,
                        "metrics": metrics,
                    }
                )
            result[lane] = records
        return result

    def test_scaling_reducer_recomputes_pass_but_never_invents_predecessor(self) -> None:
        plan = self.pair_plan()
        records = self.synthetic_records(plan)
        validation = {
            "failed_attempts": 0,
            "normative_scaling_capture": True,
        }
        bundle = {"content_sha256": "a" * 64}
        with (
            mock.patch.object(
                reduction,
                "validate_pair_bundle",
                return_value=validation,
            ),
            mock.patch.object(
                reduction,
                "_read_root_json",
                side_effect=(plan, bundle),
            ),
            mock.patch.object(
                reduction,
                "_lane_records",
                side_effect=lambda path: records[path.name],
            ),
        ):
            receipt = reduction.evaluate_pair_scaling(
                self.repository,
                self.scratch / "synthetic-pair-bundle",
            )
        self.assertEqual(receipt["scaling_verdict"], "PASS")
        self.assertEqual(
            receipt["m7_verdict"],
            "NO_VERDICT_MISSING_PREDECESSOR_ONE_WORKER_COHORT",
        )
        self.assertEqual(len(receipt["rows"]), 24)
        self.assertEqual(receipt["qualifying_workloads"], sorted(self.workloads))
        self.assertTrue(receipt["aggregate_gates"]["a_a_calibration"])
        self.assertTrue(receipt["aggregate_gates"]["primary_cpu_four_worker_target"])
        self.assertFalse(receipt["claim_boundary"]["m7_promotion_receipt"])
