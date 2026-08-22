from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
from unittest import mock

from scripts.typed_air_r006_capture_lib import reduction
from scripts.typed_air_r006_capture_lib import pair as pair_module
from scripts.typed_air_r006_capture_lib import pair_identity
from scripts.typed_air_r006_capture_lib import pair_validation
from scripts.typed_air_r006_capture_lib.codec import content_digest
from scripts.typed_air_r006_capture_lib.controller import ProcessResult
from scripts.typed_air_r006_capture_lib.model import PLAN_ATTEMPTS, CaptureError
from scripts.typed_air_r006_capture_lib.orchestration import (
    SNAPSHOT_CLASSIFICATION,
    host_preflight,
)
from scripts.typed_air_r006_capture_lib.workload_profile import (
    GUEST_ARTIFACT_FORMAT_VERSION,
    GUEST_ARTIFACT_KIND,
    GUEST_PROFILE_MANIFEST_SHA256,
    GUEST_PROFILE_VERSION,
    GUEST_TASK_PROFILE_EXAMPLE,
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
from scripts.tests.typed_air_r006_guest_fixture import guest_artifact


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
            "stwo.typed-air.r006-paired-capture-plan.v3",
        )
        self.assertEqual(plan["schema_version"], 3)
        self.assertEqual(
            plan["schedule"]["post_capture_quieting"],
            pair_module.quieting.POST_CAPTURE_QUIETING_POLICY,
        )
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
        changed["schedule"]["post_capture_quieting"]["timeout_ns"] -= 1
        changed["content_sha256"] = content_digest(changed)
        with self.assertRaisesRegex(CaptureError, "authority changed"):
            validate_pair_plan(
                changed,
                repository=self.repository,
                verify_local=False,
                source_provider=self.source,
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
                payload = f"proof:{attempt['workload_id']}".encode("ascii")
                artifact = self.base_artifact(
                    payload, backend=lane_plan["lane"]["cli_backend"]
                )
                (Path(cwd) / relative).write_bytes(artifact)
                return ProcessResult(
                    0, self.report(lane_plan, attempt, artifact), b"", 123
                )
            relative = command[command.index("--artifact") + 1]
            return ProcessResult(
                0,
                self.verifier_receipt(
                    lane_plan,
                    proof_payload=self.base_artifact_payload(
                        (Path(cwd) / relative).read_bytes()
                    ),
                ),
                b"",
                45,
            )

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

    def test_post_capture_quieting_timeout_preserves_resumable_journals(self) -> None:
        plan = self.pair_plan()
        plan_path = self.scratch / "quiet-timeout-plan.json"
        bundle = self.scratch / "quiet-timeout-bundle"
        write_pair_plan_new(plan_path, plan)

        def runner(command, cwd, timeout, environment):
            del timeout, environment
            lane = Path(cwd).name
            lane_plan = plan["lanes"][lane]
            if command[1] == "bench":
                relative = command[command.index("--proof-out") + 1]
                ordinal = int(Path(relative).name.split(".")[0])
                attempt = lane_plan["attempts"][ordinal]
                artifact = self.base_artifact(
                    backend=lane_plan["lane"]["cli_backend"]
                )
                (Path(cwd) / relative).write_bytes(artifact)
                return ProcessResult(
                    0, self.report(lane_plan, attempt, artifact), b"", 123
                )
            relative = command[command.index("--artifact") + 1]
            return ProcessResult(
                0,
                self.verifier_receipt(
                    lane_plan,
                    proof_payload=self.base_artifact_payload(
                        (Path(cwd) / relative).read_bytes()
                    ),
                ),
                b"",
                45,
            )

        rejected_host = preflight_host(logical_cpu_count=10)
        rejected = host_preflight(
            host_provider=lambda: rejected_host,
            quiet_provider=lambda _: quiet_evidence(
                rejected_host,
                idle_percent=(80.0, 81.0, 82.0),
            ),
        )
        samples = iter((self.preflight(), rejected))
        original = pair_module.quieting.await_admitted_post_capture_preflight

        def bounded_quieting(**arguments):
            ticks = iter((0, 2))
            arguments.update(
                monotonic=lambda: next(ticks),
                retry_interval_ns=1,
                timeout_ns=2,
            )
            return original(**arguments)

        settings = PairCaptureSettings(
            repository=self.repository,
            plan_path=plan_path,
            bundle_path=bundle,
            execute_frozen_2080_attempt_schedule=True,
            timeout_seconds=10,
            max_new_attempts=1,
        )
        with (
            mock.patch.object(
                pair_module.quieting,
                "await_admitted_post_capture_preflight",
                side_effect=bounded_quieting,
            ),
            self.assertRaisesRegex(CaptureError, "quieting timed out"),
        ):
            capture_pair(
                settings,
                child_runner=runner,
                sleeper=lambda _: None,
                preflight_provider=lambda: next(samples),
                source_provider=self.source,
                closure_provider=self.closure,
            )

        self.assertEqual(
            len((bundle / "cpu-native/journal.ndjson").read_bytes().splitlines()),
            2,
        )
        self.assertEqual(
            len((bundle / "metal-hybrid/journal.ndjson").read_bytes().splitlines()),
            1,
        )
        self.assertEqual(
            len((bundle / "pair-journal.ndjson").read_bytes().splitlines()),
            2,
        )
        self.assertTrue((bundle / "cpu-native/attempts/0000.proof.json").is_file())
        self.assertFalse((bundle / "pair-bundle.json").exists())

        resumed = capture_pair(
            settings,
            child_runner=runner,
            sleeper=lambda _: None,
            preflight_provider=self.preflight,
            source_provider=self.source,
            closure_provider=self.closure,
        )
        self.assertEqual(resumed["completed_attempts"], 2)
        self.assertEqual(resumed["lane_attempts"], {"cpu-native": 1, "metal-hybrid": 1})

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
        bundle = {"content_sha256": "a" * 64}
        validation = {
            "failed_attempts": 0,
            "normative_scaling_capture": True,
            "exact_work_authority": pair_validation.validate_exact_work_authority(
                plan, records
            ),
            "_snapshot": {
                "plan": plan,
                "bundle": bundle,
                "lane_records": records,
                "identities": {},
            },
        }
        with (
            mock.patch.object(
                reduction,
                "validate_pair_bundle",
                return_value=validation,
            ),
            mock.patch.object(
                reduction,
                "assert_pair_snapshot_current",
            ),
            mock.patch.object(
                reduction,
                "_require_unchanged_bundle_validation",
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
        self.assertEqual(receipt["schema_version"], 2)
        self.assertEqual(
            len(receipt["cross_lane_executed_work_observations"]), 16
        )
        self.assertEqual(receipt["qualifying_workloads"], sorted(self.workloads))
        self.assertTrue(receipt["aggregate_gates"]["a_a_calibration"])
        self.assertTrue(receipt["aggregate_gates"]["primary_cpu_four_worker_target"])
        self.assertFalse(receipt["claim_boundary"]["m7_promotion_receipt"])

    def test_reduction_snapshot_rejects_post_validation_replacement(self) -> None:
        root = self.scratch / "reduction-snapshot"
        root.mkdir()
        path = root / "pair-plan.json"
        original = b"snapshot-a\n"
        path.write_bytes(original)
        snapshot = {
            "identities": {
                "pair-plan.json": {
                    "bytes": len(original),
                    "sha256": hashlib.sha256(original).hexdigest(),
                }
            }
        }
        pair_validation.assert_pair_snapshot_current(root, snapshot)
        path.write_bytes(b"snapshot-b\n")
        with self.assertRaisesRegex(CaptureError, "source changed"):
            pair_validation.assert_pair_snapshot_current(root, snapshot)

        with (
            mock.patch.object(
                reduction,
                "validate_pair_bundle",
                return_value={"status": "changed"},
            ),
            self.assertRaisesRegex(CaptureError, "changed during scaling"),
        ):
            reduction._require_unchanged_bundle_validation(
                self.repository,
                root,
                {"status": "initial"},
            )

    def test_zero_parallel_and_observational_counters_produce_honest_receipt(self) -> None:
        plan = self.pair_plan()
        records = self.synthetic_records(plan)
        for lane_records in records.values():
            for record in lane_records:
                metrics = record["metrics"]
                metrics["task_disclosure"]["parallel_eligible_ns"] = 0
                metrics["energy_nj"] = 0
                metrics["cycles"] = 0
        bundle = {"content_sha256": "b" * 64}
        validation = {
            "failed_attempts": 0,
            "normative_scaling_capture": True,
            "exact_work_authority": pair_validation.validate_exact_work_authority(
                plan, records
            ),
            "_snapshot": {
                "plan": plan,
                "bundle": bundle,
                "lane_records": records,
                "identities": {},
            },
        }
        with (
            mock.patch.object(
                reduction,
                "validate_pair_bundle",
                return_value=validation,
            ),
            mock.patch.object(reduction, "assert_pair_snapshot_current"),
            mock.patch.object(
                reduction, "_require_unchanged_bundle_validation"
            ),
        ):
            receipt = reduction.evaluate_pair_scaling(
                self.repository,
                self.scratch / "zero-observational-bundle",
            )
        self.assertEqual(receipt["scaling_verdict"], "NO_VERDICT")
        self.assertEqual(receipt["qualifying_workloads"], [])
        for row in receipt["rows"]:
            self.assertEqual(
                row["parallelizable_fraction"]["median_fraction"], 0.0
            )
            for metric in ("energy_nj", "cycles"):
                statistic = row["statistics"][metric]
                self.assertEqual(statistic["availability"], "unavailable")
                self.assertFalse(statistic["blocking"])
                self.assertIsNone(statistic["ci_lower"])

    def test_exact_work_authority_is_strict_only_within_execution_cells(self) -> None:
        plan = self.pair_plan()
        records = self.synthetic_records(plan)
        authority = pair_validation.validate_exact_work_authority(plan, records)
        self.assertTrue(authority["every_attempt_complete_exact_work"])
        self.assertTrue(authority["every_cell_deterministic"])
        self.assertEqual(authority["expected_cells"], 32)

        same_cell_drift = copy.deepcopy(records)
        same_cell_drift["cpu-native"][1]["metrics"]["work_disclosure"][
            "field_additions"
        ] += 1
        with self.assertRaisesRegex(CaptureError, "within execution cell"):
            pair_validation.validate_exact_work_authority(plan, same_cell_drift)

        cross_cell = copy.deepcopy(records)
        for lane in pair_module.PAIR_LANE_ORDER:
            for attempt, record in zip(
                plan["lanes"][lane]["attempts"], cross_cell[lane], strict=True
            ):
                if attempt["worker_count"] == 2:
                    work = record["metrics"]["work_disclosure"]
                    work["field_additions"] += 2_981_970
                    work["field_multiplications"] += 164
                    work["field_inversions"] += 3
                    work["profile_sha256"] = "4" * 64
        changed = pair_validation.validate_exact_work_authority(plan, cross_cell)
        self.assertTrue(changed["every_cell_deterministic"])

    def test_cross_lane_identity_uses_plan_selected_semantics(self) -> None:
        full_plan = self.pair_plan()
        plan = {"lanes": {}}
        records: dict[str, list[dict[str, object]]] = {}
        payload = b"same-decoded-postcard-proof"
        guest = guest_artifact()
        for lane in pair_module.PAIR_LANE_ORDER:
            lane_plan = full_plan["lanes"][lane]
            base_attempt = next(
                attempt
                for attempt in lane_plan["attempts"]
                if attempt["workload_id"] == "multi_shard_addi"
            )
            guest_attempt = next(
                attempt
                for attempt in lane_plan["attempts"]
                if attempt["workload_id"] == "balanced_core_and_poseidon2"
            )
            plan["lanes"][lane] = {
                "attempts": [base_attempt, guest_attempt],
                "workloads": lane_plan["workloads"],
            }
            wrapper = self.base_artifact(
                payload, backend=lane_plan["lane"]["cli_backend"]
            )
            records[lane] = [
                {
                    "status": "verified",
                    "identity": {
                        "statement_sha256": "4" * 64,
                        "transcript_state_blake2s": "5" * 64,
                        "proof_bytes": len(wrapper),
                        "proof_sha256": hashlib.sha256(wrapper).hexdigest(),
                        "verifier_proof_bytes": len(payload),
                        "verifier_proof_sha256": hashlib.sha256(
                            payload
                        ).hexdigest(),
                        "total_steps": 100,
                        "n_components": 4,
                    },
                },
                {
                    "status": "verified",
                    "identity": {
                        "statement_sha256": "6" * 64,
                        "transcript_state_blake2s": "7" * 64,
                        "proof_bytes": len(guest),
                        "proof_sha256": hashlib.sha256(guest).hexdigest(),
                        "total_steps": 464_184,
                        "n_components": 6,
                        "artifact_kind": GUEST_ARTIFACT_KIND,
                        "artifact_schema_version": GUEST_ARTIFACT_FORMAT_VERSION,
                        "profile_identity": GUEST_TASK_PROFILE_EXAMPLE,
                        "profile_version": GUEST_PROFILE_VERSION,
                        "profile_manifest_sha256": GUEST_PROFILE_MANIFEST_SHA256,
                        "guest_calls": 8,
                    },
                },
            ]

        cpu_base = records["cpu-native"][0]["identity"]
        metal_base = records["metal-hybrid"][0]["identity"]
        self.assertNotEqual(cpu_base["proof_sha256"], metal_base["proof_sha256"])
        authority = pair_identity.validate_pair_identity_authority(
            plan, records, pair_module.PAIR_LANE_ORDER
        )
        self.assertEqual(set(authority), {
            "multi_shard_addi",
            "balanced_core_and_poseidon2",
        })
        self.assertEqual(
            authority["multi_shard_addi"]["verifier_proof_sha256"],
            hashlib.sha256(payload).hexdigest(),
        )

        base_mutations = {
            "verifier_proof_bytes": len(payload) + 1,
            "verifier_proof_sha256": "8" * 64,
            "statement_sha256": "8" * 64,
            "transcript_state_blake2s": "8" * 64,
            "total_steps": 101,
            "n_components": 5,
        }
        for name, value in base_mutations.items():
            with self.subTest(base=name):
                changed = copy.deepcopy(records)
                changed["metal-hybrid"][0]["identity"][name] = value
                with self.assertRaisesRegex(CaptureError, "semantic proof identity"):
                    pair_identity.validate_pair_identity_authority(
                        plan, changed, pair_module.PAIR_LANE_ORDER
                    )

        guest_mutations = {
            "proof_bytes": len(guest) + 1,
            "proof_sha256": "8" * 64,
            "artifact_kind": "wrong_guest_artifact",
            "artifact_schema_version": 2,
            "profile_identity": "wrong-profile",
            "profile_version": 2,
            "profile_manifest_sha256": "8" * 64,
            "guest_calls": 7,
            "statement_sha256": "8" * 64,
            "transcript_state_blake2s": "8" * 64,
            "total_steps": 464_185,
            "n_components": 7,
        }
        for name, value in guest_mutations.items():
            with self.subTest(guest=name):
                changed = copy.deepcopy(records)
                changed["metal-hybrid"][1]["identity"][name] = value
                with self.assertRaisesRegex(CaptureError, "semantic"):
                    pair_identity.validate_pair_identity_authority(
                        plan, changed, pair_module.PAIR_LANE_ORDER
                    )

        self_routed = copy.deepcopy(records)
        self_routed["metal-hybrid"][0]["identity"] = copy.deepcopy(
            self_routed["metal-hybrid"][1]["identity"]
        )
        with self.assertRaisesRegex(CaptureError, "identity fields drifted"):
            pair_identity.validate_pair_identity_authority(
                plan, self_routed, pair_module.PAIR_LANE_ORDER
            )

        lane_drift_plan = copy.deepcopy(plan)
        lane_drift_records = copy.deepcopy(records)
        lane_drift_plan["lanes"]["cpu-native"]["attempts"].append(
            lane_drift_plan["lanes"]["cpu-native"]["attempts"][0]
        )
        duplicate = copy.deepcopy(lane_drift_records["cpu-native"][0])
        duplicate["identity"]["proof_sha256"] = "9" * 64
        lane_drift_records["cpu-native"].append(duplicate)
        with self.assertRaisesRegex(CaptureError, "within-lane proof artifact"):
            pair_identity.validate_pair_identity_authority(
                lane_drift_plan,
                lane_drift_records,
                pair_module.PAIR_LANE_ORDER,
            )
