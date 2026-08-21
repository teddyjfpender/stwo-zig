from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from scripts.typed_air_r006_capture_lib.codec import content_digest
from scripts.typed_air_r006_capture_lib.contract import (
    PlanSettings,
    WorkloadPaths,
    _validate_generated_input,
    build_plan,
    materialized_poseidon_input,
    validate_plan,
)
from scripts.typed_air_r006_capture_lib.model import (
    GENERATED_INPUT_GEOMETRY_SCHEMA,
    GENERATED_WORKLOAD_PARAMETERS,
    CaptureError,
)
from scripts.typed_air_r006_capture_lib.workload_profile import is_guest_workload
from scripts.tests.test_typed_air_r006_capture import R006Fixture


class GeneratedGeometryTests(R006Fixture):
    def test_plan_v3_binds_distinct_versioned_workload_geometry(self) -> None:
        expected = {
            "balanced_core_and_poseidon2": (
                8,
                516,
                "efcf4956a010c85866868b5e45f712980addd512f4d0462d54df2115e0ed6e82",
            ),
            "poseidon2_dominant": (
                4096,
                262_148,
                "ff798e2438279ac57ab9ea8cb7d5816d4500f628850e00c02c202f2eb32455ca",
            ),
        }
        for workload in self.plan["workloads"]:
            if workload["id"] not in expected:
                continue
            calls, byte_count, digest = expected[workload["id"]]
            self.assertEqual(
                workload["parameters"],
                GENERATED_WORKLOAD_PARAMETERS[workload["id"]],
            )
            self.assertEqual(workload["parameters"]["calls"], calls)
            self.assertEqual(workload["parameters"]["schema_version"], 1)
            self.assertEqual(
                workload["parameters"]["schema"],
                GENERATED_INPUT_GEOMETRY_SCHEMA,
            )
            self.assertEqual(workload["input"]["bytes"], byte_count)
            self.assertEqual(workload["input"]["sha256"], digest)

    def test_geometry_mutations_fail_closed_after_resigning(self) -> None:
        balanced_index = next(
            index
            for index, workload in enumerate(self.plan["workloads"])
            if workload["id"] == "balanced_core_and_poseidon2"
        )
        mutations = {
            "calls": 4096,
            "width": 8,
            "encoding_word_bytes": 8,
            "schema": "stwo.typed-air.r006-generated-input-geometry.v2",
            "schema_version": 2,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(self.plan)
                changed["workloads"][balanced_index]["parameters"][field] = value
                changed["content_sha256"] = content_digest(changed)
                with self.assertRaisesRegex(CaptureError, "geometry changed"):
                    validate_plan(
                        changed,
                        repository=self.repository,
                        verify_local=False,
                    )

    def test_legacy_plan_schema_is_not_reinterpreted(self) -> None:
        changed = copy.deepcopy(self.plan)
        changed["schema"] = "stwo.typed-air.r006-capture-plan.v2"
        changed["schema_version"] = 2
        changed["content_sha256"] = content_digest(changed)
        with self.assertRaisesRegex(CaptureError, "schema identity changed"):
            validate_plan(
                changed,
                repository=self.repository,
                verify_local=False,
            )

    def test_cross_workload_input_is_rejected_before_scheduling(self) -> None:
        changed = dict(self.workloads)
        balanced = changed["balanced_core_and_poseidon2"]
        dominant = changed["poseidon2_dominant"]
        changed["balanced_core_and_poseidon2"] = WorkloadPaths(
            balanced.elf,
            dominant.input,
        )
        with self.assertRaisesRegex(CaptureError, "canonical for balanced"):
            build_plan(
                PlanSettings(
                    repository=self.repository,
                    session_id="fixture-r006-cross-input",
                    lane="cpu-native",
                    power_state="AC power; fixture",
                    executable=self.executable,
                    workloads=changed,
                    toolchain="zig:fixture",
                    target="aarch64-macos",
                    cpu_features="apple-m2",
                ),
                source_provider=self.source,
                host_provider=self.host,
                closure_provider=self.closure,
            )

    def test_materializer_accepts_only_authorized_call_counts(self) -> None:
        for calls in (8, 4096):
            raw = materialized_poseidon_input(calls)
            self.assertEqual(len(raw), 4 + calls * 16 * 4)
        for calls in (0, 1, 256, 4095):
            with self.subTest(calls=calls):
                with self.assertRaisesRegex(CaptureError, "per-workload call counts"):
                    materialized_poseidon_input(calls)

    def test_profile_routing_rejects_geometry_drift(self) -> None:
        workload = copy.deepcopy(
            next(
                item
                for item in self.plan["workloads"]
                if item["id"] == "balanced_core_and_poseidon2"
            )
        )
        workload["parameters"]["calls"] = 4096
        with self.assertRaisesRegex(CaptureError, "parameters changed"):
            is_guest_workload(workload)

    def test_materialize_command_seals_each_input_identity(self) -> None:
        output = self.scratch / "materialized"
        command = (
            sys.executable,
            str(self.repository / "scripts/typed_air_r006_capture.py"),
            "--repository",
            str(self.repository),
            "materialize-inputs",
            "--output-dir",
            str(output),
        )
        result = subprocess.run(
            command,
            cwd=self.repository,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        receipt = json.loads(result.stdout)
        self.assertEqual(
            receipt["schema"],
            "stwo.typed-air.r006-materialized-inputs.v2",
        )
        self.assertEqual(receipt["schema_version"], 2)
        self.assertEqual(len(receipt["outputs"]), 2)
        for item in receipt["outputs"]:
            workload_id = item["workload"]
            path = Path(item["input"]["path"])
            raw = path.read_bytes()
            self.assertEqual(
                item["parameters"],
                GENERATED_WORKLOAD_PARAMETERS[workload_id],
            )
            self.assertEqual(item["input"]["bytes"], len(raw))
            self.assertEqual(
                item["input"]["sha256"], hashlib.sha256(raw).hexdigest()
            )
            self.assertEqual(
                _validate_generated_input(path, workload_id),
                item["parameters"],
            )
