from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path
from typing import Callable

from scripts.typed_air_poseidon_benchmark_lib import (
    ARMS,
    BenchmarkError,
    BenchmarkRunFailed,
    ChildResult,
    ContractError,
    ReportError,
    Settings,
    atomic_write_new,
    collect_benchmark,
    decode_one_line_json,
    integer_summary,
    launch_order,
    run_benchmark,
    validate_report,
    validate_sample,
)
from scripts.typed_air_poseidon_benchmark_lib.contract import (
    ARM_BY_ID,
    ARTIFACT_DIGEST,
    BACKEND,
    BENCHMARK_ID,
    CALL_SCHEDULE,
    CLASSIFICATION,
    DIRECT_NODES,
    DIRECT_RETAINED_SCRATCH_BYTES,
    DIRECT_ROOTS,
    EVALUATOR,
    MAIN_COLUMNS,
    MATERIALIZATIONS,
    MEASUREMENT_SCOPE,
    SAMPLE_KEYS,
    SAMPLE_SCHEMA,
    SAMPLE_SCHEMA_VERSION,
    SEMANTIC_RETAINED_SCRATCH_BYTES,
    VECTOR_ARTIFACT_DIGESTS,
    VECTOR_CALL_DIGESTS,
    VECTOR_OUTPUT_DIGESTS,
    VECTOR_SEALS,
    VECTOR_TRACE_DIGESTS,
)
from scripts.typed_air_poseidon_benchmark_lib.environment import SOURCE_MANIFEST


Transform = Callable[[dict[str, object], int, int], None]


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def valid_check() -> dict[str, object]:
    return {
        "schema": SAMPLE_SCHEMA,
        "schema_version": 1,
        "benchmark": BENCHMARK_ID,
        "command": "check",
        "status": "passed",
        "arms": 4,
        "correctness_log_sizes": [4, 6],
        "measurement_logs_checked": [10, 14],
        "direct_roots_checked_per_row": DIRECT_ROOTS,
        "rss_probe_allocated_bytes": 64 * 1024 * 1024,
        "rss_probe_delta_bytes": 48 * 1024 * 1024,
        "rss_probe_source": "getrusage-self-maxrss-native-bytes",
        "proof_executed": False,
        "metal_candidate_execution_supported": False,
        "production_layout_changed": False,
    }


def valid_sample(arm: str, log_size: int, arm_ordinal: int = 0) -> dict[str, object]:
    pin = ARM_BY_ID[arm]
    return {
        "schema": SAMPLE_SCHEMA,
        "schema_version": SAMPLE_SCHEMA_VERSION,
        "classification": CLASSIFICATION,
        "benchmark_id": BENCHMARK_ID,
        "evaluator": EVALUATOR,
        "backend": BACKEND,
        "measurement_scope": MEASUREMENT_SCOPE,
        "optimization_mode": "ReleaseFast",
        "zig_version": "0.15.2",
        "target": "aarch64-macos-none",
        "allocator": "libc-c-allocator",
        "monotonic_clock": "std.time.Timer",
        "vector_storage_class": (
            "generated_opt_in_uncommitted_non_receiptable"
            if log_size == 18
            else "checked_repository_artifact"
        ),
        "vector_seal": VECTOR_SEALS[log_size],
        "vector_artifact_sha256": VECTOR_ARTIFACT_DIGESTS[log_size],
        "vector_bytes": 130 + (1 << log_size) * 140,
        "arm": arm,
        "frontier_ordinal": pin.frontier_ordinal,
        "log_size": log_size,
        "rows": 1 << log_size,
        "setup_ns": 101 + arm_ordinal,
        "witness_ns": 201 + arm_ordinal,
        "direct_ns": 301 + arm_ordinal,
        "peak_rss_bytes": 1_000_001 + arm_ordinal,
        "peak_rss_native_value": 1_000_001 + arm_ordinal,
        "peak_rss_native_unit": "bytes",
        "resource_source": "getrusage-self-maxrss-native-bytes",
        "root_evaluations": (1 << log_size) * DIRECT_ROOTS,
        "nonzero_roots": 0,
        "direct_sink": 0,
        "artifact_digest": ARTIFACT_DIGEST,
        "cut_digest": pin.cut_digest,
        "proposal_digest": pin.proposal_digest,
        "layout_digest": digest(f"layout:{arm}"),
        "direct_program_digest": digest(f"program:{arm}"),
        "evaluator_digest": digest(f"evaluator:{arm}"),
        "output_digest": VECTOR_OUTPUT_DIGESTS[log_size],
        "trace_digest": VECTOR_TRACE_DIGESTS[log_size][ARMS.index(arm)],
        "trace_digest_class": "candidate_layout_regression_pin_not_correctness_oracle",
        "call_schedule": CALL_SCHEDULE,
        "call_digest": VECTOR_CALL_DIGESTS[log_size],
        "semantic_execution_digest": digest(f"semantic:{arm}:{log_size}"),
        "direct_result_digest": digest(f"direct-result:{arm}:{log_size}"),
        "main_columns": MAIN_COLUMNS,
        "materializations": MATERIALIZATIONS,
        "direct_nodes": DIRECT_NODES,
        "direct_roots": DIRECT_ROOTS,
        "semantic_retained_scratch_bytes": SEMANTIC_RETAINED_SCRATCH_BYTES,
        "direct_retained_scratch_bytes": DIRECT_RETAINED_SCRATCH_BYTES,
        "allocation_free_timed_row_loops": True,
        "valid": True,
        "proof_executed": False,
        "verification_executed": False,
        "hash_component_shell_executed": False,
        "logup_executed": False,
        "commitment_executed": False,
        "pcs_executed": False,
        "metal_candidate_execution_supported": False,
        "production_layout_changed": False,
        "promotion_authority": False,
        "status": "pass",
    }


def encoded(value: dict[str, object]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class FakeRunner:
    def __init__(
        self,
        *,
        transform: Transform | None = None,
        fail_at: int | None = None,
        stderr_at: int | None = None,
        fail_log_18: bool = False,
        bad_check: bool = False,
    ) -> None:
        self.transform = transform
        self.fail_at = fail_at
        self.stderr_at = stderr_at
        self.fail_log_18 = fail_log_18
        self.bad_check = bad_check
        self.calls: list[tuple[tuple[str, ...], Path, float, dict[str, str]]] = []
        self.arm_counts: dict[tuple[str, int], int] = defaultdict(int)

    def __call__(self, command, cwd, timeout, environment) -> ChildResult:
        call_index = len(self.calls)
        self.calls.append((tuple(command), cwd, timeout, dict(environment)))
        if self.fail_at == call_index:
            return ChildResult(23, b"", b"injected failure")
        if command[1] == "check":
            check = valid_check()
            if self.bad_check:
                check["measurement_logs_checked"] = [10]
            return ChildResult(0, encoded(check), b"")
        arm = command[2]
        log_size = int(command[3])
        if self.fail_log_18 and log_size == 18:
            return ChildResult(24, b"", b"stress allocation failed")
        arm_ordinal = self.arm_counts[(arm, log_size)]
        self.arm_counts[(arm, log_size)] += 1
        sample = valid_sample(arm, log_size, arm_ordinal)
        if self.transform is not None:
            self.transform(sample, call_index, arm_ordinal)
        stderr = b"injected warning" if self.stderr_at == call_index else b""
        return ChildResult(0, encoded(sample), stderr)


def fake_provenance(repository: Path, executable: Path, power_state: str):
    binary = executable.read_bytes()
    return {
        "repository": {
            "commit": "1" * 40,
            "tree": "2" * 40,
            "clean": True,
            "status_porcelain": [],
        },
        "source_closure": {
            "manifest": SOURCE_MANIFEST.canonical(),
            "manifest_sha256": SOURCE_MANIFEST.digest(),
            "source_count": 1,
            "content_sha256": digest("closure"),
            "sources": ["src/frontends/riscv/poseidon_layout_benchmark_tool.zig"],
        },
        "executable": {
            "path": str(executable.resolve()),
            "bytes": len(binary),
            "sha256": hashlib.sha256(binary).hexdigest(),
        },
        "artifact": {
            "path": "design/typed-air/artifacts/h009-poseidon2-cost-v1/frontier.stwairm",
            "bytes": 275_153,
            "sha256": ARTIFACT_DIGEST,
        },
        "host": {
            "target_arch": "arm64",
            "expected_native_target_prefix": "aarch64-macos-",
            "os": "Darwin",
            "os_version": "test-version",
            "kernel_release": "test-kernel",
            "cpu_model": "test-cpu",
            "logical_cores": 8,
            "physical_cores": 4,
            "memory_bytes": 16 * 1024**3,
            "power_state": {
                "operator_declaration": power_state,
                "machine_verified": False,
            },
        },
        "build_expectation": {
            "zig_version": "0.15.2",
            "optimization_mode": "ReleaseFast",
            "target_prefix": "aarch64-macos-",
            "allocator": "libc-c-allocator",
            "monotonic_clock": "std.time.Timer",
        },
        "environment_allowlist": {"LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
        "worker_count": 1,
        "clock_adapter": "std.time.Timer",
        "rss_adapter": "getrusage(RUSAGE_SELF).ru_maxrss",
    }


class TypedAirPoseidonBenchmarkTests(unittest.TestCase):
    def settings(self, root: Path, *, stress: bool = False) -> Settings:
        executable = root / "runner"
        executable.write_bytes(b"fake-release-fast-executable\n")
        executable.chmod(0o755)
        return Settings(
            executable=executable,
            output_path=root / "reports/h010.json",
            repo_root=root,
            power_state="AC power; low-power mode disabled",
            include_log_18=stress,
            timeout_seconds=17.0,
            run_id="h010-test-run",
        )

    def test_rotation_and_integer_statistics_are_exact(self) -> None:
        self.assertEqual(ARMS, launch_order(0))
        self.assertEqual(
            ("removed-q0", "removed-q50", "removed-q100", "compat-seed"),
            launch_order(1),
        )
        self.assertEqual(ARMS, launch_order(4))
        values = [100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        self.assertEqual(
            {"raw": values, "median": 6, "mad": 3, "minimum": 1, "maximum": 100},
            integer_summary(values),
        )

    def test_sample_contract_is_closed_for_every_arm_and_log(self) -> None:
        for arm in ARMS:
            for log_size in (10, 14, 18):
                sample = valid_sample(arm, log_size)
                self.assertEqual(SAMPLE_KEYS, frozenset(sample))
                self.assertEqual(
                    sample,
                    validate_sample(
                        encoded(sample), expected_arm=arm, expected_log=log_size
                    ),
                )
        linux = valid_sample("compat-seed", 10)
        linux["peak_rss_native_value"] = 2_048
        linux["peak_rss_native_unit"] = "KiB"
        linux["peak_rss_bytes"] = 2_048 * 1024
        linux["resource_source"] = "getrusage-self-maxrss-kib-normalized-bytes"
        validate_sample(encoded(linux), expected_arm="compat-seed", expected_log=10)

    def test_decoder_and_sample_mutations_fail_closed(self) -> None:
        for raw in (b"", b"{}\n{}\n", b" {}\n", b'{"x":1,"x":2}\n', b"\xff\n"):
            with self.assertRaises(ContractError):
                decode_one_line_json(raw)
        for key, replacement in (
            ("schema_version", 2),
            ("root_evaluations", 17),
            ("setup_ns", 0),
            ("vector_seal", "0" * 64),
            ("vector_artifact_sha256", "0" * 64),
            ("semantic_retained_scratch_bytes", 1),
            ("proof_executed", True),
            ("valid", False),
        ):
            sample = valid_sample("compat-seed", 10)
            sample[key] = replacement
            with self.subTest(key=key), self.assertRaises(ContractError):
                validate_sample(
                    encoded(sample), expected_arm="compat-seed", expected_log=10
                )

    def test_default_run_preflights_rotates_summarizes_and_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(root)
            fake = FakeRunner()
            document, payload = run_benchmark(
                settings,
                child_runner=fake,
                provenance_provider=fake_provenance,
            )
            self.assertEqual(113, len(fake.calls))
            self.assertEqual("check", fake.calls[0][0][1])
            self.assertEqual(list(ARMS), [call[0][2] for call in fake.calls[1:5]])
            self.assertEqual(payload, settings.output_path.read_bytes())
            self.assertTrue(document["valid"])
            self.assertTrue(document["requested_run_complete"])
            self.assertEqual([10, 14], document["logs"])
            self.assertEqual([10, 14], [item["log_size"] for item in document["vectors"]])
            cohort = document["cohorts"][0]
            self.assertEqual(12, len(cohort["warmups"]))
            self.assertEqual(44, len(cohort["samples"]))
            self.assertEqual(
                list(range(104, 115)),
                cohort["summaries"]["compat-seed"]["setup_ns"]["raw"],
            )
            validate_report(document)

    def test_dirty_or_unavailable_provenance_writes_invalid_report_without_children(self) -> None:
        def dirty(repo, executable, power):
            value = fake_provenance(repo, executable, power)
            value["repository"]["clean"] = False
            value["repository"]["status_porcelain"] = [" M source.zig"]
            return value

        def unavailable(repo, executable, power):
            raise ValueError("injected provenance failure")

        def malformed(repo, executable, power):
            value = fake_provenance(repo, executable, power)
            del value["source_closure"]
            return value

        for provider, code in (
            (dirty, "repository-dirty"),
            (unavailable, "provenance-unavailable"),
            (malformed, "provenance-schema"),
        ):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                settings = self.settings(root)
                fake = FakeRunner()
                with self.assertRaises(BenchmarkRunFailed) as caught:
                    run_benchmark(
                        settings, child_runner=fake, provenance_provider=provider
                    )
                self.assertEqual([], fake.calls)
                self.assertFalse(caught.exception.document["valid"])
                self.assertEqual(code, caught.exception.document["failures"][0]["code"])
                self.assertTrue(settings.output_path.is_file())

    def test_preflight_and_child_failures_write_one_invalid_no_retry_report(self) -> None:
        for fake, expected_calls in ((FakeRunner(bad_check=True), 1), (FakeRunner(fail_at=7), 8)):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                settings = self.settings(root)
                with self.assertRaises(BenchmarkRunFailed) as caught:
                    run_benchmark(
                        settings,
                        child_runner=fake,
                        provenance_provider=fake_provenance,
                    )
                self.assertEqual(expected_calls, len(fake.calls))
                self.assertFalse(caught.exception.document["valid"])
                self.assertEqual(0, caught.exception.document["automatic_retries"])
                self.assertEqual(caught.exception.encoded, settings.output_path.read_bytes())

    def test_optional_log18_failure_preserves_valid_defaults_and_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(root, stress=True)
            fake = FakeRunner(fail_log_18=True)
            with self.assertRaises(BenchmarkRunFailed) as caught:
                run_benchmark(
                    settings,
                    child_runner=fake,
                    provenance_provider=fake_provenance,
                )
            report = caught.exception.document
            self.assertTrue(report["valid"])
            self.assertFalse(report["requested_run_complete"])
            self.assertEqual([True, True, False], [item["valid"] for item in report["cohorts"]])
            self.assertEqual(18, report["failures"][0]["log_size"])
            self.assertEqual(114, len(fake.calls))
            validate_report(report)

        def replace_failure_field(
            value: dict[str, object], key: str, replacement: object
        ) -> None:
            value["cohorts"][2]["failure"][key] = replacement
            value["failures"][0][key] = replacement

        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory), stress=True)
            launch_failure = collect_benchmark(
                settings,
                child_runner=FakeRunner(fail_at=116),
                provenance_provider=fake_provenance,
            )
            failed = launch_failure["cohorts"][2]
            self.assertEqual("warmup", failed["failure"]["phase"])
            self.assertEqual(3, failed["failure"]["launch_ordinal"])
            self.assertEqual(3, len(failed["warmups"]))
            validate_report(launch_failure)

            mutations = []
            value = copy.deepcopy(launch_failure)
            value["cohorts"][2]["schedule"].append(
                copy.deepcopy(value["cohorts"][2]["schedule"][0])
            )
            mutations.append(value)
            value = copy.deepcopy(launch_failure)
            value["cohorts"][2]["warmups"].append(
                copy.deepcopy(value["cohorts"][2]["warmups"][0])
            )
            mutations.append(value)
            value = copy.deepcopy(launch_failure)
            value["cohorts"][2]["warmups"][0]["sample"] = copy.deepcopy(
                value["cohorts"][2]["warmups"][1]["sample"]
            )
            mutations.append(value)
            value = copy.deepcopy(launch_failure)
            replace_failure_field(value, "log_size", 14)
            mutations.append(value)
            value = copy.deepcopy(launch_failure)
            value["cohorts"][2]["summaries"] = {"junk": {}}
            mutations.append(value)
            value = copy.deepcopy(launch_failure)
            replace_failure_field(value, "code", "Bad_Code")
            mutations.append(value)
            value = copy.deepcopy(launch_failure)
            replace_failure_field(value, "arm", "compat-seed")
            mutations.append(value)
            for ordinal, mutated in enumerate(mutations):
                with self.subTest(shape="launch", ordinal=ordinal), self.assertRaises(
                    ReportError
                ):
                    validate_report(mutated)

        def stress_identity_drift(sample, call, arm_ordinal):
            if (
                sample["log_size"] == 18
                and sample["arm"] == "removed-q50"
                and arm_ordinal == 4
            ):
                sample["layout_digest"] = digest("stress-drift")

        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory), stress=True)
            validation_failure = collect_benchmark(
                settings,
                child_runner=FakeRunner(transform=stress_identity_drift),
                provenance_provider=fake_provenance,
            )
            failed = validation_failure["cohorts"][2]
            self.assertEqual("cohort-validation", failed["failure"]["phase"])
            self.assertEqual(14, len(failed["schedule"]))
            self.assertEqual((12, 44), (len(failed["warmups"]), len(failed["samples"])))
            validate_report(validation_failure)

            mutations = []
            value = copy.deepcopy(validation_failure)
            value["cohorts"][2]["schedule"].pop()
            mutations.append(value)
            value = copy.deepcopy(validation_failure)
            value["cohorts"][2]["samples"].pop()
            mutations.append(value)
            value = copy.deepcopy(validation_failure)
            replace_failure_field(value, "round", 13)
            mutations.append(value)
            for ordinal, mutated in enumerate(mutations):
                with self.subTest(
                    shape="cohort-validation", ordinal=ordinal
                ), self.assertRaises(ReportError):
                    validate_report(mutated)

    def test_identity_drift_and_snapshot_drift_are_reported(self) -> None:
        def sample_drift(sample, call, arm_ordinal):
            if sample["arm"] == "removed-q50" and arm_ordinal == 4:
                sample["layout_digest"] = digest("drift")

        class DriftingProvenance:
            def __init__(self):
                self.calls = 0

            def __call__(self, repo, executable, power):
                value = fake_provenance(repo, executable, power)
                if self.calls:
                    value["repository"]["tree"] = "3" * 40
                self.calls += 1
                return value

        for fake, provider, code in (
            (FakeRunner(transform=sample_drift), fake_provenance, "sample-identity-drift"),
            (FakeRunner(), DriftingProvenance(), "provenance-identity-drift"),
        ):
            with tempfile.TemporaryDirectory() as directory:
                settings = self.settings(Path(directory))
                with self.assertRaises(BenchmarkRunFailed) as caught:
                    run_benchmark(
                        settings, child_runner=fake, provenance_provider=provider
                    )
                self.assertIn(code, [item["code"] for item in caught.exception.document["failures"]])

    def test_final_report_validator_replays_all_admission_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            report = collect_benchmark(
                settings,
                child_runner=FakeRunner(),
                provenance_provider=fake_provenance,
            )
            mutations = []
            value = copy.deepcopy(report)
            value["schema_version"] = 2
            mutations.append(value)
            value = copy.deepcopy(report)
            del value["geometry"]
            mutations.append(value)
            value = copy.deepcopy(report)
            value["geometry"]["semantic_retained_scratch_bytes"] = 1
            mutations.append(value)
            value = copy.deepcopy(report)
            value["arm_selection"]["frontier_count"] = 125
            mutations.append(value)
            value = copy.deepcopy(report)
            value["preflight"]["measurement_logs_checked"] = [10]
            mutations.append(value)
            value = copy.deepcopy(report)
            value["cohorts"][0]["schedule"][1]["arms"].reverse()
            mutations.append(value)
            value = copy.deepcopy(report)
            value["cohorts"][0]["samples"][0]["sample"]["proof_executed"] = True
            mutations.append(value)
            value = copy.deepcopy(report)
            value["cohorts"][0]["summaries"]["compat-seed"]["setup_ns"]["raw"][0] += 1
            mutations.append(value)
            value = copy.deepcopy(report)
            value["vectors"][0]["artifact_sha256"] = "0" * 64
            mutations.append(value)
            value = copy.deepcopy(report)
            value["cohorts"].append(copy.deepcopy(value["cohorts"][0]))
            mutations.append(value)
            value = copy.deepcopy(report)
            value["vectors"].append(copy.deepcopy(value["vectors"][0]))
            mutations.append(value)
            value = copy.deepcopy(report)
            value["provenance"]["source_closure"]["manifest"]["product"] = "mutated"
            mutations.append(value)
            value = copy.deepcopy(report)
            value["rss_adapters_observed"].append(copy.deepcopy(value["rss_adapters_observed"][0]))
            mutations.append(value)
            for ordinal, mutated in enumerate(mutations):
                with self.subTest(ordinal=ordinal), self.assertRaises(ReportError):
                    validate_report(mutated)

    def test_existing_output_is_never_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(root)
            settings.output_path.parent.mkdir()
            settings.output_path.write_bytes(b"irreplaceable\n")
            fake = FakeRunner()
            with self.assertRaises(BenchmarkError):
                run_benchmark(
                    settings,
                    child_runner=fake,
                    provenance_provider=fake_provenance,
                )
            self.assertEqual([], fake.calls)
            with self.assertRaises(ReportError):
                atomic_write_new(settings.output_path, b"replacement\n")
            self.assertEqual(b"irreplaceable\n", settings.output_path.read_bytes())


if __name__ == "__main__":
    unittest.main()
