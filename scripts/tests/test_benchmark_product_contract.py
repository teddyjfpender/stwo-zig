from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.benchmark_product_contract_lib import (
    ProductEvidenceError,
    build_receipt,
    validate_product_identity,
    validate_receipt,
)
from scripts.benchmark_product_contract_lib.identity import canonical_identity_sha256
from scripts.product_identity_lib import validate_canonical_identity
from scripts import benchmark_delta
from scripts.check_benchmark_product_contract import validate as validate_policy
from scripts.tests.native_proof_matrix_support import product_identity
from scripts.tests.test_benchmark_delta import write_json
from scripts.tests.test_native_matrix_phase1_evidence import native_v4_report


def functional_descriptor(name: str, parameters: dict[str, int]) -> str:
    parameter_order = {
        "wide_fibonacci": ("log_n_rows", "sequence_len"),
        "xor": ("log_size", "log_step", "offset"),
        "plonk": ("log_n_rows",),
        "poseidon": ("log_n_instances",),
    }
    fields = ["native-proof-workload-v3", f"example={name}"]
    fields.extend(f"{key}={parameters[key]}" for key in parameter_order[name])
    if name == "xor":
        fields.append("air_protocol=raw-stwo-xor-lookup-v2")
    elif name == "poseidon":
        fields.append("air_protocol=raw-stwo-poseidon-logup-split2-v1")
    fields.extend((
        "protocol=functional",
        "pow_bits=10",
        "log_blowup_factor=1",
        "log_last_layer_degree_bound=0",
        "n_queries=3",
        "fold_step=1",
    ))
    return hashlib.sha256("|".join(fields).encode("ascii")).hexdigest()


def measurement() -> dict[str, object]:
    return {
        "workload": {
            "name": "wide_fibonacci",
            "parameters": {"log_n_rows": 10, "sequence_len": 8},
            "trace_log_rows": 10,
            "trace_rows": 1024,
            "committed_trees": 2,
            "committed_columns": 8,
            "committed_trace_cells": 8192,
            "native_unit": "trace_rows",
            "native_units": 1024,
            "descriptor_sha256": functional_descriptor(
                "wide_fibonacci", {"log_n_rows": 10, "sequence_len": 8}
            ),
        },
        "numerator": {"unit": "trace_rows", "units": 1024},
        "security_profile": {
            "name": "functional",
            "pow_bits": 10,
            "log_blowup_factor": 1,
            "log_last_layer_degree_bound": 0,
            "n_queries": 3,
            "fold_step": 1,
        },
        "timing_scope": {
            "headline": "prove_seconds",
            "total": "request_seconds",
            "included": [
                "input_seconds",
                "prove_seconds",
                "proof_encode_seconds",
                "verify_seconds",
            ],
            "backend_init": "reported_separately",
        },
        "cold_warm_state": {
            "backend_initialization": "once_before_warmups",
            "warmups_excluded": 10,
            "measured_samples": 10,
            "sample_state": "post_warmup",
            "metal_runtime": "not_applicable",
        },
        "proof_status": {
            "local_verification": True,
            "verified_samples": 10,
            "byte_identical_samples": True,
            "cross_backend_canonical_equality": True,
            "pinned_rust_stwo_verified": True,
            "proof_sha256": "5" * 64,
        },
        "eligibility_status": {
            "headline_eligible": True,
            "stability_satisfied": True,
            "evidence_class": "verified_unprofiled",
            "profiled": False,
        },
    }


def benchmark_policy() -> dict[str, object]:
    return {
        "execution": "sequential_alternating_lane_order",
        "proof_protocol": "functional",
        "formal": True,
        "profiled": False,
        "final_correctness_oracle": "pinned Rust Stwo",
        "minimum_excluded_warmups": 10,
        "minimum_verified_samples": 10,
        "every_measured_proof_locally_verified": True,
        "cross_backend_canonical_proof_equality": True,
    }


def profile_measurement() -> dict[str, object]:
    result = measurement()
    result["timing_scope"] = {
        "headline": None,
        "diagnostic": "instrumented_verified_request",
        "host_timers": ["prove_seconds"],
        "gpu_timers": None,
    }
    result["cold_warm_state"].update({
        "measured_samples": 1,
        "sample_state": "profiled_post_warmup_diagnostic",
    })
    result["proof_status"].update({
        "verified_samples": 1,
        "pinned_rust_stwo_verified": False,
    })
    result["eligibility_status"] = {
        "headline_eligible": False,
        "stability_satisfied": False,
        "evidence_class": "profiled_diagnostic",
        "profiled": True,
    }
    return result


def resign(receipt: dict[str, object]) -> None:
    payload = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    receipt["receipt_sha256"] = hashlib.sha256(encoded).hexdigest()


def v6_report(commit: str, binary_suffix: str, *, cpu_model: str = "apple_m1") -> dict:
    report = native_v4_report(commit, binary_suffix, 2048)
    report["schema_version"] = 6
    report["protocol"] = benchmark_delta.NATIVE_PROTOCOL_V6
    report["configuration"]["host_environment"] = {
        "schema": "native_matrix_host_environment_v1",
        "machine": "test",
    }
    report["configuration"]["host_load"] = {
        "start": {"schema": "native_matrix_host_load_v1"},
        "end": {"schema": "native_matrix_host_load_v1"},
    }
    row = report["rows"][0]
    row["descriptor_sha256"] = functional_descriptor("plonk", {"log_n_rows": 10})
    row["workload"] = {
        "name": "plonk",
        "parameters": {"log_n_rows": 10},
        "trace_log_rows": 10,
        "trace_rows": 1024,
        "committed_trees": 2,
        "committed_columns": 8,
        "committed_trace_cells": 8192,
        "native_unit": "plonk_rows",
        "native_units": 1024,
    }
    receipts = {}
    for lane in ("cpu", "metal"):
        identity = product_identity(lane)
        identity["implementation_commit"] = commit
        identity["cpu_model"] = cpu_model
        identity["identity_sha256"] = canonical_identity_sha256(identity)
        lane_row = row["lanes"][lane]
        lane_row["product_identity"] = identity
        lane_row["proof"] = {
            "verified_samples": 10,
            "all_samples_byte_identical": True,
        }
        lane_measurement = measurement()
        lane_measurement["workload"] = {
            **row["workload"],
            "descriptor_sha256": row["descriptor_sha256"],
        }
        lane_measurement["numerator"] = {"unit": "plonk_rows", "units": 1024}
        lane_measurement["proof_status"]["proof_sha256"] = row[
            "proof_digest_sha256"
        ]
        lane_measurement["eligibility_status"] = {
            "headline_eligible": True,
            "stability_satisfied": True,
            "evidence_class": "verified_unprofiled",
            "profiled": False,
        }
        lane_row["evidence_class"] = "verified_unprofiled"
        lane_row["profiled"] = False
        if lane == "metal":
            lane_measurement["cold_warm_state"]["metal_runtime"] = "source-jit"
        receipts[lane] = build_receipt(
            lane=lane,
            evidence_kind="benchmark",
            product_identity=identity,
            executable_sha256=binary_suffix * 64,
            measurement_policy=benchmark_policy(),
            host_device=report["configuration"]["host_environment"],
            measurements=[lane_measurement],
            promotion_eligible=True,
        )
    report["product_receipts"] = receipts
    return report


class BenchmarkProductContractTests(unittest.TestCase):
    def test_independent_identity_digest_matches_and_mutations_fail_closed(self) -> None:
        identity = product_identity("cpu")
        validate_product_identity(identity, "cpu")
        for field, mutation in (
            ("name", "stwo-native-metal"),
            ("role", "cli"),
            ("protocol_features", "changed"),
            ("implementation_commit", "9" * 40),
            ("cpu_features_sha256", "8" * 64),
            ("runtime_manifest", "unexpected"),
            ("identity_sha256", "7" * 64),
        ):
            changed = copy.deepcopy(identity)
            changed[field] = mutation
            with self.subTest(field=field), self.assertRaises(ProductEvidenceError):
                validate_product_identity(changed, "cpu")

    def test_metal_identity_requires_exact_source_jit_build_manifests(self) -> None:
        identity = product_identity("metal")
        validate_product_identity(identity, "metal")
        mutations = (
            (
                "legacy_runtime",
                "runtime_manifest",
                "metal-runtime-v1:source-jit+authenticated-aot",
            ),
            (
                "aot_mode",
                "runtime_manifest",
                identity["runtime_manifest"].replace(
                    "mode=source-jit", "mode=authenticated-aot"
                ),
            ),
            (
                "invalid_shader_digest",
                "runtime_manifest",
                identity["runtime_manifest"].replace("5" * 64, "not-a-digest"),
            ),
            (
                "legacy_sdk",
                "sdk_manifest",
                "apple-metal-sdk:metal3.1:safe-math",
            ),
            (
                "aot_manifest",
                "aot_manifest",
                "metal-aot-v1:source+compile-profile+metallib-sha256",
            ),
        )
        for name, field, value in mutations:
            changed = copy.deepcopy(identity)
            changed[field] = value
            changed["identity_sha256"] = canonical_identity_sha256(changed)
            with self.subTest(name=name), self.assertRaises(ProductEvidenceError):
                validate_product_identity(changed, "metal")

    def test_generic_identity_validator_has_no_benchmark_lane_policy(self) -> None:
        products = (
            ("stwo-core", "none", "none", "library", "stwo-core-v1"),
            (
                "stwo-prover",
                "none",
                "contracts",
                "library",
                "generic-prover+backend-contracts-v1",
            ),
            (
                "stwo-riscv-cpu",
                "stark-v-rv32im",
                "cpu",
                "benchmark",
                "stark-v-rv32im-v1+lifted-pcs-v1",
            ),
            ("stwo-zig", "aggregate", "cpu", "gate", "aggregate-gate-v1"),
        )
        for name, frontend, backend, role, features in products:
            identity = product_identity("cpu")
            identity.update({
                "name": name,
                "frontend": frontend,
                "backend": backend,
                "role": role,
                "protocol_features": features,
            })
            identity["protocol_manifest_sha256"] = hashlib.sha256(features.encode()).hexdigest()
            identity["identity_sha256"] = canonical_identity_sha256(identity)
            with self.subTest(name=name):
                self.assertIs(validate_canonical_identity(identity), identity)
                with self.assertRaises(ProductEvidenceError):
                    validate_product_identity(identity, "cpu")

    def test_receipt_binds_product_executable_and_verified_proof(self) -> None:
        identity = product_identity("cpu")
        host_device = {
            "machine": "test",
            "metal_device": {
                "name": "Apple M5 Max",
                "runtime_identity": "metal-runtime-v1:source-jit+authenticated-aot",
            },
        }
        receipt = build_receipt(
            lane="cpu",
            evidence_kind="benchmark",
            product_identity=identity,
            executable_sha256="6" * 64,
            measurement_policy=benchmark_policy(),
            host_device=host_device,
            measurements=[measurement()],
            promotion_eligible=True,
        )
        validate_receipt(
            receipt,
            lane="cpu",
            evidence_kind="benchmark",
            expected_identity=identity,
            expected_executable_sha256="6" * 64,
            expected_host_device=host_device,
        )
        for mutation, expected in (
            (lambda value: value.__setitem__("executable_sha256", "0" * 64), "executable"),
            (
                lambda value: value["measurements"][0]["proof_status"].__setitem__(
                    "local_verification", False
                ),
                "locally verified",
            ),
            (lambda value: value.__setitem__("receipt_sha256", "0" * 64), "digest"),
        ):
            changed = copy.deepcopy(receipt)
            mutation(changed)
            with self.subTest(expected=expected), self.assertRaisesRegex(
                ProductEvidenceError, expected
            ):
                validate_receipt(
                    changed,
                    lane="cpu",
                    evidence_kind="benchmark",
                    expected_identity=identity,
                    expected_executable_sha256="6" * 64,
                    expected_host_device=host_device,
                )

        changed = copy.deepcopy(receipt)
        changed["host_device"]["metal_device"]["runtime_identity"] = (
            "metal-runtime-v1:substituted"
        )
        resign(changed)
        with self.assertRaisesRegex(ProductEvidenceError, "host/device identity changed"):
            validate_receipt(
                changed,
                lane="cpu",
                evidence_kind="benchmark",
                expected_identity=identity,
                expected_executable_sha256="6" * 64,
                expected_host_device=host_device,
            )

    def test_receipt_accepts_exact_xor_geometry_and_identity(self) -> None:
        xor = measurement()
        parameters = {"log_size": 8, "log_step": 3, "offset": 5}
        xor["workload"] = {
            "name": "xor",
            "parameters": parameters,
            "trace_log_rows": 8,
            "trace_rows": 256,
            "committed_trees": 3,
            "committed_columns": 15,
            "committed_trace_cells": 3_840,
            "native_unit": "xor_rows",
            "native_units": 256,
            "descriptor_sha256": functional_descriptor("xor", parameters),
        }
        xor["numerator"] = {"unit": "xor_rows", "units": 256}
        identity = product_identity("cpu")
        host_device = {"machine": "test"}
        receipt = build_receipt(
            lane="cpu",
            evidence_kind="benchmark",
            product_identity=identity,
            executable_sha256="6" * 64,
            measurement_policy=benchmark_policy(),
            host_device=host_device,
            measurements=[xor],
            promotion_eligible=True,
        )
        validate_receipt(
            receipt,
            lane="cpu",
            evidence_kind="benchmark",
            expected_identity=identity,
            expected_executable_sha256="6" * 64,
            expected_host_device=host_device,
        )

    def test_receipt_accepts_exact_poseidon_geometry_and_identity(self) -> None:
        poseidon = measurement()
        parameters = {"log_n_instances": 13}
        poseidon["workload"] = {
            "name": "poseidon",
            "parameters": parameters,
            "trace_log_rows": 10,
            "trace_rows": 1_024,
            "committed_trees": 3,
            "committed_columns": 1_296,
            "committed_trace_cells": 1_327_104,
            "native_unit": "poseidon_instances",
            "native_units": 8_192,
            "descriptor_sha256": functional_descriptor("poseidon", parameters),
        }
        poseidon["numerator"] = {"unit": "poseidon_instances", "units": 8_192}
        identity = product_identity("cpu")
        host_device = {"machine": "test"}
        receipt = build_receipt(
            lane="cpu",
            evidence_kind="benchmark",
            product_identity=identity,
            executable_sha256="6" * 64,
            measurement_policy=benchmark_policy(),
            host_device=host_device,
            measurements=[poseidon],
            promotion_eligible=True,
        )
        validate_receipt(
            receipt,
            lane="cpu",
            evidence_kind="benchmark",
            expected_identity=identity,
            expected_executable_sha256="6" * 64,
            expected_host_device=host_device,
        )

    def test_promotion_claim_fails_closed_for_every_blocker(self) -> None:
        receipt = build_receipt(
            lane="cpu",
            evidence_kind="benchmark",
            product_identity=product_identity("cpu"),
            executable_sha256="6" * 64,
            measurement_policy=benchmark_policy(),
            host_device={"machine": "test"},
            measurements=[measurement()],
            promotion_eligible=True,
        )
        blockers = (
            ("nonformal", lambda value: value["measurement_policy"].__setitem__("formal", False)),
            ("profiled", lambda value: value["measurement_policy"].__setitem__("profiled", True)),
            (
                "rust_oracle",
                lambda value: value["measurements"][0]["proof_status"].__setitem__(
                    "pinned_rust_stwo_verified", False
                ),
            ),
            (
                "byte_identity",
                lambda value: value["measurements"][0]["proof_status"].__setitem__(
                    "byte_identical_samples", False
                ),
            ),
            (
                "cross_backend",
                lambda value: value["measurements"][0]["proof_status"].__setitem__(
                    "cross_backend_canonical_equality", False
                ),
            ),
            (
                "warmups",
                lambda value: value["measurements"][0]["cold_warm_state"].__setitem__(
                    "warmups_excluded", 9
                ),
            ),
            (
                "under_sampled",
                lambda value: (
                    value["measurements"][0]["cold_warm_state"].__setitem__(
                        "measured_samples", 9
                    ),
                    value["measurements"][0]["proof_status"].__setitem__(
                        "verified_samples", 9
                    ),
                ),
            ),
            (
                "headline",
                lambda value: value["measurements"][0]["eligibility_status"].__setitem__(
                    "headline_eligible", False
                ),
            ),
            (
                "stability",
                lambda value: value["measurements"][0]["eligibility_status"].__setitem__(
                    "stability_satisfied", False
                ),
            ),
        )
        for name, mutation in blockers:
            changed = copy.deepcopy(receipt)
            mutation(changed)
            resign(changed)
            with self.subTest(name=name), self.assertRaisesRegex(
                ProductEvidenceError, "promotion eligibility"
            ):
                validate_receipt(changed, lane="cpu", evidence_kind="benchmark")

        changed = copy.deepcopy(receipt)
        changed["measurements"][0]["proof_status"]["verified_samples"] = 9
        resign(changed)
        with self.assertRaisesRegex(ProductEvidenceError, "verified samples differ"):
            validate_receipt(changed, lane="cpu", evidence_kind="benchmark")

    def test_receipt_rejects_nonfinite_and_unknown_nested_shapes(self) -> None:
        receipt = build_receipt(
            lane="cpu",
            evidence_kind="benchmark",
            product_identity=product_identity("cpu"),
            executable_sha256="6" * 64,
            measurement_policy=benchmark_policy(),
            host_device={"machine": "test"},
            measurements=[measurement()],
            promotion_eligible=True,
        )
        changed = copy.deepcopy(receipt)
        changed["host_device"]["load"] = float("nan")
        with self.assertRaisesRegex(ProductEvidenceError, "non-finite"):
            validate_receipt(changed, lane="cpu", evidence_kind="benchmark")

        changed = copy.deepcopy(receipt)
        changed["measurement_policy"]["unknown"] = True
        resign(changed)
        with self.assertRaisesRegex(ProductEvidenceError, "unsupported schema"):
            validate_receipt(changed, lane="cpu", evidence_kind="benchmark")

    def test_profile_receipts_are_never_promotion_eligible(self) -> None:
        with self.assertRaisesRegex(ProductEvidenceError, "promotion eligibility"):
            build_receipt(
                lane="cpu",
                evidence_kind="profile",
                product_identity=product_identity("cpu"),
                executable_sha256=hashlib.sha256(b"cpu").hexdigest(),
                measurement_policy={
                    "execution": "bounded_sequential_cpu_then_metal",
                    "proof_protocol": "functional",
                    "profiled_diagnostic": True,
                    "headline_eligible": False,
                    "every_measured_proof_locally_verified": True,
                    "cross_backend_canonical_proof_equality": True,
                    "final_correctness_oracle_checked": False,
                },
                host_device={"machine": "test"},
                measurements=[profile_measurement()],
                promotion_eligible=True,
            )

    def test_machine_policy_matches_live_commands_and_aliases(self) -> None:
        self.assertEqual(validate_policy()["status"], "ok")

    def test_v5_history_maps_forward_to_focused_v6_without_orphaning_rows(self) -> None:
        baseline = native_v4_report("a" * 40, "3", 2048)
        baseline["schema_version"] = 5
        baseline["protocol"] = benchmark_delta.NATIVE_PROTOCOL_V5
        baseline["rows"][0]["workload"] = {
            "name": "plonk",
            "parameters": {"log_n_rows": 10},
            "trace_log_rows": 10,
            "trace_rows": 1024,
            "committed_trees": 2,
            "committed_columns": 8,
            "committed_trace_cells": 8192,
            "native_unit": "plonk_rows",
            "native_units": 1024,
        }
        baseline["rows"][0]["descriptor_sha256"] = functional_descriptor(
            "plonk", {"log_n_rows": 10}
        )
        current = v6_report("b" * 40, "4")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_path = root / "baseline.json"
            current_path = root / "current.json"
            write_json(baseline_path, baseline)
            write_json(current_path, current)
            delta, _, _ = benchmark_delta.compare_reports(
                baseline_path, current_path, "2026-07-19T12:00:00Z"
            )
        self.assertEqual(delta["status"], "comparable")
        transition = delta["comparison_identity"]["product_identity_transition"]
        self.assertEqual(transition["kind"], "explicit_historical_alias")
        self.assertEqual(
            transition["aliases"]["cpu"]["focused_product"], "stwo-native-cpu"
        )

    def test_v6_delta_rejects_product_or_executable_identity_drift(self) -> None:
        baseline = v6_report("a" * 40, "3")
        for mutation, expected in (
            (
                lambda report: report["configuration"]["binaries"]["cpu"].__setitem__(
                    "sha256", "9" * 64
                ),
                "executable",
            ),
            (
                lambda report: report["rows"][0]["lanes"]["cpu"][
                    "product_identity"
                ].__setitem__("role", "cli"),
                "product evidence",
            ),
        ):
            current = v6_report("b" * 40, "4")
            mutation(current)
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                baseline_path = root / "baseline.json"
                current_path = root / "current.json"
                write_json(baseline_path, baseline)
                write_json(current_path, current)
                with self.assertRaisesRegex(benchmark_delta.DeltaError, expected):
                    benchmark_delta.compare_reports(
                        baseline_path, current_path, "2026-07-19T12:00:00Z"
                    )

        current = v6_report("b" * 40, "4")
        current["product_receipts"]["cpu"]["host_device"] = {
            "schema": "native_matrix_host_environment_v1",
            "machine": "substituted-host",
            "metal_device": {"runtime_identity": "substituted-metal-runtime"},
        }
        resign(current["product_receipts"]["cpu"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_path = root / "baseline.json"
            current_path = root / "current.json"
            write_json(baseline_path, baseline)
            write_json(current_path, current)
            with self.assertRaisesRegex(benchmark_delta.DeltaError, "host/device identity"):
                benchmark_delta.compare_reports(
                    baseline_path, current_path, "2026-07-19T12:00:00Z"
                )

        current = v6_report("b" * 40, "4", cpu_model="apple_m2")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_path = root / "baseline.json"
            current_path = root / "current.json"
            write_json(baseline_path, baseline)
            write_json(current_path, current)
            delta, _, _ = benchmark_delta.compare_reports(
                baseline_path, current_path, "2026-07-19T12:00:00Z"
            )
        self.assertEqual(delta["status"], "incomparable")
        self.assertIn("product configuration", delta["incompatibilities"][0])

    def test_v6_delta_compares_metal_code_artifact_revisions(self) -> None:
        baseline = v6_report("a" * 40, "3")
        current = v6_report("b" * 40, "4")
        identity = current["rows"][0]["lanes"]["metal"]["product_identity"]
        identity["runtime_manifest"] = identity["runtime_manifest"].replace(
            "5" * 64, "9" * 64
        ).replace("6" * 64, "a" * 64)
        identity["identity_sha256"] = canonical_identity_sha256(identity)
        receipt = current["product_receipts"]["metal"]
        receipt["product_identity"] = copy.deepcopy(identity)
        resign(receipt)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_path = root / "baseline.json"
            current_path = root / "current.json"
            write_json(baseline_path, baseline)
            write_json(current_path, current)
            delta, _, _ = benchmark_delta.compare_reports(
                baseline_path, current_path, "2026-07-19T12:00:00Z"
            )

        self.assertEqual(delta["status"], "comparable")
        transition = delta["comparison_identity"]["product_identity_transition"]
        self.assertEqual(
            transition["products"]["metal"]["runtime_configuration"]["mode"],
            "source-jit",
        )
        revisions = transition["artifact_revisions"]["metal"]
        self.assertNotEqual(
            revisions["baseline"]["runtime_manifest"],
            revisions["current"]["runtime_manifest"],
        )

    def test_v6_delta_rejects_metal_sdk_configuration_drift(self) -> None:
        baseline = v6_report("a" * 40, "3")
        current = v6_report("b" * 40, "4")
        identity = current["rows"][0]["lanes"]["metal"]["product_identity"]
        identity["sdk_manifest"] = identity["sdk_manifest"].replace(
            "sdk-version=15.0", "sdk-version=16.0"
        )
        identity["identity_sha256"] = canonical_identity_sha256(identity)
        receipt = current["product_receipts"]["metal"]
        receipt["product_identity"] = copy.deepcopy(identity)
        resign(receipt)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_path = root / "baseline.json"
            current_path = root / "current.json"
            write_json(baseline_path, baseline)
            write_json(current_path, current)
            delta, _, _ = benchmark_delta.compare_reports(
                baseline_path, current_path, "2026-07-19T12:00:00Z"
            )

        self.assertEqual(delta["status"], "incomparable")
        self.assertIn("product configuration", delta["incompatibilities"][0])

    def test_v6_delta_ignores_metal_tool_path_relocation(self) -> None:
        baseline = v6_report("a" * 40, "3")
        current = v6_report("b" * 40, "4")
        identity = current["rows"][0]["lanes"]["metal"]["product_identity"]
        identity["sdk_manifest"] = identity["sdk_manifest"].replace(
            "/Applications/Xcode.app/SDKs/MacOSX.sdk", "/opt/Xcode/SDKs/MacOSX.sdk"
        ).replace("/usr/bin/clang", "/opt/Xcode/usr/bin/clang")
        identity["identity_sha256"] = canonical_identity_sha256(identity)
        receipt = current["product_receipts"]["metal"]
        receipt["product_identity"] = copy.deepcopy(identity)
        resign(receipt)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_path = root / "baseline.json"
            current_path = root / "current.json"
            write_json(baseline_path, baseline)
            write_json(current_path, current)
            delta, _, _ = benchmark_delta.compare_reports(
                baseline_path, current_path, "2026-07-19T12:00:00Z"
            )

        self.assertEqual(delta["status"], "comparable")

    def test_v6_delta_rejects_unbound_metal_artifact_substitution(self) -> None:
        baseline = v6_report("a" * 40, "3")
        current = copy.deepcopy(baseline)
        identity = current["rows"][0]["lanes"]["metal"]["product_identity"]
        identity["runtime_manifest"] = identity["runtime_manifest"].replace(
            "5" * 64, "9" * 64
        )
        identity["identity_sha256"] = canonical_identity_sha256(identity)
        receipt = current["product_receipts"]["metal"]
        receipt["product_identity"] = copy.deepcopy(identity)
        resign(receipt)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_path = root / "baseline.json"
            current_path = root / "current.json"
            write_json(baseline_path, baseline)
            write_json(current_path, current)
            with self.assertRaisesRegex(
                benchmark_delta.DeltaError, "without a source or executable revision"
            ):
                benchmark_delta.compare_reports(
                    baseline_path, current_path, "2026-07-19T12:00:00Z"
                )


if __name__ == "__main__":
    unittest.main()
