from __future__ import annotations

import datetime as dt
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.autoresearch_activation_lib.contract import (
    SETTINGS_SCHEMA,
    activation_errors,
    validate_settings_receipt,
)
from scripts.autoresearch_activation_lib.github import (
    SettingsCaptureError,
    build_settings_receipt,
)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def settings_receipt() -> dict:
    payload = {
        "ruleset_enforcement": "active",
        "non_fast_forward": True,
        "required_status_checks": [
            {"context": "autoresearch-judge", "integration_id": 15368},
            {"context": "autoresearch-validate", "integration_id": 15368},
        ],
        "bypass_actors": [
            {"actor_id": None, "actor_type": "DeployKey", "bypass_mode": "always"},
        ],
        "write_deploy_keys": [{
            "id": 157962927,
            "title": "autoresearch-publisher",
            "verified": True,
            "read_only": False,
        }],
    }
    return {
        "schema": SETTINGS_SCHEMA,
        "repository": "teddyjfpender/stwo-zig",
        "default_branch": "main",
        "source": "github-api",
        "observed_at": "2026-07-21T12:00:00+00:00",
        "payload": payload,
        "payload_sha256": hashlib.sha256(canonical(payload)).hexdigest(),
    }


class SettingsReceiptTest(unittest.TestCase):
    def test_valid_receipt_binds_required_checks(self) -> None:
        errors = validate_settings_receipt(
            settings_receipt(),
            repository="teddyjfpender/stwo-zig",
            now=dt.datetime(2026, 7, 21, 12, 15, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(errors, [])

    def test_digest_and_check_tampering_fail(self) -> None:
        receipt = settings_receipt()
        receipt["payload"]["required_status_checks"] = [
            {"context": "autoresearch-validate", "integration_id": 15368},
        ]
        errors = validate_settings_receipt(
            receipt,
            repository="teddyjfpender/stwo-zig",
            now=dt.datetime(2026, 7, 21, 12, 15, tzinfo=dt.timezone.utc),
        )
        self.assertIn("GitHub settings receipt payload digest mismatches", errors)

    def test_authenticated_capture_reduces_active_main_rules(self) -> None:
        receipt = build_settings_receipt(
            "example/repo",
            {"default_branch": "main"},
            [{
                "id": 17,
                "name": "main",
                "enforcement": "active",
                "bypass_actors": [{
                    "actor_id": None,
                    "actor_type": "DeployKey",
                    "bypass_mode": "always",
                }],
                "updated_at": "2026-07-21T12:00:00Z",
                "conditions": {
                    "ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []},
                },
                "rules": [
                    {"type": "non_fast_forward"},
                    {
                        "type": "required_status_checks",
                        "parameters": {"required_status_checks": [
                            {"context": "autoresearch-judge", "integration_id": 15368},
                            {"context": "autoresearch-validate", "integration_id": 15368},
                        ]},
                    },
                ],
            }],
            [{
                "id": 157962927,
                "title": "autoresearch-publisher",
                "verified": True,
                "read_only": False,
            }],
            observed_at=dt.datetime(2026, 7, 21, 12, 0, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(receipt["source"], "github-api")
        self.assertEqual(
            receipt["payload"]["required_status_checks"],
            [
                {"context": "autoresearch-judge", "integration_id": 15368},
                {"context": "autoresearch-validate", "integration_id": 15368},
            ],
        )
        self.assertTrue(receipt["payload"]["non_fast_forward"])
        self.assertEqual(
            validate_settings_receipt(
                receipt,
                repository="example/repo",
                now=dt.datetime(2026, 7, 21, 12, 1, tzinfo=dt.timezone.utc),
            ),
            [],
        )

    def test_capture_rejects_ruleset_for_another_branch(self) -> None:
        with self.assertRaises(SettingsCaptureError):
            build_settings_receipt(
                "example/repo",
                {"default_branch": "main"},
                [{
                    "id": 17,
                    "name": "release",
                    "enforcement": "active",
                    "bypass_actors": [],
                    "updated_at": "2026-07-21T12:00:00Z",
                    "conditions": {
                        "ref_name": {
                            "include": ["refs/heads/release"],
                            "exclude": [],
                        },
                    },
                    "rules": [{"type": "non_fast_forward"}],
                }],
                [],
            )


class ActivationContractTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "autoresearch/ledger").mkdir(parents=True)
        (self.root / ".github/workflows").mkdir(parents=True)
        (self.root / "src/products/riscv_cpu").mkdir(parents=True)
        (self.root / "src/interop").mkdir(parents=True)
        (self.root / "conformance/riscv").mkdir(parents=True)
        (self.root / "autoresearch/reference/riscv-calibration-epoch-2").mkdir(
            parents=True
        )
        candidate = "a" * 40
        sail_evidence = {
            "schema": "stwo-riscv-formal-corpus-evidence-v1",
            "result": "equivalent",
            "semantic_authority": "Sail",
            "independent_cross_check": "Spike",
            "programs": 17,
            "retirements": 472827,
            "sail": {
                "repository_revision": "8c7f2da58de0ba5e4457e4de07e0046f0439f35f",
            },
        }
        evidence_path = self.root / "conformance/riscv/formal-corpus-evidence.json"
        evidence_path.write_bytes(canonical(sail_evidence))
        evidence_digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        calibration_classes = {}
        for index, workload_class in enumerate(("small", "wide", "deep"), 1):
            raw_receipt = {
                "board": "riscv",
                "workload_class": workload_class,
                "anchor_prove_ms": float(index),
            }
            raw_path = (
                self.root
                / f"autoresearch/reference/riscv-calibration-epoch-2/{workload_class}.json"
            )
            raw_path.write_bytes(canonical(raw_receipt))
            calibration_classes[workload_class] = {
                "anchor_prove_ms": float(index),
                "dispersion": 0.01,
                "ci": [0.99, 1.01],
                "receipt": str(raw_path.relative_to(self.root)),
                "receipt_sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
            }
        calibration = {
            "schema": "stwo_perf_riscv_calibration_freeze_v1",
            "status": "frozen",
            "board": "riscv",
            "epoch": 1,
            "repository": {
                "commit": "c" * 40, "tree": "b" * 40, "dirty": False,
            },
            "host": {"chip": "Apple M5 Max", "logical_cpu_count": 18},
            "oracle": {
                "authority": "stark-v",
                "commit": "d478f783055aa0d73a93768a433a3c6c31c91d1c",
                "required_features": ["parallel"],
                "release_anchor_candidate": candidate,
                "release_anchor_sha256": "f" * 64,
            },
            "classes": calibration_classes,
        }
        calibration_path = self.root / "autoresearch/reference/riscv-calibration.json"
        calibration_path.write_bytes(canonical(calibration))
        calibration_digest = hashlib.sha256(calibration_path.read_bytes()).hexdigest()
        workloads = {}
        pools = {}
        for workload_class in ("small", "wide", "deep"):
            members = []
            for index in range(2):
                workload_id = f"riscv_{workload_class}_{index}"
                members.append(workload_id)
                workloads[workload_id] = {
                    "class": workload_class,
                    "args": (
                        f"bench --elf vectors/{workload_id}.elf --backend cpu "
                        "--protocol functional {admission} --warmups {warmups} "
                        "--samples {samples}"
                    ),
                    "native_unit": "executed instructions",
                }
            pools[workload_class] = members
        manifest = {
            "harness": {
                "anchor_prove_ms": {
                    "riscv": {"small": 1.0, "wide": 2.0, "deep": 3.0},
                },
                "riscv_calibration": {
                    "schema": "stwo_perf_riscv_calibration_freeze_v1",
                    "status": "frozen",
                    "board": "riscv",
                    "epoch": 1,
                    "artifact": str(calibration_path.relative_to(self.root)),
                    "artifact_sha256": calibration_digest,
                    "measured_commit": "c" * 40,
                    "designated_host": {
                        "chip": "Apple M5 Max", "logical_cpu_count": 18,
                    },
                },
            },
            "workload_registry": {
                "classes": {
                    name: {"scored": True}
                    for name in ("small", "wide", "deep", "xlarge", "huge")
                },
                "groups": {"riscv": {
                "enabled": True,
                "promotion_eligible": True,
                "board": "riscv",
                "report_schema": "riscv_proof_v2",
                "correctness_oracle": {
                    "authority": "sail-riscv",
                    "repository": "https://github.com/riscv/sail-riscv",
                    "commit": "8c7f2da58de0ba5e4457e4de07e0046f0439f35f",
                    "final_validator": True,
                    "evidence": {
                        "path": "conformance/riscv/formal-corpus-evidence.json",
                        "sha256": evidence_digest,
                    },
                    "benchmark_reference": {
                        "authority": "stark-v",
                        "commit": "d478f783055aa0d73a93768a433a3c6c31c91d1c",
                        "required_features": ["parallel"],
                    },
                },
                "gates_policy": {
                    "samples_per_round": 1, "min_rounds": 3, "max_rounds": 5,
                },
                "mechanism_telemetry": {
                    "fail_closed": True,
                    "required_fields": [
                        "total_steps", "n_components", "mean_proving_seconds",
                        "statement_sha256",
                    ],
                },
                "resource_telemetry": {
                    "fail_closed": True,
                    "source": "darwin.proc_pid_rusage.RUSAGE_INFO_V6",
                    "scope": "self_process_lifetime",
                    "sampling_points": [
                        "before_warmups", "after_verified_samples",
                    ],
                    "fields": [
                        "lifetime_max_phys_footprint_bytes", "energy_nj",
                        "instructions", "cycles",
                    ],
                },
                "holdout_generator": {
                    "strategy": "seeded_workload_pool_v1", "pools": pools,
                },
                "workloads": workloads,
            }}},
        }
        (self.root / "autoresearch/MANIFEST.json").write_text(json.dumps(manifest))
        epochs = {"epochs": [{"epoch": 1, "aa_dispersion": {"riscv": {
            "small": 0.01, "wide": 0.01, "deep": 0.01,
        }}}]}
        (self.root / "autoresearch/ledger/epochs.json").write_text(json.dumps(epochs))
        (self.root / ".github/workflows/judge.yml").write_text(
            "name: autoresearch-judge\n"
        )
        (self.root / ".github/workflows/promote.yml").write_text(
            "name: autoresearch-promote\n"
        )
        (self.root / "src/products/riscv_cpu/capabilities.zig").write_text(
            "pub const adapter_release_gated = true;\n"
        )
        (self.root / "src/interop/riscv_artifact.zig").write_text(
            'pub const RELEASE_STATUS = "release_gated";\n'
        )
        self.receipt = self.root / "settings.json"
        receipt = settings_receipt()
        receipt["observed_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        self.receipt.write_text(json.dumps(receipt))

    def test_complete_activation_contract_passes(self) -> None:
        self.assertEqual(activation_errors(
            self.root,
            board="riscv",
            settings_receipt=self.receipt,
            repository="teddyjfpender/stwo-zig",
        ), [])

    def test_skeletal_sail_evidence_cannot_activate_a_board(self) -> None:
        evidence = self.root / "conformance/riscv/formal-corpus-evidence.json"
        evidence.write_text("{}")
        manifest_path = self.root / "autoresearch/MANIFEST.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["workload_registry"]["groups"]["riscv"]["correctness_oracle"][
            "evidence"
        ]["sha256"] = hashlib.sha256(evidence.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
        errors = activation_errors(
            self.root,
            board="riscv",
            settings_receipt=self.receipt,
            repository="teddyjfpender/stwo-zig",
        )
        self.assertIn("RISC-V Sail evidence identity or verdict is invalid", errors)

    def test_non_finite_calibration_cannot_activate_a_board(self) -> None:
        path = self.root / "autoresearch/MANIFEST.json"
        manifest = json.loads(path.read_text())
        manifest["harness"]["anchor_prove_ms"]["riscv"]["small"] = float("inf")
        path.write_text(json.dumps(manifest))
        errors = activation_errors(
            self.root,
            board="riscv",
            settings_receipt=self.receipt,
            repository="teddyjfpender/stwo-zig",
        )
        self.assertIn("RISC-V small anchor is not frozen", errors)

    def test_disabled_board_and_irrelevant_holdout_fail(self) -> None:
        path = self.root / "autoresearch/MANIFEST.json"
        manifest = json.loads(path.read_text())
        group = manifest["workload_registry"]["groups"]["riscv"]
        group["enabled"] = False
        group["promotion_eligible"] = False
        group["holdout_generator"]["pools"]["small"] = ["unknown", "missing"]
        path.write_text(json.dumps(manifest))
        errors = activation_errors(
            self.root,
            board="riscv",
            settings_receipt=self.receipt,
            repository="teddyjfpender/stwo-zig",
        )
        self.assertIn("board riscv is disabled", errors)
        self.assertIn("board riscv is not promotion eligible", errors)
        self.assertTrue(any("holdout references" in error for error in errors))

    def test_resource_contract_drift_blocks_activation(self) -> None:
        path = self.root / "autoresearch/MANIFEST.json"
        manifest = json.loads(path.read_text())
        manifest["workload_registry"]["groups"]["riscv"][
            "resource_telemetry"
        ]["source"] = "getrusage"
        path.write_text(json.dumps(manifest))
        errors = activation_errors(
            self.root,
            board="riscv",
            settings_receipt=self.receipt,
            repository="teddyjfpender/stwo-zig",
        )
        self.assertTrue(any("resource telemetry" in error for error in errors))

    def test_tampered_sail_evidence_and_staged_phase_fail(self) -> None:
        evidence = self.root / "conformance/riscv/formal-corpus-evidence.json"
        evidence.write_text("{}")
        (self.root / "src/products/riscv_cpu/capabilities.zig").write_text(
            "pub const adapter_release_gated = false;\n"
        )
        errors = activation_errors(
            self.root,
            board="riscv",
            settings_receipt=self.receipt,
            repository="teddyjfpender/stwo-zig",
        )
        self.assertIn("RISC-V Sail evidence digest mismatches", errors)
        self.assertIn("RISC-V adapter is not release gated", errors)

    def test_tampered_calibration_and_manual_anchor_fail(self) -> None:
        manifest_path = self.root / "autoresearch/MANIFEST.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["harness"]["anchor_prove_ms"]["riscv"]["wide"] = 1.5
        manifest_path.write_text(json.dumps(manifest))
        calibration = self.root / "autoresearch/reference/riscv-calibration.json"
        calibration.write_text(calibration.read_text() + "\n")
        errors = activation_errors(
            self.root,
            board="riscv",
            settings_receipt=self.receipt,
            repository="teddyjfpender/stwo-zig",
        )
        self.assertIn("RISC-V calibration artifact digest mismatches", errors)
        self.assertIn(
            "RISC-V wide anchor differs from calibration evidence", errors,
        )


if __name__ == "__main__":
    unittest.main()
