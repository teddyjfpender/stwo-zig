from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

from scripts.native_cuda_benchmark_lib.activation import (  # noqa: E402
    ActivationError,
    DEFAULT_STATE_PATH,
    REQUIRED_FAMILIES,
    load_state,
    validate_manifest_activation,
    validate_state,
)


class CudaActivationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state_document = json.loads(
            (ROOT / DEFAULT_STATE_PATH).read_bytes()
        )
        self.manifest = json.loads(
            (ROOT / "autoresearch/MANIFEST.json").read_bytes()
        )

    def test_current_state_is_explicitly_blocked_by_semantic_routes(self) -> None:
        state, _ = load_state(ROOT)
        self.assertFalse(state["activation_ready"])
        self.assertEqual(1, state["release_ready_family_count"])
        self.assertEqual(len(REQUIRED_FAMILIES), state["required_family_count"])
        self.assertTrue(
            state["families"]["wide_fibonacci"]["release_ready"]
        )
        self.assertTrue(
            state["families"]["plonk_logup"]["gates"][
                "exact_constraint_semantics"
            ]
        )
        for family in (
            "blake",
            "poseidon",
            "state_machine",
            "xor_lookup",
        ):
            with self.subTest(family=family):
                self.assertFalse(state["families"][family]["release_ready"])
                self.assertFalse(
                    state["families"][family]["gates"][
                        "exact_constraint_semantics"
                    ]
                )

    def test_manifest_pin_binds_exact_activation_state(self) -> None:
        validate_manifest_activation(ROOT, self.manifest)
        contract = self.manifest["workload_registry"]["groups"]["cuda"][
            "activation_contract"
        ]
        self.assertEqual(
            contract["state_sha256"],
            hashlib.sha256(
                (ROOT / DEFAULT_STATE_PATH).read_bytes()
            ).hexdigest(),
        )

    def test_blocked_state_rejects_manifest_activation(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        group = manifest["workload_registry"]["groups"]["cuda"]
        group["enabled"] = True
        group["promotion_eligible"] = True
        with self.assertRaisesRegex(
            ActivationError,
            "cannot be enabled or promotion eligible",
        ):
            validate_manifest_activation(ROOT, manifest)

    def test_family_release_ready_cannot_overstate_its_gates(self) -> None:
        document = copy.deepcopy(self.state_document)
        document["families"]["blake"]["release_ready"] = True
        with self.assertRaisesRegex(
            ActivationError,
            "release_ready contradicts",
        ):
            validate_state(ROOT, document)

    def test_passing_gate_requires_retained_evidence(self) -> None:
        document = copy.deepcopy(self.state_document)
        blake = document["families"]["blake"]
        blake["gates"]["exact_trace_semantics"] = True
        blake["blockers"]["exact_trace_semantics"] = None
        blake["evidence"]["exact_trace_semantics"] = []
        with self.assertRaisesRegex(
            ActivationError,
            "passes without retained evidence",
        ):
            validate_state(ROOT, document)

    def test_parity_gate_rejects_declarative_source_path(self) -> None:
        document = copy.deepcopy(self.state_document)
        wide = document["families"]["wide_fibonacci"]
        wide["evidence"]["exact_cpu_cuda_proof_bytes"] = [
            "src/integrations/native_cuda/wide_fibonacci/program.zig"
        ]
        with self.assertRaisesRegex(
            ActivationError,
            "no valid immutable parity receipt",
        ):
            validate_state(ROOT, document)

    def test_stage_gate_rejects_nontelemetry_json(self) -> None:
        document = copy.deepcopy(self.state_document)
        wide = document["families"]["wide_fibonacci"]
        wide["evidence"]["complete_stage_telemetry"] = [
            "conformance/evidence/cuda/native-bringup-sm89/"
            "product-parity-receipt.json"
        ]
        with self.assertRaisesRegex(
            ActivationError,
            "no complete parsed report",
        ):
            validate_state(ROOT, document)

    def test_candidate_dry_run_requires_parsed_diagnostic_receipt(self) -> None:
        document = copy.deepcopy(self.state_document)
        document["global"]["evidence"]["candidate_dry_run"] = [
            "conformance/cuda-native-activation-state-v1.json"
        ]
        with self.assertRaisesRegex(
            ActivationError,
            "candidate_dry_run has no valid parsed release receipt",
        ):
            validate_state(ROOT, document)

    def test_predecessor_rehearsal_requires_paired_abba_receipt(self) -> None:
        document = copy.deepcopy(self.state_document)
        document["global"]["evidence"]["predecessor_abba_rehearsal"] = [
            "conformance/evidence/cuda/system-architecture-sm89/receipt.json"
        ]
        with self.assertRaisesRegex(
            ActivationError,
            "predecessor_abba_rehearsal has no valid parsed release receipt",
        ):
            validate_state(ROOT, document)

    def test_future_global_gate_rejects_declarative_path(self) -> None:
        document = copy.deepcopy(self.state_document)
        global_entry = document["global"]
        global_entry["gates"]["full_repository_gates"] = True
        global_entry["blockers"]["full_repository_gates"] = None
        global_entry["evidence"]["full_repository_gates"] = [
            "autoresearch/tasks/cuda/06-cuda-autoresearch-activation.md"
        ]
        with self.assertRaisesRegex(
            ActivationError,
            "full_repository_gates has no valid parsed release receipt",
        ):
            validate_state(ROOT, document)

    def test_rust_gate_requires_pinned_commit_authority_receipt(self) -> None:
        document = copy.deepcopy(self.state_document)
        wide = document["families"]["wide_fibonacci"]
        wide["evidence"]["pinned_rust_verification"] = [
            "conformance/evidence/cuda/native-bringup-sm89/"
            "product-parity-receipt.json"
        ]
        with self.assertRaisesRegex(
            ActivationError,
            "no matching pinned-commit authority",
        ):
            validate_state(ROOT, document)

    def test_activation_ready_is_derived_not_asserted(self) -> None:
        document = copy.deepcopy(self.state_document)
        document["activation_ready"] = True
        with self.assertRaisesRegex(
            ActivationError,
            "activation_ready contradicts",
        ):
            validate_state(ROOT, document)


if __name__ == "__main__":
    unittest.main()
