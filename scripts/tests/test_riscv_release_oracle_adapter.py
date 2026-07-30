"""Regression checks for removal of Stark-V from the active release gate."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

from scripts.riscv_release_gate_lib import contract, controller
from scripts.riscv_release_oracle_lib import public_values


ROOT = Path(__file__).resolve().parents[2]


class SailReleaseAuthorityTest(unittest.TestCase):
    def test_release_contract_pins_sail_as_semantic_authority(self) -> None:
        self.assertEqual(
            "https://github.com/riscv/sail-riscv",
            contract.SAIL_REPOSITORY,
        )
        self.assertEqual(
            "8c7f2da58de0ba5e4457e4de07e0046f0439f35f",
            contract.PINNED_SAIL,
        )
        self.assertEqual(contract.PINNED_SAIL, public_values.PINNED_SAIL)

    def test_archived_stark_v_identity_is_distinct_from_sail_authority(self) -> None:
        self.assertEqual(
            "d478f783055aa0d73a93768a433a3c6c31c91d1c",
            contract.ARCHIVED_STARK_V_COMMIT,
        )
        self.assertEqual(
            contract.ARCHIVED_STARK_V_COMMIT,
            public_values.PINNED_STARK_V,
        )
        self.assertNotEqual(contract.PINNED_SAIL, contract.ARCHIVED_STARK_V_COMMIT)

    def test_active_gate_source_has_no_cp11_stark_v_invocation(self) -> None:
        source = (ROOT / "scripts/riscv_release_gate_lib/controller.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("riscv_release_oracle.py", source)
        self.assertNotIn("--stark-v-source", source)

    def test_build_and_architecture_gates_have_no_cp11_admission_input(self) -> None:
        build_gate = (ROOT / "build_support/gates/riscv.zig").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/riscv_sail_gate.py", build_gate)
        self.assertNotIn("riscv_release_evidence.py", build_gate)
        self.assertNotIn("oracle-receipt.json", build_gate)

        architecture_plan = (
            ROOT / "conformance/build-architecture-ci-plan-v1.json"
        ).read_text(encoding="utf-8")
        architecture_workflow = (
            ROOT / ".github/workflows/architecture-authority.yml"
        ).read_text(encoding="utf-8")
        for source in (architecture_plan, architecture_workflow):
            self.assertNotIn("riscv_release_bundle.py", source)
            self.assertNotIn("riscv_release_challenge.py", source)
            self.assertNotIn("riscv_producer_run_id", source)

    def test_legacy_hosted_jobs_are_unselectable_and_disabled(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        dispatch = workflow.split("permissions:", 1)[0]
        self.assertNotIn("riscv-produce-", dispatch)
        self.assertNotIn("riscv-candidate", dispatch)
        self.assertNotIn("producer_run_id:", dispatch)
        bodies = (
            workflow.split("  riscv-release-evidence:", 1)[1].split(
                "  riscv-fast-release-gate:", 1
            )[0],
            workflow.split("  riscv-fast-release-gate:", 1)[1].split(
                "  architecture-diagnostic:", 1
            )[0],
        )
        for body in bodies:
            self.assertIn("if: ${{ false }}", body)
            self.assertIn("Archived RISC-V Stark-V", body)

    def test_retired_top_level_clis_fail_closed_in_source(self) -> None:
        for relative in (
            "scripts/riscv_release_oracle.py",
            "scripts/riscv_release_bundle.py",
            "scripts/riscv_release_challenge.py",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("retired pre-Sail", source)

    def test_retired_top_level_clis_reject_execution(self) -> None:
        commands = (
            (
                "scripts/riscv_release_oracle.py",
                "cache-key",
                "--stark-v-source",
                "/nonexistent",
            ),
            ("scripts/riscv_release_bundle.py", "verify"),
            ("scripts/riscv_release_challenge.py", "issue"),
        )
        for command in commands:
            with self.subTest(command=command[0]):
                completed = subprocess.run(
                    [sys.executable, *command],
                    cwd=ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(0, completed.returncode)
                self.assertIn(
                    "retired pre-Sail",
                    f"{completed.stdout}\n{completed.stderr}",
                )

    def test_autoresearch_uses_sail_for_correctness_and_stark_v_only_as_benchmark(self) -> None:
        manifest = (ROOT / "autoresearch/MANIFEST.json").read_text(encoding="utf-8")
        self.assertIn('"authority": "sail-riscv"', manifest)
        self.assertIn('"benchmark_reference"', manifest)
        runner = (
            ROOT / "autoresearch/cli/stwo_perf/runner.py"
        ).read_text(encoding="utf-8")
        self.assertIn("_riscv_sail_oracle_check", runner)
        self.assertNotIn("_riscv_stark_v_oracle_check", runner)

    def test_complete_admission_policy_has_no_known_limitation_state(self) -> None:
        admission = (
            ROOT / "scripts/riscv_trace_vectors_lib/admission.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("FAIL_CLOSED", admission)
        self.assertNotIn("SIGNED_MULH_LIMITATION", admission)


if __name__ == "__main__":
    unittest.main()
