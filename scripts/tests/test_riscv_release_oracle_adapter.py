"""Regression checks for removal of Stark-V from the active release gate."""

from __future__ import annotations

import unittest
from pathlib import Path

from scripts.riscv_release_gate_lib import contract, controller


ROOT = Path(__file__).resolve().parents[2]


class SailReleaseAuthorityTest(unittest.TestCase):
    def test_release_contract_pins_sail_as_semantic_authority(self) -> None:
        self.assertEqual(
            "https://github.com/riscv/sail-riscv",
            contract.ORACLE_REPOSITORY,
        )
        self.assertEqual(
            "8c7f2da58de0ba5e4457e4de07e0046f0439f35f",
            contract.PINNED_ORACLE,
        )

    def test_active_gate_source_has_no_cp11_stark_v_invocation(self) -> None:
        source = (ROOT / "scripts/riscv_release_gate_lib/controller.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("riscv_release_oracle.py", source)
        self.assertNotIn("--stark-v-source", source)

    def test_complete_admission_policy_has_no_known_limitation_state(self) -> None:
        admission = (
            ROOT / "scripts/riscv_trace_vectors_lib/admission.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("FAIL_CLOSED", admission)
        self.assertNotIn("SIGNED_MULH_LIMITATION", admission)


if __name__ == "__main__":
    unittest.main()
