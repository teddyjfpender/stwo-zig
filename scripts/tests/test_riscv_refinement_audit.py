"""Audited-theorem inventory refresh regression tests."""

from __future__ import annotations

from scripts.tests.riscv_refinement_test_support import *


class RefinementAuditPinTest(unittest.TestCase):
    def test_audited_theorem_pin_round_trips_through_its_source_block(
        self,
    ) -> None:
        theorems = (
            "RiscvRefinement.Opcodes.lui_refines",
            "RiscvRefinement.Outcome.retirement?_retired",
        )
        rendered = riscv_refinement._render_audited_theorems(theorems)
        self.assertEqual(theorems, pinned_literal(rendered + "\n"))
        with self.assertRaisesRegex(RefinementError, "no refinement theorems"):
            riscv_refinement._render_audited_theorems(())
        with self.assertRaisesRegex(RefinementError, "source literal"):
            riscv_refinement._render_audited_theorems(('Riscv"Refinement.x',))

    def test_audited_theorem_write_mode_repins_from_the_audit(self) -> None:
        live = (
            *riscv_refinement.AUDITED_THEOREMS,
            "RiscvRefinement.Memory.lh_refines",
        )
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            pin_file = directory / "riscv_refinement.py"
            shutil.copyfile(
                ROOT
                / "scripts"
                / "riscv_refinement_lib"
                / "audited_inventory.py",
                pin_file,
            )
            transcript = directory / "audit.txt"
            transcript.write_text(audit_transcript(live), encoding="utf-8")
            riscv_refinement.audited_theorems(
                Namespace(
                    write=True,
                    audit_output=transcript,
                    pin_file=pin_file,
                ),
                Paths(ROOT),
            )
            self.assertEqual(
                tuple(sorted(live)),
                pinned_literal(pin_file.read_text(encoding="utf-8")),
            )

    def test_audited_theorem_check_mode_diffs_and_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            transcript = Path(raw) / "audit.txt"
            arguments = Namespace(
                write=False,
                audit_output=transcript,
                pin_file=None,
            )
            transcript.write_text(
                audit_transcript(riscv_refinement.AUDITED_THEOREMS),
                encoding="utf-8",
            )
            riscv_refinement.audited_theorems(arguments, Paths(ROOT))

            transcript.write_text(
                audit_transcript(
                    (
                        *riscv_refinement.AUDITED_THEOREMS,
                        "RiscvRefinement.Memory.lh_refines",
                    ),
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                RefinementError,
                "unpinned RiscvRefinement.Memory.lh_refines",
            ):
                riscv_refinement.audited_theorems(arguments, Paths(ROOT))

            transcript.write_text(
                audit_transcript(riscv_refinement.AUDITED_THEOREMS[1:]),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                RefinementError,
                "retired " + re.escape(riscv_refinement.AUDITED_THEOREMS[0]),
            ):
                riscv_refinement.audited_theorems(arguments, Paths(ROOT))

    def test_audited_theorem_equality_gate_is_still_enforced(self) -> None:
        extra = audit_transcript(
            (
                *riscv_refinement.AUDITED_THEOREMS,
                "RiscvRefinement.Memory.lh_refines",
            ),
        )
        with self.assertRaisesRegex(RefinementError, "coverage drifted"):
            riscv_refinement._audit_axioms(extra)


if __name__ == "__main__":
    unittest.main()
