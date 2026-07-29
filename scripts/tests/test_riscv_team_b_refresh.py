"""Contracts for the one-command Team B repin-and-regenerate cycle.

The subprocess boundary (``riscv_team_b_refresh._execute``) is mocked
throughout: these tests never shell out to lake, zig, git, or the gates
themselves. They pin the properties the tool exists for -- the steps run in
the one correct order, a failing step aborts everything after it, a dry run
never invokes a writing command, and staged Git changes refuse the run.
"""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import riscv_refinement
from scripts import riscv_team_b_refresh as refresh

WRITE_ORDER = (
    "staged-probe",
    "lake-build",
    "repin",
    "generate",
    "check-generated",
    "team-b-check",
    "team-b-witnesses",
)
DRY_RUN_ORDER = (
    "staged-probe",
    "lake-build",
    "audit-check",
    "check-generated",
)


def _step_marker(command: tuple[str, ...]) -> str:
    if command[0] == "git":
        return "staged-probe"
    if command[0] == "lake":
        return "lake-build"
    script = Path(command[1]).name
    if script == "riscv_team_b.py":
        return "team-b-check"
    if script == "riscv_team_b_witnesses.py":
        return "team-b-witnesses"
    if script != "riscv_refinement.py":
        raise AssertionError(f"unexpected command: {command}")
    if command[2] == "audited-theorems":
        return "repin" if "--write" in command else "audit-check"
    return command[2]


class RiscvTeamBRefreshTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.air_ir_dir = Path(directory.name) / "team-b-ir"
        self.air_ir_dir.mkdir()
        (self.air_ir_dir / "shifts_reg.json").write_text(
            "{}", encoding="utf-8"
        )

    def _recording_executor(
        self,
        *,
        staged: str = "",
        fail: frozenset[str] | set[str] = frozenset(),
    ) -> tuple[list[tuple[tuple[str, ...], Path]], object]:
        """A fake subprocess layer failing any command carrying a token
        in ``fail`` as an exact argument."""
        calls: list[tuple[tuple[str, ...], Path]] = []

        def execute(command: tuple[str, ...], cwd: Path) -> tuple[int, str]:
            calls.append((tuple(command), cwd))
            if command[0] == "git":
                return 0, staged
            if any(argument in fail for argument in command):
                return 1, f"{_step_marker(tuple(command))} exploded"
            return 0, ""

        return calls, execute

    # -- ordering -----------------------------------------------------------

    def test_write_runs_the_full_sequence_in_the_only_correct_order(
        self,
    ) -> None:
        calls, execute = self._recording_executor()
        with mock.patch.object(refresh, "_execute", execute):
            lines = refresh.refresh(self.air_ir_dir, write=True)
        self.assertEqual(
            WRITE_ORDER,
            tuple(_step_marker(command) for command, _ in calls),
        )
        # lake build runs in the Lean package; every gate runs at the root.
        by_marker = {
            _step_marker(command): cwd for command, cwd in calls
        }
        self.assertEqual(refresh.FORMAL_DIR, by_marker["lake-build"])
        for marker in WRITE_ORDER[2:]:
            self.assertEqual(refresh.ROOT, by_marker[marker])
        self.assertIn("refresh complete", lines[-1])

    def test_generation_steps_consume_the_committed_sail_evidence(
        self,
    ) -> None:
        calls, execute = self._recording_executor()
        with mock.patch.object(refresh, "_execute", execute):
            refresh.refresh(self.air_ir_dir, write=True)
        expected_tail = (
            "--reuse-committed-sail-evidence",
            "--no-export-air",
            "--air-ir-dir",
            str(self.air_ir_dir),
        )
        for marker in ("generate", "check-generated"):
            (command,) = [
                command
                for command, _ in calls
                if _step_marker(command) == marker
            ]
            self.assertEqual(expected_tail, command[-4:], marker)

    # -- abort-on-failure ---------------------------------------------------

    def test_a_failing_lake_build_aborts_every_gate(self) -> None:
        calls, execute = self._recording_executor(fail={"lake"})
        with mock.patch.object(refresh, "_execute", execute):
            with self.assertRaisesRegex(
                refresh.RefreshError, "remaining steps were not run"
            ):
                refresh.refresh(self.air_ir_dir, write=True)
        self.assertEqual(
            ("staged-probe", "lake-build"),
            tuple(_step_marker(command) for command, _ in calls),
        )

    def test_a_failing_repin_aborts_regeneration(self) -> None:
        calls, execute = self._recording_executor(fail={"audited-theorems"})
        with mock.patch.object(refresh, "_execute", execute):
            with self.assertRaises(refresh.RefreshError):
                refresh.refresh(self.air_ir_dir, write=True)
        self.assertEqual(
            ("staged-probe", "lake-build", "repin"),
            tuple(_step_marker(command) for command, _ in calls),
        )

    def test_a_failing_byte_identity_check_aborts_the_gates(self) -> None:
        calls, execute = self._recording_executor(fail={"check-generated"})
        with mock.patch.object(refresh, "_execute", execute):
            with self.assertRaises(refresh.RefreshError):
                refresh.refresh(self.air_ir_dir, write=True)
        markers = tuple(_step_marker(command) for command, _ in calls)
        self.assertEqual(WRITE_ORDER[:5], markers)
        self.assertNotIn("team-b-check", markers)
        self.assertNotIn("team-b-witnesses", markers)

    # -- dry run ------------------------------------------------------------

    def test_dry_run_never_invokes_a_writing_command(self) -> None:
        calls, execute = self._recording_executor()
        with mock.patch.object(refresh, "_execute", execute):
            lines = refresh.refresh(self.air_ir_dir, write=False)
        self.assertEqual(
            DRY_RUN_ORDER,
            tuple(_step_marker(command) for command, _ in calls),
        )
        for command, _ in calls:
            self.assertNotIn("--write", command)
            self.assertNotIn("generate", command)
        self.assertIn("dry run: nothing was written", lines[0])

    def test_dry_run_reports_drift_without_aborting_or_writing(self) -> None:
        calls, execute = self._recording_executor(
            fail={"audited-theorems", "check-generated"}
        )
        with mock.patch.object(refresh, "_execute", execute):
            lines = refresh.refresh(self.air_ir_dir, write=False)
        for command, _ in calls:
            self.assertNotIn("--write", command)
            self.assertNotIn("generate", command)
        report = "\n".join(lines)
        self.assertIn("--write would repin", report)
        self.assertIn("--write would regenerate", report)

    # -- refusals -----------------------------------------------------------

    def test_staged_changes_refuse_the_run_in_both_modes(self) -> None:
        for write in (False, True):
            calls, execute = self._recording_executor(
                staged="formal/riscv-refinement/generated-manifest.json"
            )
            with mock.patch.object(refresh, "_execute", execute):
                with self.assertRaisesRegex(
                    refresh.RefreshError, "staged changes"
                ):
                    refresh.refresh(self.air_ir_dir, write=write)
            self.assertEqual(
                ("staged-probe",),
                tuple(_step_marker(command) for command, _ in calls),
                f"write={write}",
            )

    def test_missing_air_export_is_an_actionable_refusal(self) -> None:
        calls, execute = self._recording_executor()
        with mock.patch.object(refresh, "_execute", execute):
            with self.assertRaisesRegex(
                refresh.RefreshError, "riscv-refinement-ir"
            ):
                refresh.refresh(self.air_ir_dir / "absent", write=True)
        self.assertEqual(
            ("staged-probe",),
            tuple(_step_marker(command) for command, _ in calls),
        )

    # -- summary ------------------------------------------------------------

    def test_write_summary_reports_counts_artifacts_and_coverage(
        self,
    ) -> None:
        _, execute = self._recording_executor()
        before = {"formal/riscv-refinement/generated-manifest.json": "aa"}
        after = {"formal/riscv-refinement/generated-manifest.json": "bb"}
        with (
            mock.patch.object(refresh, "_execute", execute),
            mock.patch.object(
                refresh, "pinned_theorem_count", side_effect=[2158, 2201]
            ),
            mock.patch.object(
                refresh, "_artifact_digests", side_effect=[before, after]
            ),
        ):
            lines = refresh.refresh(self.air_ir_dir, write=True)
        self.assertEqual("audited theorems: 2158 -> 2201", lines[0])
        self.assertEqual(
            "changed artifacts: "
            "formal/riscv-refinement/generated-manifest.json",
            lines[1],
        )
        self.assertRegex(lines[2], r"^coverage: \d+/\d+ proved")

    def test_pinned_theorem_count_matches_the_live_pin(self) -> None:
        self.assertEqual(
            len(riscv_refinement.AUDITED_THEOREMS),
            refresh.pinned_theorem_count(),
        )

    def test_pinned_theorem_count_refuses_a_malformed_pin(self) -> None:
        broken = self.air_ir_dir / "broken_pin.py"
        broken.write_text("AUDITED_THEOREMS = ()\n", encoding="utf-8")
        with self.assertRaisesRegex(refresh.RefreshError, "expected shape"):
            refresh.pinned_theorem_count(broken)

    # -- CLI ----------------------------------------------------------------

    def test_parser_defaults_to_dry_run(self) -> None:
        args = refresh._parser().parse_args([])
        self.assertFalse(args.write)
        self.assertEqual(refresh.DEFAULT_AIR_IR_DIR, args.air_ir_dir)

    def test_parser_refuses_write_combined_with_dry_run(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                refresh._parser().parse_args(["--write", "--dry-run"])

    def test_main_reports_a_refusal_on_stderr_and_fails(self) -> None:
        calls, execute = self._recording_executor(staged="scripts/x.py")
        stderr = io.StringIO()
        with (
            mock.patch.object(refresh, "_execute", execute),
            contextlib.redirect_stderr(stderr),
        ):
            status = refresh.main(["--write"])
        self.assertEqual(1, status)
        self.assertIn("staged changes", stderr.getvalue())
        self.assertEqual(
            ("staged-probe",),
            tuple(_step_marker(command) for command, _ in calls),
        )


if __name__ == "__main__":
    unittest.main()
