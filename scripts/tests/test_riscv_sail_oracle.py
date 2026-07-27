from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import riscv_equivalence as equivalence
from scripts import riscv_sail_oracle as oracle


def one_retirement_trace(rd_value: int = 1) -> dict:
    """ADDI x1, x0, 1 at the formal corpus entry: the smallest honest trace."""
    entry = equivalence.RVFI_DII_ENTRY
    return {
        "schema": equivalence.TRACE_SCHEMA,
        "profile": equivalence.PROFILE,
        "initial_pc": entry,
        "retirements": [
            {
                "order": 0,
                "pc": entry,
                "instruction": 0x00100093,
                "rd": 1,
                "rd_value": rd_value,
                "next_pc": entry + 4,
                "memory": {
                    "address": 0,
                    "read_mask": 0,
                    "read_value": 0,
                    "write_mask": 0,
                    "write_value": 0,
                },
            }
        ],
        "final_pc": entry + 4,
        "total_steps": 1,
    }


def pinned_workspace_binary() -> Path:
    return oracle.DEFAULT_WORKSPACE / oracle.SAIL_BINARY_IN_WORKSPACE


class VerdictContractTests(unittest.TestCase):
    """The four verdicts and their exit codes, with no Sail required."""

    def test_skip_and_failure_exit_codes_never_collide(self) -> None:
        # A caller skips only on 3; every other non-zero code must fail the
        # caller. If UNAVAILABLE ever shared a code with a failure, a dead
        # oracle would be indistinguishable from a divergence.
        self.assertEqual(0, oracle.EXIT_CODES[oracle.VERDICT_EQUIVALENT])
        self.assertEqual(0, oracle.EXIT_CODES[oracle.VERDICT_AVAILABLE])
        self.assertEqual(1, oracle.EXIT_CODES[oracle.VERDICT_DIVERGENT])
        self.assertEqual(2, oracle.EXIT_CODES[oracle.VERDICT_ERROR])
        self.assertEqual(3, oracle.EXIT_CODES[oracle.VERDICT_UNAVAILABLE])

    def test_missing_binary_is_unavailable_with_build_instructions(self) -> None:
        with self.assertRaises(oracle.SailUnavailable) as caught:
            oracle.resolve_sail(Path("/nonexistent/sail_riscv_sim"), environ={})
        message = str(caught.exception)
        self.assertIn("riscv_formal_tools.py prepare", message)
        self.assertIn("--sail-bin", message)

    def test_configured_but_unpinned_binary_never_falls_through(self) -> None:
        # An executable that exists but is not the pinned oracle must be
        # UNAVAILABLE with the configured source named, even if some other
        # candidate on the host would have verified.
        with tempfile.TemporaryDirectory() as scratch:
            impostor = Path(scratch) / "sail_riscv_sim"
            impostor.write_text("#!/bin/sh\necho not-a-pinned-oracle\n")
            impostor.chmod(impostor.stat().st_mode | stat.S_IXUSR)
            with self.assertRaises(oracle.SailUnavailable) as caught:
                oracle.resolve_sail(None, environ={"STWO_RISCV_SAIL_BIN": str(impostor)})
            self.assertIn("$STWO_RISCV_SAIL_BIN", str(caught.exception))
            self.assertIn("not the pinned Sail oracle", str(caught.exception))

    def test_unavailable_check_reports_verdict_without_consulting(self) -> None:
        report = oracle.check_trace_agreement(
            Path("/nonexistent/guest.elf"),
            Path("/nonexistent/trace.json"),
            sail_bin=Path("/nonexistent/sail_riscv_sim"),
            environ={},
        )
        self.assertEqual(oracle.VERDICT_UNAVAILABLE, report["verdict"])
        self.assertEqual(3, report["exit_code"])
        self.assertEqual({}, report["identity"])

    def test_semantic_disagreement_is_divergent_not_error(self) -> None:
        resolved = oracle.ResolvedSail(Path("/pinned/sail"), {"model_tag": "t"}, "test")
        with tempfile.TemporaryDirectory() as scratch:
            elf = Path(scratch) / "guest.elf"
            elf.write_bytes(b"\x7fELF")
            trace = Path(scratch) / "trace.json"
            trace.write_text(json.dumps(one_retirement_trace()))
            with (
                mock.patch.object(oracle, "resolve_sail", return_value=resolved),
                mock.patch.object(
                    equivalence,
                    "run_sail_rvfi_dii",
                    side_effect=equivalence.SailDisagreement(
                        "Sail trapped at retirement 0 for 0x00100093"
                    ),
                ),
            ):
                report = oracle.check_trace_agreement(elf, trace)
        self.assertEqual(oracle.VERDICT_DIVERGENT, report["verdict"])
        self.assertIn("trapped", report["reason"])

    def test_transport_failure_is_error_not_skip(self) -> None:
        resolved = oracle.ResolvedSail(Path("/pinned/sail"), {"model_tag": "t"}, "test")
        with tempfile.TemporaryDirectory() as scratch:
            elf = Path(scratch) / "guest.elf"
            elf.write_bytes(b"\x7fELF")
            trace = Path(scratch) / "trace.json"
            trace.write_text(json.dumps(one_retirement_trace()))
            with (
                mock.patch.object(oracle, "resolve_sail", return_value=resolved),
                mock.patch.object(
                    equivalence,
                    "run_sail_rvfi_dii",
                    side_effect=equivalence.EquivalenceError(
                        "Sail RVFI-DII closed after 0 of 88 bytes"
                    ),
                ),
            ):
                report = oracle.check_trace_agreement(elf, trace)
        self.assertEqual(oracle.VERDICT_ERROR, report["verdict"])
        self.assertEqual(2, report["exit_code"])

    def test_malformed_trace_is_error(self) -> None:
        resolved = oracle.ResolvedSail(Path("/pinned/sail"), {"model_tag": "t"}, "test")
        with tempfile.TemporaryDirectory() as scratch:
            elf = Path(scratch) / "guest.elf"
            elf.write_bytes(b"\x7fELF")
            trace = Path(scratch) / "trace.json"
            trace.write_text('{"schema": "bogus"}')
            with mock.patch.object(oracle, "resolve_sail", return_value=resolved):
                report = oracle.check_trace_agreement(elf, trace)
        self.assertEqual(oracle.VERDICT_ERROR, report["verdict"])
        self.assertIn("input artefact rejected", report["reason"])


@unittest.skipUnless(
    pinned_workspace_binary().is_file(),
    f"pinned Sail binary absent at {pinned_workspace_binary()}; "
    "Sail agreement was NOT checked live "
    "(python3 scripts/riscv_formal_tools.py prepare "
    f"--workspace {oracle.DEFAULT_WORKSPACE})",
)
class LivePinnedSailTests(unittest.TestCase):
    """Round-trips through the real pinned binary; ~0.1 s each."""

    def test_probe_reports_available_with_pinned_identity(self) -> None:
        report = oracle.probe(environ={})
        self.assertEqual(oracle.VERDICT_AVAILABLE, report["verdict"])
        self.assertEqual(
            equivalence.PINNED_SAIL_REVISION,
            report["identity"]["repository_revision"],
        )

    def test_honest_single_retirement_is_equivalent(self) -> None:
        self.assertEqual(
            oracle.VERDICT_EQUIVALENT, self._check(one_retirement_trace())["verdict"]
        )

    def test_forged_integer_write_is_divergent(self) -> None:
        report = self._check(one_retirement_trace(rd_value=2))
        self.assertEqual(oracle.VERDICT_DIVERGENT, report["verdict"])
        self.assertTrue(
            any("rd_value" in item for item in report["differences"]),
            report["differences"],
        )

    def _check(self, trace_value: dict) -> dict:
        with tempfile.TemporaryDirectory() as scratch:
            elf = Path(scratch) / "guest.elf"
            elf.write_bytes(b"\x7fELF")
            trace = Path(scratch) / "trace.json"
            trace.write_text(json.dumps(trace_value))
            return oracle.check_trace_agreement(elf, trace, environ={})


if __name__ == "__main__":
    unittest.main()
