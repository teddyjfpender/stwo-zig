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


REPO_ROOT = Path(__file__).resolve().parents[2]


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


INPUT_WORD_ADDRESS = 0x0018_0000
INPUT_WORD_VALUE = 0x0403_0201


def load_word_trace() -> dict:
    """LUI x4, 0x180 then LW x5, 0(x4): a load of runner-initialized memory.

    The claimed read value exists nowhere in the injected instruction stream,
    so Sail can only agree by reading it out of a seeded memory image — the
    shape of every guest that consumes a public-input word.
    """
    entry = equivalence.RVFI_DII_ENTRY
    def row(order: int, pc: int, instruction: int, rd: int, rd_value: int, **memory):
        return {
            "order": order,
            "pc": pc,
            "instruction": instruction,
            "rd": rd,
            "rd_value": rd_value,
            "next_pc": pc + 4,
            "memory": {
                "address": 0,
                "read_mask": 0,
                "read_value": 0,
                "write_mask": 0,
                "write_value": 0,
                **memory,
            },
        }
    final_regs = [0] * 32
    final_regs[4] = INPUT_WORD_ADDRESS
    final_regs[5] = INPUT_WORD_VALUE
    return {
        "schema": equivalence.TRACE_SCHEMA,
        "profile": equivalence.PROFILE,
        "initial_pc": entry,
        "retirements": [
            row(0, entry, 0x00180237, 4, INPUT_WORD_ADDRESS),
            row(
                1,
                entry + 4,
                0x00022283,
                5,
                INPUT_WORD_VALUE,
                address=INPUT_WORD_ADDRESS,
                read_mask=0xF,
                read_value=INPUT_WORD_VALUE,
            ),
        ],
        "final_pc": entry + 8,
        "final_regs": final_regs,
        "total_steps": 2,
    }


def memory_image(value: int) -> dict:
    return {
        "schema": oracle.INITIAL_MEMORY_SCHEMA,
        "words": [{"address": INPUT_WORD_ADDRESS, "value": value}],
    }


def pinned_workspace_binary() -> Path:
    return oracle.DEFAULT_WORKSPACE / oracle.SAIL_BINARY_IN_WORKSPACE


class EndToEndAttributionCoverageTests(unittest.TestCase):
    """Every direct end-to-end proof module retains one sampled Sail tail."""

    SAMPLES = {
        # Landed reference: the other six modules follow this exact
        # `requireAgreement` verdict boundary and last-obligation convention.
        "src/tests/riscv/mulh_soundness_test.zig": (
            "mulh guest (vectors/riscv_elfs/mul_div.elf)",
            "try riscv_cpu.verifyRiscV(",
            "&.{}",
        ),
        "src/tests/riscv/malicious_witness_test.zig": (
            "malicious-witness matrix public-I/O guest",
            "matrix.bound_pow_classified + matrix.bound_logup_classified > 0",
            "&sail_memory",
        ),
        "src/tests/riscv/metal_backend_test.zig": (
            "Metal backend eight-ADDI runner guest",
            "try std.testing.expect(output.statement.n_components > 0);",
            "&.{}",
        ),
        "src/tests/riscv/proof_admission_test.zig": (
            "proving-substitution four-ADDI runner guest",
            "CountingEngine.prove_calls",
            "&.{}",
        ),
        "src/tests/riscv/prover_test.zig": (
            "CPU prover eight-ADDI runner guest",
            "try verifyRiscV(",
            "&.{}",
        ),
        "src/tests/riscv/public_relation_binding_test.zig": (
            "public-relation binding public-I/O guest",
            "mutated.initial_rw_root = initial_root.root ^ 1;",
            "&sail_memory",
        ),
        "src/tests/riscv/transcript_path_test.zig": (
            "transcript-path four-ADDI runner guest",
            "try expectEqualTrace(verifier_trace, reverted_trace);",
            "&.{}",
        ),
    }

    def test_all_seven_direct_proof_modules_keep_fail_closed_sample(self) -> None:
        self.assertEqual(7, len(self.SAMPLES))
        marker = ".sail_oracle.requireAgreement("
        for relative, (label, preceding_assertion, memory_argument) in self.SAMPLES.items():
            with self.subTest(module=relative):
                source = (REPO_ROOT / relative).read_text()
                call = source.find(marker)
                self.assertNotEqual(-1, call, "missing fail-closed Sail assertion")
                self.assertNotEqual(
                    -1,
                    source.rfind(preceding_assertion, 0, call),
                    "Sail sample moved ahead of its proof/attribution assertions",
                )
                call_end = source.find("\n    );", call)
                self.assertNotEqual(-1, call_end, "cannot delimit Sail assertion")
                call_source = source[call:call_end]
                self.assertIn(f'"{label}"', call_source)
                self.assertIn(memory_argument, call_source)

        for relative in (
            "src/tests/riscv/malicious_witness_test.zig",
            "src/tests/riscv/public_relation_binding_test.zig",
        ):
            self.assertIn(
                "release_elf_fixture.initialMemory(&input)",
                (REPO_ROOT / relative).read_text(),
            )


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

    def test_malformed_initial_memory_is_error_not_a_silent_unseeded_run(self) -> None:
        # A rejected image must never degrade into an unseeded comparison:
        # the caller declared initial memory, so either it is seeded exactly
        # as declared or the whole check fails as ERROR.
        resolved = oracle.ResolvedSail(Path("/pinned/sail"), {"model_tag": "t"}, "test")
        rejected = [
            '{"schema": "bogus"}',
            '{"schema": "%s", "words": [{"address": 2, "value": 1}]}'
            % oracle.INITIAL_MEMORY_SCHEMA,
            '{"schema": "%s", "words": [{"address": 4, "value": 1, "extra": 2}]}'
            % oracle.INITIAL_MEMORY_SCHEMA,
        ]
        for text in rejected:
            with tempfile.TemporaryDirectory() as scratch:
                elf = Path(scratch) / "guest.elf"
                elf.write_bytes(b"\x7fELF")
                trace = Path(scratch) / "trace.json"
                trace.write_text(json.dumps(one_retirement_trace()))
                memory = Path(scratch) / "memory.json"
                memory.write_text(text)
                with mock.patch.object(oracle, "resolve_sail", return_value=resolved):
                    report = oracle.check_trace_agreement(
                        elf, trace, memory_path=memory
                    )
            self.assertEqual(oracle.VERDICT_ERROR, report["verdict"], text)
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

    def test_seeded_load_of_declared_memory_is_equivalent(self) -> None:
        # Unseeded, the same trace is DIVERGENT (Sail's memory is zeroed), so
        # equivalence here is evidence the seeding preamble is load-bearing.
        self.assertEqual(
            oracle.VERDICT_DIVERGENT, self._check(load_word_trace())["verdict"]
        )
        report = self._check(load_word_trace(), memory_image(INPUT_WORD_VALUE))
        self.assertEqual(oracle.VERDICT_EQUIVALENT, report["verdict"], report)
        self.assertEqual(1, report["seeded_words"])

    def test_seed_disagreeing_with_the_trace_is_divergent(self) -> None:
        # Sail reads its *own* seeded memory, never the trace's claims: a
        # wrong image surfaces as Sail reporting the wrong-image value.
        report = self._check(load_word_trace(), memory_image(0x0807_0605))
        self.assertEqual(oracle.VERDICT_DIVERGENT, report["verdict"])
        self.assertTrue(
            any("0x08070605" in item for item in report["differences"]),
            report["differences"],
        )

    def _check(self, trace_value: dict, memory_value: dict | None = None) -> dict:
        with tempfile.TemporaryDirectory() as scratch:
            elf = Path(scratch) / "guest.elf"
            elf.write_bytes(b"\x7fELF")
            trace = Path(scratch) / "trace.json"
            trace.write_text(json.dumps(trace_value))
            memory: Path | None = None
            if memory_value is not None:
                memory = Path(scratch) / "memory.json"
                memory.write_text(json.dumps(memory_value))
            return oracle.check_trace_agreement(
                elf, trace, environ={}, memory_path=memory
            )


if __name__ == "__main__":
    unittest.main()
