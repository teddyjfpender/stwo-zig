from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch" / "benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_function_value_contract as contract  # noqa: E402
import ethereum_block_function_value_evidence as evidence  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts.tests.test_ethereum_block_pc_hotspot_evidence import (  # noqa: E402
    write_journal,
)


ENTRY_PC = 0x1000
ENTRY_WORD = 0xFC010113
VALUE_PC = 0x1004
VALUE_WORD = 0x0085A903


def observation(elf: Path, input_path: Path, journal: Path) -> dict:
    return protocol.seal({
        "claim_boundary": contract.CLAIM_BOUNDARY,
        "clock_frame": contract.CLOCK_FRAME,
        "distinct_value_count": 2,
        "elf_sha256": hashlib.sha256(elf.read_bytes()).hexdigest(),
        "entry_count": 4,
        "entry_instruction_word": ENTRY_WORD,
        "entry_pc": ENTRY_PC,
        "execution_profile": contract.PROFILE,
        "first_global_cycle": 1,
        "first_segment_index": 0,
        "histogram": [
            {"count": 2, "value": 7},
            {"count": 1, "value": 11},
        ],
        "input_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
        "maximum_value": 11,
        "minimum_value": 7,
        "pending_entry_count": 1,
        "production": False,
        "retired_instructions": 9,
        "sampled_cycles": 9,
        "schema": contract.OBSERVATION_SCHEMA,
        "segment_count": 2,
        "source_sha256": hashlib.sha256(journal.read_bytes()).hexdigest(),
        "status": contract.OBSERVATION_STATUS,
        "value_count": 3,
        "value_imm": 8,
        "value_instruction_word": VALUE_WORD,
        "value_pc": VALUE_PC,
        "value_rd": 18,
        "value_rs1": 11,
        "value_source": contract.VALUE_SOURCE,
        "value_sum": 25,
    })


class FunctionValueEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.elf = self.root / "guest.elf"
        self.input = self.root / "input.bin"
        self.journal = self.root / "execution-v3.ndjson"
        self.source = self.root / "function-value-observer.zig"
        self.executable = self.root / "function-value-observer"
        self.output = self.root / "function-value-evidence.json"
        self.staging = self.root / "staging"
        self.elf.write_bytes(b"fixture ELF")
        self.input.write_bytes(b"fixture input")
        write_journal(self.journal, self.elf.read_bytes(), self.input.read_bytes())
        self.source.write_text("// fixture function-value observer\n")
        self.observed = observation(self.elf, self.input, self.journal)
        encoded = protocol.canonical_bytes(self.observed)
        self.executable.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            f"sys.stdout.buffer.write({encoded!r})\n"
        )
        self.executable.chmod(self.executable.stat().st_mode | stat.S_IXUSR)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def capture(self) -> dict:
        return evidence.capture(
            executable_path=self.executable,
            observer_source_path=self.source,
            elf_path=self.elf,
            input_path=self.input,
            execution_journal_path=self.journal,
            segment_count=2,
            entry_pc=ENTRY_PC,
            entry_instruction_word=ENTRY_WORD,
            value_pc=VALUE_PC,
            value_instruction_word=VALUE_WORD,
            timeout_seconds=5,
            output_path=self.output,
            staging_directory=self.staging,
        )

    def admit(self, raw: Path, output: Path | None = None) -> dict:
        return evidence.admit(
            executable_path=self.executable,
            observer_source_path=self.source,
            elf_path=self.elf,
            input_path=self.input,
            execution_journal_path=self.journal,
            observation_path=raw,
            output_path=output or self.output,
            staging_directory=self.staging,
        )

    def test_capture_and_replay_are_exact_and_nonpromotable(self) -> None:
        captured = self.capture()
        self.assertEqual(evidence.load(self.output), captured)
        self.assertEqual(captured["mode"], "adapter-process-group-capture")
        self.assertFalse(captured["production"])
        self.assertTrue(captured["no_extrapolation"])
        self.assertEqual(captured["sample"]["segment_count"], 2)
        self.assertEqual(captured["canonical_totals"]["histogram_count_sum"], 3)
        self.assertEqual(captured["canonical_totals"]["histogram_weighted_sum"], 25)
        self.assertIsNone(captured["promotion"]["air_claim"])
        self.assertIsNone(captured["promotion"]["proof_correctness"])
        self.assertIsNone(captured["promotion"]["fresh_verification"])
        self.assertIsNone(captured["promotion"]["end_to_end_wall_ns"])
        self.assertFalse(captured["promotion"]["production_promotion_eligible"])
        self.assertLessEqual(captured["process"]["timeout_seconds"], 60)

    def test_retained_raw_artifact_admits_without_process_claim(self) -> None:
        raw = self.root / "raw-observation.json"
        raw.write_bytes(protocol.canonical_bytes(self.observed))
        admitted = self.admit(raw)
        self.assertEqual(evidence.load(self.output), admitted)
        self.assertEqual(admitted["mode"], "retained-observation-admission")
        self.assertIsNone(admitted["process"])
        self.assertIsNone(admitted["stderr"])
        self.assertFalse(admitted["promotion"]["performance_claim_eligible"])

    def test_histogram_order_count_sum_min_max_and_pending_mutations_reject(self) -> None:
        mutations = (
            lambda value: value["histogram"].reverse(),
            lambda value: value["histogram"][0].__setitem__("count", True),
            lambda value: value.__setitem__("value_sum", 26),
            lambda value: value.__setitem__("minimum_value", 6),
            lambda value: value.__setitem__("maximum_value", 12),
            lambda value: value.__setitem__("pending_entry_count", 0),
            lambda value: value.__setitem__("distinct_value_count", True),
            lambda value: value.__setitem__("entry_pc", VALUE_PC),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                changed = copy.deepcopy(self.observed)
                mutate(changed)
                changed["content_sha256"] = protocol.content_sha256(changed)
                with self.assertRaises(contract.FunctionValueContractError):
                    contract.validate_observation(changed)

        changed = copy.deepcopy(self.observed)
        changed["value_sum"] = 26
        with self.assertRaises(contract.FunctionValueContractError):
            contract.validate_observation(changed)

    def test_raw_framing_identity_and_symlink_mutations_reject(self) -> None:
        raw = self.root / "raw-observation.json"
        raw.write_bytes(protocol.canonical_bytes(self.observed)[:-1])
        with self.assertRaises((contract.FunctionValueContractError,
                                protocol.ProofProtocolError)):
            self.admit(raw)

        raw.write_bytes(protocol.canonical_bytes(self.observed))
        symlink = self.root / "observer-link"
        symlink.symlink_to(self.executable)
        with self.assertRaises(protocol.ProofProtocolError):
            evidence.admit(
                executable_path=symlink,
                observer_source_path=self.source,
                elf_path=self.elf,
                input_path=self.input,
                execution_journal_path=self.journal,
                observation_path=raw,
                output_path=self.output,
                staging_directory=self.staging,
            )

    def test_resealed_wrapper_promotion_timeout_and_type_mutations_reject(self) -> None:
        captured = self.capture()
        mutations = (
            lambda value: value["process"].__setitem__("timeout_seconds", 61),
            lambda value: value.__setitem__("production", 0),
            lambda value: value["promotion"].__setitem__("proof_correctness", False),
            lambda value: value["canonical_totals"].__setitem__(
                "pending_entry_count", True,
            ),
        )
        for mutate in mutations:
            changed = copy.deepcopy(captured)
            mutate(changed)
            changed["content_sha256"] = protocol.content_sha256(changed)
            with self.assertRaises(contract.FunctionValueContractError):
                evidence.validate(changed)

    def test_replay_reopens_every_shared_file(self) -> None:
        self.capture()
        self.elf.write_bytes(self.elf.read_bytes() + b"mutation")
        with self.assertRaises((contract.FunctionValueContractError,
                                protocol.ProofProtocolError)):
            evidence.load(self.output)

    def test_create_only_output_rejects_different_existing_bytes(self) -> None:
        raw = self.root / "raw-observation.json"
        raw.write_bytes(protocol.canonical_bytes(self.observed))
        self.output.write_bytes(b"different existing evidence")
        with self.assertRaises(protocol.ProofProtocolError):
            self.admit(raw)

    def test_process_group_timeout_is_bounded(self) -> None:
        sleeper = self.root / "slow-function-value-observer"
        sleeper.write_text(
            "#!/usr/bin/env python3\n"
            "import time\n"
            "time.sleep(10)\n"
        )
        sleeper.chmod(sleeper.stat().st_mode | stat.S_IXUSR)
        started = time.monotonic()
        with self.assertRaisesRegex(
            contract.FunctionValueContractError,
            "timed out",
        ):
            evidence.capture(
                executable_path=sleeper,
                observer_source_path=self.source,
                elf_path=self.elf,
                input_path=self.input,
                execution_journal_path=self.journal,
                segment_count=2,
                entry_pc=ENTRY_PC,
                entry_instruction_word=ENTRY_WORD,
                value_pc=VALUE_PC,
                value_instruction_word=VALUE_WORD,
                timeout_seconds=1,
                output_path=self.output,
                staging_directory=self.staging,
            )
        self.assertLess(time.monotonic() - started, 5)

        argv = [str(self.executable)] + ["x"] * 16
        with self.assertRaises(contract.FunctionValueContractError):
            evidence._run(argv, self.root, 61)


if __name__ == "__main__":
    unittest.main()
