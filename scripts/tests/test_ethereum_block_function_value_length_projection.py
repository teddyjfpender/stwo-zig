from __future__ import annotations

import copy
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch" / "benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_function_value_contract as value_contract  # noqa: E402
import ethereum_block_function_value_evidence as value_evidence  # noqa: E402
import ethereum_block_function_value_length_projection as projection  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts.tests.test_ethereum_block_function_value_evidence import (  # noqa: E402
    observation,
)
from scripts.tests.test_ethereum_block_pc_hotspot_evidence import (  # noqa: E402
    write_journal,
)


class FunctionValueLengthProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.elf = self.root / "guest.elf"
        self.input = self.root / "input.bin"
        self.journal = self.root / "execution-v3.ndjson"
        self.source = self.root / "function-value-observer.zig"
        self.executable = self.root / "function-value-observer"
        self.raw_observation = self.root / "raw-observation.json"
        self.source_evidence = self.root / "function-value-evidence.json"
        self.output = self.root / "length-projection.json"
        self.staging = self.root / "staging"
        self.elf.write_bytes(b"fixture ELF")
        self.input.write_bytes(b"fixture input")
        write_journal(self.journal, self.elf.read_bytes(), self.input.read_bytes())
        self.source.write_text("// fixture function-value observer\n")
        self.executable.write_text("#!/bin/sh\nexit 0\n")
        self.executable.chmod(self.executable.stat().st_mode | stat.S_IXUSR)
        observed = observation(self.elf, self.input, self.journal)
        observed["entry_count"] = observed["value_count"]
        observed["pending_entry_count"] = 0
        observed["content_sha256"] = protocol.content_sha256(observed)
        self.raw_observation.write_bytes(protocol.canonical_bytes(observed))
        value_evidence.admit(
            executable_path=self.executable,
            observer_source_path=self.source,
            elf_path=self.elf,
            input_path=self.input,
            execution_journal_path=self.journal,
            observation_path=self.raw_observation,
            output_path=self.source_evidence,
            staging_directory=self.staging,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create(self) -> dict:
        return projection.create(
            source_evidence_path=self.source_evidence,
            output_path=self.output,
            staging_directory=self.staging,
        )

    def test_create_and_replay_exact_observed_projection(self) -> None:
        value = self.create()
        self.assertEqual(projection.load(self.output), value)
        observed = value["observed"]
        self.assertEqual(observed["call_count"], 3)
        self.assertEqual(observed["total_input_bytes"], 25)
        self.assertEqual(observed["four_byte_lane_padded_input_word_count"], 7)
        self.assertEqual(observed["jump_bitmap_byte_count"], 4)
        self.assertEqual(observed["jump_bitmap_output_word_count"], 3)
        self.assertEqual(observed["length_histogram"], [
            {"count": 2, "value": 7},
            {"count": 1, "value": 11},
        ])
        self.assertEqual(
            [row["value_bytes"] for row in observed["length_quantiles"]],
            [7, 7, 7, 11, 11, 11, 11, 11],
        )
        self.assertFalse(value["production"])
        self.assertFalse(value["performance_claim_eligible"])
        self.assertTrue(value["no_extrapolation"])
        self.assertTrue(all(
            candidate is None for candidate in value["candidate_boundary"].values()
        ))

    def test_resealed_derived_histogram_quantile_and_type_mutations_reject(self) -> None:
        original = self.create()
        mutations = (
            lambda value: value["observed"].__setitem__("total_input_bytes", 26),
            lambda value: value["observed"]["length_histogram"].reverse(),
            lambda value: value["observed"]["length_quantiles"][1].__setitem__(
                "rank_one_based", 2,
            ),
            lambda value: value["observed"].__setitem__("call_count", True),
            lambda value: value["candidate_boundary"].__setitem__(
                "air_main_columns", 7,
            ),
            lambda value: value.__setitem__("production", 0),
            lambda value: value.__setitem__("performance_claim_eligible", 0),
        )
        for mutate in mutations:
            changed = copy.deepcopy(original)
            mutate(changed)
            changed["content_sha256"] = protocol.content_sha256(changed)
            with self.assertRaises(projection.FunctionValueLengthProjectionError):
                projection.validate(changed)

    def test_source_tool_executable_journal_and_input_custody_are_exact(self) -> None:
        value = self.create()
        source = value_evidence.load(self.source_evidence)
        self.assertEqual(value["source_custody"], {
            "elf": source["elf"],
            "execution_journal": source["execution_journal"],
            "input": source["input"],
            "observer_executable": source["observer_executable"],
            "observer_source": source["observer_source"],
            "raw_observation": source["raw_observation"],
        })
        changed = copy.deepcopy(value)
        changed["source_custody"]["input"]["sha256"] = "0" * 64
        changed["content_sha256"] = protocol.content_sha256(changed)
        with self.assertRaises(projection.FunctionValueLengthProjectionError):
            projection.validate(changed)

    def test_source_evidence_mutation_and_noncanonical_projection_reject(self) -> None:
        self.create()
        self.source_evidence.write_bytes(self.source_evidence.read_bytes() + b"mutation")
        with self.assertRaises((projection.FunctionValueLengthProjectionError,
                                protocol.ProofProtocolError)):
            projection.load(self.output)

        original = self.output.read_bytes()
        self.output.write_bytes(original[:-1])
        with self.assertRaises(projection.FunctionValueLengthProjectionError):
            projection.load(self.output)

    def test_unclosed_source_call_rejects_projection(self) -> None:
        observed = observation(self.elf, self.input, self.journal)
        observed["content_sha256"] = protocol.content_sha256(observed)
        raw = self.root / "pending-observation.json"
        raw.write_bytes(protocol.canonical_bytes(observed))
        pending_source = self.root / "pending-source-evidence.json"
        value_evidence.admit(
            executable_path=self.executable,
            observer_source_path=self.source,
            elf_path=self.elf,
            input_path=self.input,
            execution_journal_path=self.journal,
            observation_path=raw,
            output_path=pending_source,
            staging_directory=self.staging,
        )
        with self.assertRaisesRegex(
            projection.FunctionValueLengthProjectionError,
            "unclosed call",
        ):
            projection.create(
                source_evidence_path=pending_source,
                output_path=self.output,
                staging_directory=self.staging,
            )

    def test_create_only_output_rejects_different_existing_bytes(self) -> None:
        self.output.write_bytes(b"different existing projection")
        with self.assertRaises(protocol.ProofProtocolError):
            self.create()


if __name__ == "__main__":
    unittest.main()
