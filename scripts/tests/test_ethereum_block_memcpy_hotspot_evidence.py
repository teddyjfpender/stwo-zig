from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch/benchmarks"
import sys
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_allocator_execution_evidence as allocator  # noqa: E402
import ethereum_block_memcpy_hotspot_evidence as subject  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts.tests import test_ethereum_block_allocator_execution_evidence as fixture  # noqa: E402


def identity(path: Path) -> dict:
    return allocator._identity(path, "fixture identity")


def observation_bytes(unsigned: dict) -> bytes:
    raw = (json.dumps(
        unsigned, ensure_ascii=True, allow_nan=False, separators=(",", ":"),
    ) + "\n").encode("ascii")
    seal = hashlib.sha256(raw).hexdigest()
    sealed = {}
    for key in subject.OBSERVATION_KEYS:
        sealed[key] = seal if key == "content_sha256" else unsigned[key]
    return (json.dumps(
        sealed, ensure_ascii=True, allow_nan=False, separators=(",", ":"),
    ) + "\n").encode("ascii")


class MemcpyHotspotEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.baseline_elf = self.root / "baseline.elf"
        self.candidate_elf = self.root / "candidate.elf"
        self.input = self.root / "input.bin"
        self.baseline_elf.write_bytes(b"baseline")
        self.candidate_elf.write_bytes(b"candidate")
        self.input.write_bytes(b"input")
        self.baseline_journal = self.root / "baseline.ndjson"
        self.candidate_journal = self.root / "candidate.ndjson"
        fixture.write_journal(
            self.baseline_journal, self.baseline_elf.read_bytes(),
            self.input.read_bytes(), (5, 4), legacy_v2=False,
        )
        fixture.write_journal(
            self.candidate_journal, self.candidate_elf.read_bytes(),
            self.input.read_bytes(), (5,), legacy_v2=True,
        )
        self.source_request = self.root / "source.json"
        self.source_request.write_bytes(protocol.canonical_bytes({
            "schema": "stwo.ethereum.block-proof-leaf-stream-source.v2",
            "input": identity(self.input),
            "elf": identity(self.baseline_elf),
            "execution_journal": identity(self.baseline_journal),
        }))
        self.candidate_timing = self.root / "candidate.time"
        self.candidate_timing.write_text(
            "real 1.25\nuser 1.00\nsys 0.25\n"
            " 100 maximum resident set size\n 0 swaps\n 120 peak memory footprint\n",
            encoding="ascii",
        )
        sources = []
        for name in ("workspace.rs", "allocator.rs", "main.rs", "Cargo.toml"):
            path = self.root / name
            path.write_text(name, encoding="ascii")
            sources.append(path)
        allocator_value = allocator.build(
            baseline_journal=self.baseline_journal,
            candidate_journal=self.candidate_journal,
            baseline_elf=self.baseline_elf,
            candidate_elf=self.candidate_elf,
            source_request=self.source_request,
            candidate_timing_log=self.candidate_timing,
            workspace_allocator_source=sources[0], allocator_snapshot=sources[1],
            main_snapshot=sources[2], cargo_snapshot=sources[3],
            baseline_wall_ns=allocator.EXPECTED_BASELINE_WALL_NS,
            baseline_wall_authority=allocator.BASELINE_WALL_AUTHORITY,
        )
        self.allocator_evidence = self.root / "allocator-evidence.json"
        self.allocator_evidence.write_bytes(protocol.canonical_bytes(allocator_value))
        self.executable = self.root / "observer"
        self.executable.write_bytes(b"observer executable")
        self.executable.chmod(0o500)
        self.source = self.root / "observer.zig"
        self.source.write_bytes(b"observer source")
        self.timing = self.root / "observer.time"
        self.timing.write_text(
            "real 0.50\nuser 0.40\nsys 0.10\n"
            " 90 maximum resident set size\n 0 swaps\n 88 peak memory footprint\n",
            encoding="ascii",
        )
        self.observation = self.root / "observation.json"
        self.write_observation()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def value(self) -> dict:
        return {
            "alignment_histogram": [{
                "call_count": 3, "destination_mod_16": 0,
                "source_mod_16": 0, "total_bytes": 4,
            }],
            "call_count": 3,
            "clock_frame": "leaf_local",
            "distinct_alignment_count": 1,
            "distinct_length_count": 2,
            "elf_sha256": identity(self.candidate_elf)["sha256"],
            "execution_profile": "rv32im-zkvm-ethereum-v1",
            "first_global_cycle": 1,
            "first_segment_index": 0,
            "input_sha256": identity(self.input)["sha256"],
            "length_histogram": [
                {"call_count": 1, "length": 0, "total_bytes": 0},
                {"call_count": 2, "length": 2, "total_bytes": 4},
            ],
            "maximum_requested_bytes": 2,
            "memcpy_entry_pc": 0x1000,
            "production": False,
            "retired_instructions": 4,
            "sampled_cycles": 5,
            "schema": subject.OBSERVATION_SCHEMA,
            "segment_count": 1,
            "source_sha256": identity(self.candidate_journal)["sha256"],
            "status": "captured-diagnostic-only",
            "total_requested_bytes": 4,
            "validated_register_reads": 7,
            "zero_length_calls": 1,
        }

    def write_observation(self, value: dict | None = None) -> None:
        self.observation.write_bytes(observation_bytes(value or self.value()))

    def capture(self, name: str = "evidence.json") -> tuple[Path, dict]:
        output = self.root / name
        value = subject.capture(
            observation_path=self.observation,
            observer_executable=self.executable,
            observer_source=self.source,
            candidate_elf=self.candidate_elf,
            candidate_journal=self.candidate_journal,
            input_path=self.input,
            timing_log=self.timing,
            allocator_evidence_path=self.allocator_evidence,
            output=output,
            staging=self.root / "staging",
        )
        return output, value

    def test_captures_replays_and_keeps_prefix_nonpromotable(self) -> None:
        output, value = self.capture()
        self.assertEqual(value, subject.load(output))
        self.assertEqual(value["sample"]["call_count"], 3)
        self.assertTrue(value["claim_boundary"]["prefix_only"])
        self.assertIsNone(value["claim_boundary"]["proof_correctness"])
        self.assertIsNone(value["claim_boundary"]["measured_end_to_end_wall_ns"])

    def test_bool_as_int_histogram_and_journal_mutations_reject(self) -> None:
        value = self.value()
        value["production"] = 0
        self.write_observation(value)
        with self.assertRaises(subject.MemcpyHotspotEvidenceError):
            self.capture("bad-bool.json")

        value = self.value()
        value["length_histogram"][1]["total_bytes"] = 5
        self.write_observation(value)
        with self.assertRaises(subject.MemcpyHotspotEvidenceError):
            self.capture("bad-histogram.json")

        self.write_observation()
        output, _ = self.capture()
        self.candidate_journal.write_bytes(
            self.candidate_journal.read_bytes() + b"mutation",
        )
        with self.assertRaises((subject.MemcpyHotspotEvidenceError,
                                protocol.ProofProtocolError)):
            subject.load(output)


if __name__ == "__main__":
    unittest.main()
