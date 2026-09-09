from __future__ import annotations

import copy
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

import ethereum_block_allocator_execution_evidence as subject  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import riscv_segmented_execution as segmented  # noqa: E402


def digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("ascii")
    return hashlib.sha256(value).hexdigest()


def envelope(payload: dict) -> bytes:
    raw = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    record = {"payload": payload, "content_sha256": digest(raw)}
    return json.dumps(record, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"


def boundary(label: str, *, entry: bool) -> dict:
    return {
        "pc": 0x1000,
        "cpu_sha256": digest(f"cpu-{label}"),
        "rw_memory_sha256": digest(f"memory-{label}"),
        "rw_memory_retained_words": 0,
        "rw_memory_nonzero_words": 0,
        "access_clocks_sha256": (
            segmented._empty_access_clocks_sha256() if entry else digest(f"clock-{label}")
        ),
        "memory_access_clock_entries": 0 if entry else 1,
    }


def family_rows(rows: int) -> list[dict]:
    return [{"family": family, "rows": rows if family == "base_alu_imm" else 0}
            for family in segmented.FAMILIES]


def external_rows(calls: int) -> list[dict]:
    return [{
        "family": family,
        "calls": calls if index == 0 else 0,
        "execution_rows": calls if index == 0 else 0,
    } for index, family in enumerate(
        segmented.EXTERNAL_FAMILIES[segmented.PROFILE_ETHEREUM]
    )]


def write_journal(
    path: Path, elf: bytes, input_bytes: bytes, cycles: tuple[int, ...], *,
    legacy_v2: bool,
) -> None:
    typed = not legacy_v2
    header = {
        "schema": segmented.HEADER_SCHEMA if typed else segmented.HEADER_SCHEMA_V2,
        "profile": segmented.PROFILE_ETHEREUM,
        "clock_frame": segmented.CLOCK_FRAME_LEAF_LOCAL,
        "claim_boundary": segmented.CLAIM_BOUNDARY,
        "elf_bytes": len(elf),
        "elf_sha256": digest(elf),
        "input_bytes": len(input_bytes),
        "input_sha256": digest(input_bytes),
        "segment_step_budget": segmented.MIN_SEGMENT_STEPS,
        "strict_completion": True,
        "trace_retention": "segment-owned",
    }
    lines = [envelope(header)]
    previous = json.loads(lines[-1])["content_sha256"]
    first_cycle = 1
    core_total = external_total = 0
    last_exit = None
    for index, cycle_count in enumerate(cycles):
        external = 1 if index == 0 else 0
        core = cycle_count - external
        last = index == len(cycles) - 1
        exit_state = boundary(f"{len(cycles)}-{index + 1}", entry=False)
        payload = {
            "schema": segmented.SEGMENT_SCHEMA if typed else segmented.SEGMENT_SCHEMA_V2,
            "clock_frame": segmented.CLOCK_FRAME_LEAF_LOCAL,
            "previous_record_sha256": previous,
            "segment_index": index,
            "global_first_cycle": first_cycle,
            "cycle_count": cycle_count,
            "is_first": index == 0,
            "is_last": last,
            "entry": (
                boundary(f"{len(cycles)}-entry", entry=True)
                if index == 0 else boundary(f"{len(cycles)}-{index}", entry=True)
            ),
            "exit": exit_state,
            "core_trace_rows": core,
            "external_trace_rows": external,
        }
        if typed:
            payload["external_family_rows"] = external_rows(external)
        payload.update({
            "unclassified_core_rows": 0,
            "opcode_family_rows": family_rows(core),
            "completion_reason": "halt_flag" if last else None,
            "completion_address": 0,
            "completion_value": 0,
            "completion_clock": 0,
            "exit_code": None,
            "output_bytes": 3 if last else None,
            "output_sha256": digest("same-output") if last else None,
            "continuation_sha256": None if last else digest(f"continuation-{index}"),
        })
        line = envelope(payload)
        lines.append(line)
        previous = json.loads(line)["content_sha256"]
        first_cycle += cycle_count
        core_total += core
        external_total += external
        last_exit = exit_state
    summary = {
        "schema": segmented.SUMMARY_SCHEMA if typed else segmented.SUMMARY_SCHEMA_V2,
        "clock_frame": segmented.CLOCK_FRAME_LEAF_LOCAL,
        "previous_record_sha256": previous,
        "claim_boundary": segmented.CLAIM_BOUNDARY,
        "completed": True,
        "segment_count": len(cycles),
        "total_cycles": sum(cycles),
        "total_core_trace_rows": core_total,
        "total_external_trace_rows": external_total,
    }
    if typed:
        summary["external_family_rows"] = external_rows(external_total)
    summary.update({
        "total_unclassified_core_rows": 0,
        "opcode_family_rows": family_rows(core_total),
        "completion_reason": "halt_flag",
        "exit_code": None,
        "output_bytes": 3,
        "output_sha256": digest("same-output"),
        "final_cpu_sha256": last_exit["cpu_sha256"],
        "final_rw_memory_sha256": last_exit["rw_memory_sha256"],
        "final_access_clocks_sha256": last_exit["access_clocks_sha256"],
        "max_segment_cycle_count": max(cycles),
        "leaf_local_clock_ranges_within_v3_limit": True,
        "segment_statement_v2_global_cycle_limit": segmented.MAX_SEGMENT_STEPS,
        "segment_statement_v2_admissible": True,
    })
    lines.append(envelope(summary))
    path.write_bytes(b"".join(lines))


class AllocatorExecutionEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.baseline_elf = self.root / "baseline.elf"
        self.candidate_elf = self.root / "candidate.elf"
        self.input = self.root / "input.bin"
        self.baseline_elf.write_bytes(b"baseline program")
        self.candidate_elf.write_bytes(b"candidate program")
        self.input.write_bytes(b"ethereum input")
        self.baseline_journal = self.root / "baseline.ndjson"
        self.candidate_journal = self.root / "candidate.ndjson"
        write_journal(
            self.baseline_journal, self.baseline_elf.read_bytes(),
            self.input.read_bytes(), (5, 4), legacy_v2=False,
        )
        write_journal(
            self.candidate_journal, self.candidate_elf.read_bytes(),
            self.input.read_bytes(), (5,), legacy_v2=True,
        )
        self.source_request = self.root / "source-v2.json"
        self.source_request.write_bytes(protocol.canonical_bytes({
            "schema": "stwo.ethereum.block-proof-leaf-stream-source.v2",
            "input": subject._identity(self.input, "fixture input"),
            "elf": subject._identity(self.baseline_elf, "fixture ELF"),
            "execution_journal": subject._identity(
                self.baseline_journal, "fixture journal",
            ),
        }))
        self.timing = self.root / "candidate.time"
        self.timing.write_text(
            "real 1.25\nuser 1.00\nsys 0.25\n"
            " 100 maximum resident set size\n 0 swaps\n 120 peak memory footprint\n",
            encoding="ascii",
        )
        self.sources = []
        for name, raw in (
            ("workspace.rs", b"workspace allocator"),
            ("allocator.rs", b"retained allocator"),
            ("main.rs", b"guest main"),
            ("Cargo.toml", b"cargo manifest"),
        ):
            path = self.root / name
            path.write_bytes(raw)
            self.sources.append(path)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self) -> dict:
        return subject.build(
            baseline_journal=self.baseline_journal,
            candidate_journal=self.candidate_journal,
            baseline_elf=self.baseline_elf,
            candidate_elf=self.candidate_elf,
            source_request=self.source_request,
            candidate_timing_log=self.timing,
            workspace_allocator_source=self.sources[0],
            allocator_snapshot=self.sources[1],
            main_snapshot=self.sources[2],
            cargo_snapshot=self.sources[3],
            baseline_wall_ns=subject.EXPECTED_BASELINE_WALL_NS,
            baseline_wall_authority=subject.BASELINE_WALL_AUTHORITY,
        )

    def test_seals_replays_and_keeps_wall_and_proof_nonpromotable(self) -> None:
        value = self.build()
        output = self.root / "evidence.json"
        output.write_bytes(protocol.canonical_bytes(value))
        self.assertEqual(value, subject.load(output))
        self.assertEqual(value["reductions"]["cycles"]["saved"], 4)
        self.assertFalse(value["measurements"]["wall_comparison_fully_file_backed"])
        self.assertIsNone(value["promotion"]["proof_completion"])
        self.assertFalse(value["equivalence"]["program_and_elf_equal"])

    def test_bool_as_int_and_mutated_journal_reject(self) -> None:
        value = self.build()
        value["claim_boundary"]["production_active"] = 0
        value["content_sha256"] = protocol.content_sha256(value)
        with self.assertRaises(subject.AllocatorExecutionEvidenceError):
            subject.validate(value)

        value = self.build()
        output = self.root / "evidence.json"
        output.write_bytes(protocol.canonical_bytes(value))
        self.candidate_journal.write_bytes(
            self.candidate_journal.read_bytes() + b"mutation",
        )
        with self.assertRaises((subject.AllocatorExecutionEvidenceError,
                                protocol.ProofProtocolError)):
            subject.load(output)


if __name__ == "__main__":
    unittest.main()
