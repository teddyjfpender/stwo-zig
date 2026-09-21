from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch/benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_pc_hotspot_contract as contract  # noqa: E402
import ethereum_block_pc_hotspot_evidence as evidence  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import riscv_segmented_execution as segmented  # noqa: E402


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def canonical(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def record(payload: dict) -> tuple[bytes, str]:
    seal = hashlib.sha256(canonical(payload)).hexdigest()
    value = {"payload": payload, "content_sha256": seal}
    return canonical(value) + b"\n", seal


def family_rows(counts: dict[str, int]) -> list[dict]:
    return [
        {"family": family, "rows": counts.get(family, 0)}
        for family in segmented.FAMILIES
    ]


def external_rows() -> list[dict]:
    return [
        {"family": family, "calls": 0, "execution_rows": 0}
        for family in segmented.EXTERNAL_FAMILIES[segmented.PROFILE_ETHEREUM]
    ]


def boundary(cpu: str, memory: str) -> dict:
    return {
        "pc": 0x1000,
        "cpu_sha256": cpu,
        "rw_memory_sha256": memory,
        "rw_memory_retained_words": 0,
        "rw_memory_nonzero_words": 0,
        "access_clocks_sha256": segmented._empty_access_clocks_sha256(),
        "memory_access_clock_entries": 0,
    }


def write_journal(path: Path, elf: bytes, input_bytes: bytes) -> None:
    header = {
        "schema": segmented.HEADER_SCHEMA,
        "profile": segmented.PROFILE_ETHEREUM,
        "clock_frame": segmented.CLOCK_FRAME_LEAF_LOCAL,
        "claim_boundary": segmented.CLAIM_BOUNDARY,
        "elf_bytes": len(elf),
        "elf_sha256": hashlib.sha256(elf).hexdigest(),
        "input_bytes": len(input_bytes),
        "input_sha256": hashlib.sha256(input_bytes).hexdigest(),
        "segment_step_budget": segmented.MIN_SEGMENT_STEPS,
        "strict_completion": True,
        "trace_retention": "segment-owned",
    }
    lines = []
    line, previous = record(header)
    lines.append(line)
    cpu0, cpu1, cpu2 = digest("cpu0"), digest("cpu1"), digest("cpu2")
    memory = digest("memory")
    segment0 = {
        "schema": segmented.SEGMENT_SCHEMA,
        "clock_frame": segmented.CLOCK_FRAME_LEAF_LOCAL,
        "previous_record_sha256": previous,
        "segment_index": 0,
        "global_first_cycle": 1,
        "cycle_count": 5,
        "is_first": True,
        "is_last": False,
        "entry": boundary(cpu0, memory),
        "exit": boundary(cpu1, memory),
        "core_trace_rows": 5,
        "external_trace_rows": 0,
        "external_family_rows": external_rows(),
        "unclassified_core_rows": 0,
        "opcode_family_rows": family_rows({
            "base_alu_imm": 2, "branch_eq": 2, "load_store": 1,
        }),
        "completion_reason": None,
        "completion_address": 0,
        "completion_value": 0,
        "completion_clock": 0,
        "exit_code": None,
        "output_bytes": None,
        "output_sha256": None,
        "continuation_sha256": digest("continuation0"),
    }
    line, previous = record(segment0)
    lines.append(line)
    segment1 = {
        "schema": segmented.SEGMENT_SCHEMA,
        "clock_frame": segmented.CLOCK_FRAME_LEAF_LOCAL,
        "previous_record_sha256": previous,
        "segment_index": 1,
        "global_first_cycle": 6,
        "cycle_count": 4,
        "is_first": False,
        "is_last": True,
        "entry": boundary(cpu1, memory),
        "exit": boundary(cpu2, memory),
        "core_trace_rows": 4,
        "external_trace_rows": 0,
        "external_family_rows": external_rows(),
        "unclassified_core_rows": 0,
        "opcode_family_rows": family_rows({
            "base_alu_imm": 1, "branch_eq": 1, "load_store": 2,
        }),
        "completion_reason": "halt_flag",
        "completion_address": 0,
        "completion_value": 0,
        "completion_clock": 0,
        "exit_code": None,
        "output_bytes": 3,
        "output_sha256": digest("output"),
        "continuation_sha256": None,
    }
    line, previous = record(segment1)
    lines.append(line)
    summary = {
        "schema": segmented.SUMMARY_SCHEMA,
        "clock_frame": segmented.CLOCK_FRAME_LEAF_LOCAL,
        "previous_record_sha256": previous,
        "claim_boundary": segmented.CLAIM_BOUNDARY,
        "completed": True,
        "segment_count": 2,
        "total_cycles": 9,
        "total_core_trace_rows": 9,
        "total_external_trace_rows": 0,
        "external_family_rows": external_rows(),
        "total_unclassified_core_rows": 0,
        "opcode_family_rows": family_rows({
            "base_alu_imm": 3, "branch_eq": 3, "load_store": 3,
        }),
        "completion_reason": "halt_flag",
        "exit_code": None,
        "output_bytes": 3,
        "output_sha256": digest("output"),
        "final_cpu_sha256": cpu2,
        "final_rw_memory_sha256": memory,
        "final_access_clocks_sha256": segmented._empty_access_clocks_sha256(),
        "max_segment_cycle_count": 5,
        "leaf_local_clock_ranges_within_v3_limit": True,
        "segment_statement_v2_global_cycle_limit": segmented.MAX_SEGMENT_STEPS,
        "segment_statement_v2_admissible": True,
    }
    lines.append(record(summary)[0])
    path.write_bytes(b"".join(lines))


def observation(elf: Path, input_path: Path, journal: Path) -> dict:
    return protocol.seal({
        "schema": contract.OBSERVATION_SCHEMA,
        "status": contract.OBSERVATION_STATUS,
        "production": False,
        "execution_profile": segmented.PROFILE_ETHEREUM,
        "clock_frame": segmented.CLOCK_FRAME_LEAF_LOCAL,
        "elf_sha256": hashlib.sha256(elf.read_bytes()).hexdigest(),
        "input_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
        "source_sha256": hashlib.sha256(journal.read_bytes()).hexdigest(),
        "first_segment_index": 0,
        "segment_count": 2,
        "first_global_cycle": 1,
        "sampled_cycles": 9,
        "retired_instructions": 9,
        "transition_scope": contract.TRANSITION_SCOPE,
        "transition_count": 7,
        "distinct_pc_count": 3,
        "distinct_basic_edge_count": 4,
        "per_pc": [
            {"pc": 0x1000, "opcode_family": "base_alu_imm", "count": 3},
            {"pc": 0x1004, "opcode_family": "branch_eq", "count": 3},
            {"pc": 0x1008, "opcode_family": "load_store", "count": 3},
        ],
        "opcode_transitions": [
            {"from_family": "base_alu_imm", "to_family": "branch_eq", "count": 3},
            {"from_family": "branch_eq", "to_family": "base_alu_imm", "count": 1},
            {"from_family": "branch_eq", "to_family": "load_store", "count": 2},
            {"from_family": "load_store", "to_family": "load_store", "count": 1},
        ],
        "basic_edges": [
            {"from_pc": 0x1000, "to_pc": 0x1004, "count": 3},
            {"from_pc": 0x1004, "to_pc": 0x1000, "count": 1},
            {"from_pc": 0x1004, "to_pc": 0x1008, "count": 2},
            {"from_pc": 0x1008, "to_pc": 0x1008, "count": 1},
        ],
    })


class PcHotspotEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.elf = self.root / "guest.elf"
        self.input = self.root / "input.bin"
        self.journal = self.root / "execution-v3.ndjson"
        self.observer_source = self.root / "retirement_observer.zig"
        self.executable = self.root / "retirement-observer"
        self.output = self.root / "hotspot-evidence.json"
        self.staging = self.root / "staging"
        self.elf.write_bytes(b"fixture ELF")
        self.input.write_bytes(b"fixture input")
        write_journal(self.journal, self.elf.read_bytes(), self.input.read_bytes())
        self.observer_source.write_text("// fixture retirement observer\n")
        self.observation = observation(self.elf, self.input, self.journal)
        encoded = protocol.canonical_bytes(self.observation)
        self.executable.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            f"sys.stdout.buffer.write({encoded!r})\n"
        )
        self.executable.chmod(
            self.executable.stat().st_mode | stat.S_IXUSR
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def capture(self) -> dict:
        return evidence.capture(
            executable_path=self.executable,
            observer_source_path=self.observer_source,
            elf_path=self.elf,
            input_path=self.input,
            execution_journal_path=self.journal,
            first_segment_index=0,
            segment_count=2,
            top_basic_edge_limit=3,
            timeout_seconds=10,
            output_path=self.output,
            staging_directory=self.staging,
        )

    def observation_context(self) -> dict:
        captured = self.capture()
        return {
            "sample": captured["sample"],
            "elf": captured["elf"],
            "input_identity": captured["input"],
            "source": captured["execution_journal"],
        }

    def test_capture_and_replay_exact_diagnostic(self) -> None:
        captured = self.capture()
        replayed = evidence.load(self.output)
        self.assertEqual(replayed, captured)
        self.assertFalse(captured["production"])
        self.assertTrue(captured["no_extrapolation"])
        self.assertEqual(captured["sample"]["first_segment_index"], 0)
        self.assertEqual(captured["canonical_totals"]["retired_instructions"], 9)
        self.assertEqual(
            [edge["count"] for edge in captured["top_basic_edges"]], [3, 2, 1],
        )
        self.assertIsNone(captured["promotion"]["full_corpus_estimate"])
        self.assertIsNone(captured["promotion"]["proof_correctness"])
        self.assertFalse(captured["promotion"]["production_promotion_eligible"])
        self.assertLessEqual(captured["process"]["timeout_seconds"], 60)

    def test_observation_count_matrix_and_order_mutations_reject(self) -> None:
        context = self.observation_context()
        for mutate in (
            lambda value: value["per_pc"][0].__setitem__("count", 4),
            lambda value: value["opcode_transitions"][0].__setitem__("count", 4),
            lambda value: value["basic_edges"].reverse(),
            lambda value: value.__setitem__("transition_count", 6),
            lambda value: value.__setitem__("first_global_cycle", True),
        ):
            changed = copy.deepcopy(self.observation)
            mutate(changed)
            changed["content_sha256"] = protocol.content_sha256(changed)
            with self.assertRaises(contract.PcHotspotContractError):
                contract.validate_observation(changed, **context)

    def test_resealed_projection_and_authority_mutations_reject(self) -> None:
        captured = self.capture()
        changed = copy.deepcopy(captured)
        changed["top_basic_edges"].reverse()
        changed["content_sha256"] = protocol.content_sha256(changed)
        with self.assertRaises(evidence.PcHotspotEvidenceError):
            evidence.validate(changed)

        changed = copy.deepcopy(captured)
        changed["no_extrapolation"] = False
        changed["content_sha256"] = protocol.content_sha256(changed)
        with self.assertRaises(evidence.PcHotspotEvidenceError):
            evidence.validate(changed)

        changed = copy.deepcopy(captured)
        changed["process"]["timeout_seconds"] = 61
        changed["content_sha256"] = protocol.content_sha256(changed)
        with self.assertRaises(evidence.PcHotspotEvidenceError):
            evidence.validate(changed)

        changed = copy.deepcopy(captured)
        changed["promotion"]["production_promotion_eligible"] = 0
        changed["content_sha256"] = protocol.content_sha256(changed)
        with self.assertRaises(evidence.PcHotspotEvidenceError):
            evidence.validate(changed)

        self.journal.write_bytes(self.journal.read_bytes() + b"mutation")
        with self.assertRaises((evidence.PcHotspotEvidenceError,
                                protocol.ProofProtocolError)):
            evidence.load(self.output)

    def test_prefix_timeout_and_full_proof_commands_reject(self) -> None:
        with self.assertRaises(evidence.PcHotspotEvidenceError):
            evidence._require_safe_argv(["observer", "prove"], 60)
        with self.assertRaises(evidence.PcHotspotEvidenceError):
            evidence._require_safe_argv(["observer"], 61)

        captured = self.capture()
        with self.assertRaises(contract.PcHotspotContractError):
            contract.sample_authority(
                journal_path=self.journal,
                elf=captured["elf"],
                input_identity=captured["input"],
                first_segment_index=1,
                segment_count=1,
            )

        symlink = self.root / "observer-link"
        symlink.symlink_to(self.executable)
        with self.assertRaises(protocol.ProofProtocolError):
            evidence.capture(
                executable_path=symlink,
                observer_source_path=self.observer_source,
                elf_path=self.elf,
                input_path=self.input,
                execution_journal_path=self.journal,
                first_segment_index=0,
                segment_count=1,
                top_basic_edge_limit=3,
                timeout_seconds=10,
                output_path=self.root / "symlink-evidence.json",
                staging_directory=self.staging,
            )


if __name__ == "__main__":
    unittest.main()
