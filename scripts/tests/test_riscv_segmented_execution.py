from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts import riscv_segmented_execution as subject


def sha(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def envelope(payload: dict) -> bytes:
    digest = sha(subject._canonical(payload))
    return subject._canonical({"payload": payload, "content_sha256": digest}) + b"\n"


def boundary(label: str, pc: int, *, reset_clocks: bool = False) -> dict:
    return {
        "pc": pc,
        "cpu_sha256": sha(f"cpu-{label}"),
        "rw_memory_sha256": sha(f"memory-{label}"),
        "rw_memory_retained_words": 2,
        "rw_memory_nonzero_words": 1,
        "access_clocks_sha256": (
            subject._empty_access_clocks_sha256() if reset_clocks else sha(f"clocks-{label}")
        ),
        "memory_access_clock_entries": 0 if reset_clocks else 1,
    }


def families(base_alu_imm: int) -> list[dict]:
    return [
        {"family": family, "rows": base_alu_imm if family == "base_alu_imm" else 0}
        for family in subject.FAMILIES
    ]


def fixture_stream(
    elf: bytes,
    budget: int = 65536,
    clock_frame: str = subject.CLOCK_FRAME_LEAF_LOCAL,
    execution_profile: str = subject.PROFILE_BASE,
) -> list[bytes]:
    header = {
        "schema": subject.HEADER_SCHEMA,
        "profile": execution_profile,
        "clock_frame": clock_frame,
        "claim_boundary": subject.CLAIM_BOUNDARY,
        "elf_bytes": len(elf),
        "elf_sha256": sha(elf),
        "input_bytes": 0,
        "input_sha256": sha(b""),
        "segment_step_budget": budget,
        "strict_completion": True,
        "trace_retention": "segment-owned",
    }
    lines = [envelope(header)]
    previous = json.loads(lines[-1])["content_sha256"]
    cycles = (3, 3, 2)
    first_cycle = 1
    for index, count in enumerate(cycles):
        last = index == len(cycles) - 1
        payload = {
            "schema": subject.SEGMENT_SCHEMA,
            "clock_frame": clock_frame,
            "previous_record_sha256": previous,
            "segment_index": index,
            "global_first_cycle": first_cycle,
            "cycle_count": count,
            "is_first": index == 0,
            "is_last": last,
            "entry": boundary(
                str(index),
                0x10000 + index * 4,
                reset_clocks=clock_frame == subject.CLOCK_FRAME_LEAF_LOCAL,
            ),
            "exit": boundary(str(index + 1), 0x10004 + index * 4),
            "core_trace_rows": count,
            "external_trace_rows": 0,
            "unclassified_core_rows": 0,
            "opcode_family_rows": families(count),
            "completion_reason": "halt_flag" if last else None,
            "completion_address": 0x100000 if last else 0,
            "completion_value": 1 if last else 0,
            "completion_clock": sum(cycles) if last else 0,
            "exit_code": None,
            "output_bytes": None,
            "output_sha256": None,
            "continuation_sha256": None if last else sha(f"continuation-{index}"),
        }
        line = envelope(payload)
        lines.append(line)
        previous = json.loads(line)["content_sha256"]
        first_cycle += count
    final = json.loads(lines[-1])["payload"]
    summary = {
        "schema": subject.SUMMARY_SCHEMA,
        "clock_frame": clock_frame,
        "previous_record_sha256": previous,
        "claim_boundary": subject.CLAIM_BOUNDARY,
        "completed": True,
        "segment_count": 3,
        "total_cycles": 8,
        "total_core_trace_rows": 8,
        "total_external_trace_rows": 0,
        "total_unclassified_core_rows": 0,
        "opcode_family_rows": families(8),
        "completion_reason": "halt_flag",
        "exit_code": None,
        "output_bytes": None,
        "output_sha256": None,
        "final_cpu_sha256": final["exit"]["cpu_sha256"],
        "final_rw_memory_sha256": final["exit"]["rw_memory_sha256"],
        "final_access_clocks_sha256": final["exit"]["access_clocks_sha256"],
        "max_segment_cycle_count": 3,
        "leaf_local_clock_ranges_within_v3_limit": (
            clock_frame == subject.CLOCK_FRAME_LEAF_LOCAL
        ),
        "segment_statement_v2_global_cycle_limit": 1 << 24,
        "segment_statement_v2_admissible": True,
    }
    lines.append(envelope(summary))
    return lines


class SegmentedExecutionTests(unittest.TestCase):
    def test_complete_stream_reduces_exactly(self) -> None:
        lines = fixture_stream(b"elf")
        summary = subject.validate_records(lines, require_complete=True)
        self.assertEqual(summary["segment_count"], 3)
        self.assertEqual(summary["total_cycles"], 8)

    def test_global_clock_mode_retains_access_clock_adjacency(self) -> None:
        lines = fixture_stream(b"elf", clock_frame=subject.CLOCK_FRAME_GLOBAL)
        summary = subject.validate_records(lines, require_complete=True)
        self.assertFalse(summary["leaf_local_clock_ranges_within_v3_limit"])

        record = json.loads(lines[2])
        record["payload"]["entry"]["access_clocks_sha256"] = sha("forged")
        mutated = lines.copy()
        mutated[2] = envelope(record["payload"])
        with self.assertRaisesRegex(subject.ContractError, "global access-clock boundary"):
            subject.validate_records(mutated, require_complete=True)

    def test_boundary_and_content_mutations_fail_closed(self) -> None:
        lines = fixture_stream(b"elf")
        record = json.loads(lines[2])
        record["payload"]["entry"]["cpu_sha256"] = sha("forged")
        mutated = lines.copy()
        mutated[2] = envelope(record["payload"])
        with self.assertRaisesRegex(subject.ContractError, "boundary mismatch"):
            subject.validate_records(mutated, require_complete=True)

        record = json.loads(lines[2])
        record["payload"]["entry"]["access_clocks_sha256"] = sha("not-reset")
        record["payload"]["entry"]["memory_access_clock_entries"] = 1
        mutated = lines.copy()
        mutated[2] = envelope(record["payload"])
        with self.assertRaisesRegex(subject.ContractError, "entry clocks were not reset"):
            subject.validate_records(mutated, require_complete=True)

        record = json.loads(lines[1])
        record["content_sha256"] = sha("forged")
        mutated = lines.copy()
        mutated[1] = subject._canonical(record) + b"\n"
        with self.assertRaisesRegex(subject.ContractError, "content digest mismatch"):
            subject.validate_records(mutated, require_complete=True)

    def test_partial_tail_is_repaired_to_last_committed_line(self) -> None:
        lines = fixture_stream(b"elf")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "execution.ndjson"
            path.write_bytes(lines[0] + lines[1] + b'{"partial"')
            self.assertEqual(subject._read_journal(path), lines[:2])
            self.assertEqual(path.read_bytes(), lines[0] + lines[1])

    def test_capture_resumes_without_reexecuting_durable_records(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        elf = b"deterministic-fixture-elf"
        lines = fixture_stream(elf)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf_path = root / "guest.elf"
            elf_path.write_bytes(elf)
            tool = root / "fake-segment-tool"
            encoded = b"".join(lines).hex()
            tool.write_text(
                "#!/usr/bin/env python3\n"
                "import sys,time\n"
                f"data=bytes.fromhex({encoded!r})\n"
                "for line in data.splitlines(True):\n"
                " sys.stdout.buffer.write(line); sys.stdout.buffer.flush(); time.sleep(0.02)\n"
            )
            tool.chmod(0o700)
            bundle = root / "bundle"
            result = subject.capture_bundle(
                repository=repository,
                bundle=bundle,
                tool=tool,
                elf=elf_path,
                input_path=None,
                segment_steps=65536,
                max_new_segments=1,
            )
            self.assertIsNone(result)
            self.assertEqual((bundle / "execution.ndjson").read_bytes(), b"".join(lines[:2]))

            result = subject.capture_bundle(
                repository=repository,
                bundle=bundle,
                tool=tool,
                elf=elf_path,
                input_path=None,
                segment_steps=65536,
            )
            self.assertEqual(result["status"], "complete")
            self.assertEqual((bundle / "execution.ndjson").read_bytes(), b"".join(lines))
            self.assertEqual(subject.validate_bundle(bundle), result)
            self.assertEqual(len(tuple(bundle.glob("invocation-*.stderr"))), 2)
            plan = json.loads((bundle / "plan.json").read_bytes())
            self.assertEqual(plan["clock_frame"], subject.CLOCK_FRAME_LEAF_LOCAL)
            self.assertEqual(plan["execution_profile"], subject.PROFILE_BASE)
            self.assertIn("leaf-local", plan["command"])

    def test_execution_profile_is_bound_by_the_capture_plan(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool = root / "tool"
            elf_path = root / "guest.elf"
            tool.write_bytes(b"tool")
            elf_path.write_bytes(b"elf")
            plan = subject.make_plan(
                repository,
                tool,
                elf_path,
                None,
                65536,
                execution_profile=subject.PROFILE_KECCAKF,
            )
            lines = fixture_stream(b"elf", execution_profile=subject.PROFILE_KECCAKF)
            self.assertEqual(
                subject.validate_records(lines, plan, require_complete=True)["total_cycles"],
                8,
            )
            forged = fixture_stream(b"elf", execution_profile=subject.PROFILE_BASE)
            with self.assertRaisesRegex(subject.ContractError, "execution profile"):
                subject.validate_records(forged, plan, require_complete=True)

    def test_pathological_tiny_segments_are_rejected(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool = root / "tool"
            elf = root / "elf"
            tool.write_bytes(b"tool")
            elf.write_bytes(b"elf")
            with self.assertRaisesRegex(subject.ContractError, "pathological journals"):
                subject.make_plan(repository, tool, elf, None, 1)


if __name__ == "__main__":
    unittest.main()
