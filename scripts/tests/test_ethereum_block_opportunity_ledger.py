from __future__ import annotations

import copy
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
BENCHMARK = ROOT / "autoresearch/benchmarks"
if str(BENCHMARK) not in sys.path:
    sys.path.insert(0, str(BENCHMARK))

import ethereum_block_opportunity_ledger as ledger  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import riscv_segmented_execution as segmented  # noqa: E402


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def identity(path: Path) -> dict:
    raw = path.read_bytes()
    return {
        "path": str(path.absolute()),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def canonical(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def record(payload: dict) -> tuple[bytes, str]:
    seal = hashlib.sha256(canonical(payload)).hexdigest()
    return canonical({"payload": payload, "content_sha256": seal}) + b"\n", seal


CPU_BYTES = struct.pack("<33I", *([0] * 33))
CPU_SHA = hashlib.sha256(ledger.CPU_IDENTITY_DOMAIN + CPU_BYTES).hexdigest()
MEMORY_SHA = digest("memory")
ACCESS_SHA = segmented._empty_access_clocks_sha256()


def write_journal(path: Path) -> list[dict]:
    lines = []
    header_line, previous = record(copy.deepcopy(ledger.EXPECTED_HEADER))
    lines.append(header_line)
    remaining = copy.deepcopy(ledger.EXPECTED_FAMILY_ROWS)
    segments = []
    global_first = 1
    for index in range(210):
        cycles = 4_194_304 if index < 209 else 4_150_693
        keccak = 32_835 if index == 0 else 0
        recovery = 66 if index == 0 else 0
        core = cycles - keccak - recovery
        needed = core
        families = []
        for family in segmented.FAMILIES:
            take = min(remaining[family], needed)
            remaining[family] -= take
            needed -= take
            families.append({"family": family, "rows": take})
        if needed:
            raise AssertionError("synthetic journal family allocation failed")
        is_last = index == 209
        boundary_entry = {
            "pc": 0,
            "cpu_sha256": CPU_SHA,
            "rw_memory_sha256": MEMORY_SHA,
            "rw_memory_retained_words": 448_550_435 if index == 0 else 0,
            "rw_memory_nonzero_words": 448_550_435 if index == 0 else 0,
            "access_clocks_sha256": ACCESS_SHA,
            "memory_access_clock_entries": 0,
        }
        boundary_exit = {
            "pc": 0,
            "cpu_sha256": CPU_SHA,
            "rw_memory_sha256": MEMORY_SHA,
            "rw_memory_retained_words": 450_418_169 if index == 0 else 0,
            "rw_memory_nonzero_words": 450_418_169 if index == 0 else 0,
            "access_clocks_sha256": ACCESS_SHA,
            "memory_access_clock_entries": 6_541_934 if index == 0 else 0,
        }
        payload = {
            "schema": segmented.SEGMENT_SCHEMA,
            "clock_frame": segmented.CLOCK_FRAME_LEAF_LOCAL,
            "previous_record_sha256": previous,
            "segment_index": index,
            "global_first_cycle": global_first,
            "cycle_count": cycles,
            "is_first": index == 0,
            "is_last": is_last,
            "entry": boundary_entry,
            "exit": boundary_exit,
            "core_trace_rows": core,
            "external_trace_rows": keccak + recovery,
            "external_family_rows": [
                {
                    "family": "stwo.keccakf-1600.permute-in-place@1",
                    "calls": keccak,
                    "execution_rows": keccak,
                },
                {
                    "family": "stwo.secp256k1.recover-signer@1",
                    "calls": recovery,
                    "execution_rows": recovery,
                },
            ],
            "unclassified_core_rows": 0,
            "opcode_family_rows": families,
            "completion_reason": "halt_flag" if is_last else None,
            "completion_address": 0,
            "completion_value": 0,
            "completion_clock": 0,
            "exit_code": None,
            "output_bytes": 43 if is_last else None,
            "output_sha256": ledger.EXPECTED_CORPUS["output_sha256"] if is_last else None,
            "continuation_sha256": None if is_last else digest(f"continuation-{index}"),
        }
        line, previous = record(payload)
        lines.append(line)
        segments.append(payload)
        global_first += cycles
    if any(remaining.values()):
        raise AssertionError("synthetic journal family totals did not close")
    summary = {
        "schema": segmented.SUMMARY_SCHEMA,
        "clock_frame": segmented.CLOCK_FRAME_LEAF_LOCAL,
        "previous_record_sha256": previous,
        "claim_boundary": segmented.CLAIM_BOUNDARY,
        "completed": True,
        "segment_count": 210,
        "total_cycles": ledger.EXPECTED_CORPUS["total_cycles"],
        "total_core_trace_rows": ledger.EXPECTED_CORPUS["total_core_trace_rows"],
        "total_external_trace_rows": ledger.EXPECTED_CORPUS["total_external_trace_rows"],
        "external_family_rows": [
            {
                "family": family,
                "calls": rows,
                "execution_rows": rows,
            } for family, rows in ledger.EXPECTED_EXTERNAL_ROWS.items()
        ],
        "total_unclassified_core_rows": 0,
        "opcode_family_rows": [
            {"family": family, "rows": ledger.EXPECTED_FAMILY_ROWS[family]}
            for family in segmented.FAMILIES
        ],
        "completion_reason": "halt_flag",
        "exit_code": None,
        "output_bytes": 43,
        "output_sha256": ledger.EXPECTED_CORPUS["output_sha256"],
        "final_cpu_sha256": CPU_SHA,
        "final_rw_memory_sha256": MEMORY_SHA,
        "final_access_clocks_sha256": ACCESS_SHA,
        "max_segment_cycle_count": 4_194_304,
        "leaf_local_clock_ranges_within_v3_limit": True,
        "segment_statement_v2_global_cycle_limit": 1 << 24,
        "segment_statement_v2_admissible": False,
    }
    lines.append(record(summary)[0])
    path.write_bytes(b"".join(lines))
    return segments


def write_tape(path: Path, segment: dict) -> None:
    body = bytearray(ledger.TAPE_MAGIC)
    body += struct.pack("<HHI", 1, 1, 0)
    for value in (
        digest("program"), ledger.EXPECTED_HEADER["input_sha256"],
        digest("session"), MEMORY_SHA, MEMORY_SHA,
        digest(f"entry-boundary-{segment['segment_index']}"),
        digest(f"exit-boundary-{segment['segment_index']}"),
    ):
        body += bytes.fromhex(value)
    body += struct.pack(
        "<IQII", segment["segment_index"], segment["global_first_cycle"],
        segment["cycle_count"], segment["core_trace_rows"],
    )
    body += CPU_BYTES + CPU_BYTES
    body += hashlib.sha256(ledger.TAPE_CHECKSUM_DOMAIN + body).digest()
    path.write_bytes(body)


class OpportunityLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.journal = self.root / "execution-v3.ndjson"
        segments = write_journal(self.journal)
        self.journal_sha256 = hashlib.sha256(self.journal.read_bytes()).hexdigest()
        self.tapes = self.root / "tapes"
        self.tapes.mkdir()
        for index in range(65):
            write_tape(
                self.tapes / f"segment-{index:06d}.stwemt01", segments[index],
            )
        self.profile_path = self._placeholder("profile.json")
        self.batch_path = self._placeholder("batch.json")
        self.topology_path = self._placeholder("topology.json")
        self.schedule_path = self._placeholder("schedule.json")
        self.keccak_path = self._placeholder("keccak.json")
        self.raw_pair_path = self._placeholder("raw-pair.json")
        self.profile = self._profile()
        self.batch = self._batch()
        self.topology = self._topology()
        self.schedule = self._schedule()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _placeholder(self, name: str) -> Path:
        path = self.root / name
        path.write_bytes(name.encode("ascii"))
        return path

    def _profile(self) -> dict:
        aggregate = {
            **ledger.profile_evidence.REFERENCE_65,
            "provider_padded_rows_sum": 30_875_648,
            "bridge_padded_rows_sum": 13_574_144,
        }
        fixed = 65 * (1 << 24) * 445
        combined = aggregate["combined_main_cells"]
        return {
            "content_sha256": digest("profile-content"),
            "tapes": [identity(
                self.tapes / f"segment-{index:06d}.stwemt01"
            ) for index in range(65)],
            "aggregate": aggregate,
            "models": {
                "fixed_legacy_main_cells": fixed,
                "changed_only_combined_main_cells": combined,
                "changed_only_committed_cells": aggregate["d6_committed_cells"],
                "main_cell_reduction": {
                    "numerator": fixed - combined,
                    "denominator": fixed,
                    "millionths": (fixed - combined) * 1_000_000 // fixed,
                },
            },
            "ranking": {"reference_65_admitted": True},
        }

    def _batch(self) -> dict:
        workload = {"batch_size": 4, "log_size": 16, "slice_call_count": 262_144}
        profile = {
            "preprocessed_columns": 2, "main_columns": 445,
            "tree2_columns": 12,
        }
        proofs = [{"bytes": 10 + index, "sha256": digest(f"proof-{index}")}
                  for index in range(4)]
        return {
            "content_sha256": digest("batch-content"),
            "measured": {
                "proof_batch_serial_wall_ns": 400,
                "proof_batch_concurrent_wall_ns": 100,
                "proof_batch_speedup": {"numerator": 400, "denominator": 100, "milli": 4000},
                "stage_a_serial": {"wall_ns": 200},
                "stage_a_concurrent": {"wall_ns": 50},
                "stage_a_speedup": {"numerator": 200, "denominator": 50, "milli": 4000},
            },
            "source_receipt": {
                "workload": workload,
                "profile": profile,
                "proofs": {"concurrent": proofs},
            },
        }

    def _topology(self) -> dict:
        arms = [{
            "concurrent_jobs": jobs,
            "per_job_engine_workers": workers,
            "stage_a_wall_ns": stage,
            "proof_batch_wall_ns": proof,
            "cold_verify_wall_ns": 10,
            "arm_total_wall_ns": stage + proof + 10,
            "peak_physical_footprint_bytes": 1000 * jobs,
        } for jobs, workers, stage, proof in (
            (2, 8, 90, 300), (3, 5, 80, 250), (4, 4, 70, 100),
        )]
        proofs = [{
            "proof": {"bytes": 10 + index, "sha256": digest(f"proof-{index}")}
        } for index in range(4)]
        return {
            "measured_arms": arms,
            "best_measured_arm": arms[-1],
            "source_receipt": {
                "workload": copy.deepcopy(self.batch["source_receipt"]["workload"]),
                "profile": copy.deepcopy(self.batch["source_receipt"]["profile"]),
                "arms": [{"proofs": proofs}],
            },
        }

    def _schedule(self) -> dict:
        return {
            "ranked_leads": [
                {
                    "candidate_id": "incremental-memory-changed-only-v2",
                    "source_evidence": identity(self.profile_path),
                    "schedule_rank": 1,
                    "scope": "geometry",
                    "impact": {"kind": "cells", "millionths": 900_000},
                },
                {
                    "candidate_id": "provider-raw-batch-concurrency-v2",
                    "source_evidence": identity(self.batch_path),
                    "schedule_rank": 2,
                    "scope": "proof-batch",
                    "impact": {"kind": "wall", "millionths": 750_000},
                },
            ],
            "excluded_inputs": [
                {
                    "identity": identity(self.raw_pair_path),
                    "schema": "stwo.ethereum.poseidon-provider-raw-pair-hpc-benchmark.v1",
                    "reason": "executable-custody-overwritten-no-immutable-copy",
                    "ranked": False,
                    "production_promotion_eligible": False,
                },
                {
                    "identity": identity(self.keccak_path),
                    "schema": "stwo.riscv.keccak-adaptive-corpus-projection.v1",
                    "reason": "digest-only-source-authorities-and-no-content-seal",
                    "ranked": False,
                    "production_promotion_eligible": False,
                },
            ],
        }

    @contextmanager
    def _adapters(self):
        with mock.patch.object(ledger.profile_evidence, "load", return_value=self.profile), \
             mock.patch.object(ledger.batch_evidence, "load", return_value=self.batch), \
             mock.patch.object(ledger.topology_evidence, "load", return_value=self.topology), \
             mock.patch.object(ledger.schedule_protocol, "load", return_value=self.schedule), \
             mock.patch.object(ledger, "EXPECTED_JOURNAL_SHA256", self.journal_sha256):
            yield

    def _build(self) -> dict:
        return ledger.build(
            self.journal, self.profile_path, self.batch_path,
            self.topology_path, self.schedule_path,
        )

    def test_ledger_cross_binds_prefix_and_keeps_claim_scopes_separate(self) -> None:
        with self._adapters():
            value = self._build()
            path = self.root / "ledger.json"
            path.write_bytes(protocol.canonical_bytes(value))
            self.assertEqual(value, ledger.load(path))
        self.assertFalse(value["incremental_corpus_join"]["coverage"]["full_corpus"])
        inventory = {item["family"]: item for item in value["corpus"]["family_inventory"]}
        load_store = inventory["load_store"]
        self.assertEqual(280_225_149, load_store["active_rows"])
        self.assertGreaterEqual(
            load_store["diagnostic_padded_rows"], load_store["active_rows"],
        )
        self.assertEqual((131_136, 5), ledger._sharded_padding(
            [0, 1, 17, 65_536, 65_537],
        ))
        opportunities = {item["opportunity_id"]: item for item in value["opportunities"]}
        self.assertIsNone(opportunities[
            "load-store-specialization-unadmitted"
        ]["family_metrics"][0]["candidate_savings"])
        topology = opportunities[
            "provider-raw-batch-concurrency-v2"
        ]["measured_topology_sweep"]
        self.assertEqual(4, topology["best_arm"]["concurrent_jobs"])
        self.assertFalse(value["claims"]["independent_gain_multiplication_used"])
        self.assertIsNone(value["claims"]["cross_family_speedup"])
        self.assertIsNone(value["claims"]["measured_end_to_end_wall_ns"])

    def test_replay_rejects_claim_and_retained_input_mutations(self) -> None:
        with self._adapters():
            value = self._build()
            forged = copy.deepcopy(value)
            forged["claims"]["modeled_end_to_end_wall_ns"] = 1
            forged["content_sha256"] = protocol.content_sha256(forged)
            with self.assertRaisesRegex(ledger.OpportunityLedgerError, "replay"):
                ledger.validate(forged)
            forged_topology = copy.deepcopy(value)
            provider = next(item for item in forged_topology["opportunities"]
                            if item["opportunity_id"]
                            == "provider-raw-batch-concurrency-v2")
            provider["measured_topology_sweep"]["best_arm"][
                "proof_batch_wall_ns"
            ] += 1
            forged_topology["content_sha256"] = protocol.content_sha256(
                forged_topology
            )
            with self.assertRaisesRegex(ledger.OpportunityLedgerError, "replay"):
                ledger.validate(forged_topology)
            self.journal.write_bytes(self.journal.read_bytes() + b"\n")
            with self.assertRaisesRegex(ledger.OpportunityLedgerError, "identity"):
                ledger.validate(value)

    def test_tape_and_keccak_admission_fail_closed(self) -> None:
        tape = self.tapes / "segment-000000.stwemt01"
        raw = bytearray(tape.read_bytes())
        raw[-1] ^= 1
        tape.write_bytes(raw)
        with self._adapters(), self.assertRaisesRegex(
            ledger.OpportunityLedgerError, "identity",
        ):
            self._build()
        write_tape(tape, write_journal(self.journal)[0])
        self.profile = self._profile()
        self.schedule = self._schedule()
        self.schedule["excluded_inputs"] = self.schedule["excluded_inputs"][:1]
        with self._adapters(), self.assertRaisesRegex(
            ledger.OpportunityLedgerError, "Keccak exclusion",
        ):
            self._build()


if __name__ == "__main__":
    unittest.main()
