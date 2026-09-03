"""Seal a fail-closed opportunity ledger over retained Ethereum diagnostics.

The ledger never turns a geometry projection or a stage-local microbenchmark
into a proof or end-to-end timing claim.  Its corpus authority is the canonical
V3 execution journal; every other admitted input is reopened by its dedicated
adapter.  Compact tapes are additionally cross-bound to the journal prefix so
the 65-leaf incremental result cannot be silently relabeled as another corpus.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_incremental_profile_v2_evidence as profile_evidence  # noqa: E402
import ethereum_block_microbenchmark_schedule as schedule_protocol  # noqa: E402
import ethereum_block_provider_raw_batch_evidence as batch_evidence  # noqa: E402
import ethereum_block_provider_topology_evidence as topology_evidence  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402
from scripts import riscv_segmented_execution as segmented  # noqa: E402


SCHEMA = "stwo.ethereum.retained-corpus-opportunity-ledger.v1"
STATUS = "diagnostic-opportunities-replayed-nonpromotable"
MAX_EXPERIMENT_SECONDS = 60
TAPE_MAGIC = b"STWEMT01"
TAPE_CHECKSUM_DOMAIN = b"stwo.riscv.ethereum-minimal-artifact.v1\0"
CPU_IDENTITY_DOMAIN = b"stwo-zig/riscv/segment-boundary-cpu/v1\0"
MAX_TAPE_BYTES = 256 << 20
EXPECTED_JOURNAL_SHA256 = (
    "8316cb34b4573f234db76b8f0dcf54ec852a54688f8b68d2a9ffa4dfd25f240e"
)
EXPECTED_HEADER = {
    "schema": segmented.HEADER_SCHEMA,
    "profile": segmented.PROFILE_ETHEREUM,
    "clock_frame": segmented.CLOCK_FRAME_LEAF_LOCAL,
    "claim_boundary": segmented.CLAIM_BOUNDARY,
    "elf_bytes": 3_352_364,
    "elf_sha256": "b751305c0e350918a4a1e692fcfd620a54f5bce6c50322230e156faca95328fa",
    "input_bytes": 2_700_692,
    "input_sha256": "faaf02583929396faed177914da27b4a493766993001357bd1720340ca1ddabb",
    "segment_step_budget": 4_194_304,
    "strict_completion": True,
    "trace_retention": "segment-owned",
}
EXPECTED_FAMILY_ROWS = {
    "auipc": 1_292_638,
    "base_alu_imm": 250_128_062,
    "base_alu_reg": 64_906_115,
    "branch_eq": 112_500_693,
    "branch_lt": 114_034_466,
    "div": 12_690,
    "jal": 800_291,
    "jalr": 3_155_823,
    "load_store": 280_225_149,
    "lt_imm": 194_520,
    "lt_reg": 12_323_520,
    "lui": 1_273_131,
    "mul": 9_755_116,
    "mulh": 9_300_216,
    "shifts_imm": 18_396_304,
    "shifts_reg": 2_426_349,
    "fence": 2_245,
}
EXPECTED_EXTERNAL_ROWS = {
    "stwo.keccakf-1600.permute-in-place@1": 32_835,
    "stwo.secp256k1.recover-signer@1": 66,
}
EXPECTED_CORPUS = {
    "segment_count": 210,
    "total_cycles": 880_760_229,
    "total_core_trace_rows": 880_727_328,
    "total_external_trace_rows": 32_901,
    "entry_exit_nonzero_word_inclusions": 898_968_604,
    "touched_transitions": 6_541_934,
    "output_bytes": 43,
    "output_sha256": "730396807814bc71f14405b3ecf27237778a5359732001b32c93692c3275a8c5",
}


class OpportunityLedgerError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise OpportunityLedgerError(message)


def _identity(path: Path, where: str) -> dict[str, Any]:
    path = path.absolute()
    return {"path": str(path), **store.file_identity(path, where)}


def _validate_identity(value: Any, where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {"path", "bytes", "sha256"},
             f"{where} keys differ")
    path = Path(value["path"])
    _require(path.is_absolute() and value == _identity(path, where),
             f"{where} identity differs")
    return value


def _padded_rows(rows: int) -> int:
    return 0 if rows == 0 else 1 << max(4, (rows - 1).bit_length())


def _sharded_padding(rows: list[int]) -> tuple[int, int]:
    """Apply only the explicit diagnostic max-log16/min-log4 partition."""
    padded = shards = 0
    for leaf_rows in rows:
        remaining = leaf_rows
        while remaining:
            shard_rows = min(remaining, 1 << 16)
            padded += _padded_rows(shard_rows)
            shards += 1
            remaining -= shard_rows
    return padded, shards


def _ratio(numerator: int, denominator: int) -> dict[str, int]:
    _require(type(numerator) is int and type(denominator) is int
             and 0 <= numerator <= denominator and denominator > 0,
             "opportunity ratio differs")
    return {
        "numerator": numerator,
        "denominator": denominator,
        "millionths": numerator * 1_000_000 // denominator,
    }


def _journal(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = path.absolute()
    raw = store.read_regular(
        path, "retained execution journal", maximum=segmented.MAX_JOURNAL_BYTES,
    )
    lines = raw.splitlines(keepends=True)
    _require(hashlib.sha256(raw).hexdigest() == EXPECTED_JOURNAL_SHA256,
             "retained corpus journal identity differs")
    try:
        summary = segmented.validate_records(lines, require_complete=True)
    except segmented.ContractError as error:
        raise OpportunityLedgerError(str(error)) from error
    _require(summary is not None, "retained execution journal is incomplete")
    records = [json.loads(line)["payload"] for line in lines]
    header, segments = records[0], records[1:-1]
    _require(header == EXPECTED_HEADER, "retained corpus header differs")
    family_rows = {item["family"]: item["rows"]
                   for item in summary["opcode_family_rows"]}
    external_rows = {item["family"]: item["execution_rows"]
                     for item in summary["external_family_rows"]}
    inclusions = sum(
        item["entry"]["rw_memory_nonzero_words"]
        + item["exit"]["rw_memory_nonzero_words"]
        for item in segments
    )
    touched = sum(
        item["exit"]["memory_access_clock_entries"] for item in segments
    )
    actual = {
        "segment_count": len(segments),
        "total_cycles": summary["total_cycles"],
        "total_core_trace_rows": summary["total_core_trace_rows"],
        "total_external_trace_rows": summary["total_external_trace_rows"],
        "entry_exit_nonzero_word_inclusions": inclusions,
        "touched_transitions": touched,
        "output_bytes": summary["output_bytes"],
        "output_sha256": summary["output_sha256"],
    }
    _require(actual == EXPECTED_CORPUS
             and family_rows == EXPECTED_FAMILY_ROWS
             and external_rows == EXPECTED_EXTERNAL_ROWS,
             "retained corpus workload differs")

    inventory = []
    for family in segmented.FAMILIES:
        rows = [next(item["rows"] for item in segment["opcode_family_rows"]
                     if item["family"] == family) for segment in segments]
        padded, shards = _sharded_padding(rows)
        inventory.append({
            "family": family,
            "inventory_kind": "core-opcode-family",
            "active_rows": sum(rows),
            "diagnostic_padded_rows": padded,
            "diagnostic_shard_count": shards,
            "padding_policy": "per-leaf-contiguous-max-log16-min-log4",
            "nonzero_segments": sum(value > 0 for value in rows),
            "current_committed_cell_burden": None,
            "candidate_committed_cells": None,
            "candidate_savings": None,
            "cell_authority_status": "unavailable-no-typed-column-profile",
            "evidence_class": "canonical-journal-row-inventory-exact",
        })
    for family in segmented.EXTERNAL_FAMILIES[segmented.PROFILE_ETHEREUM]:
        rows = [next(item["execution_rows"]
                     for item in segment["external_family_rows"]
                     if item["family"] == family) for segment in segments]
        padded, shards = _sharded_padding(rows)
        inventory.append({
            "family": family,
            "inventory_kind": "external-call-family",
            "active_rows": sum(rows),
            "diagnostic_padded_rows": padded,
            "diagnostic_shard_count": shards,
            "padding_policy": "per-leaf-contiguous-max-log16-min-log4",
            "nonzero_segments": sum(value > 0 for value in rows),
            "current_committed_cell_burden": None,
            "candidate_committed_cells": None,
            "candidate_savings": None,
            "cell_authority_status": "unavailable-no-admitted-proof-profile",
            "evidence_class": "canonical-journal-call-inventory-exact",
        })
    projection = {
        "identity": _identity(path, "retained execution journal"),
        "header": copy.deepcopy(header),
        **actual,
        "boundary_to_touched_amplification": {
            "numerator": inclusions,
            "denominator": touched,
        },
        "family_inventory": inventory,
        "claim_boundary": "execution-workload-only-not-a-proof",
    }
    return projection, segments


def _cpu_identity(encoded: bytes) -> str:
    _require(len(encoded) == 132, "compact tape CPU encoding differs")
    values = struct.unpack("<33I", encoded)
    _require(values[1] == 0, "compact tape zero register differs")
    return hashlib.sha256(CPU_IDENTITY_DOMAIN + encoded).hexdigest()


def _compact_tape(path: Path, expected: dict[str, Any],
                  segment: dict[str, Any]) -> dict[str, Any]:
    _validate_identity(expected, "incremental compact tape")
    raw = store.read_regular(
        path, "incremental compact tape", maximum=MAX_TAPE_BYTES,
    )
    _require(len(raw) >= 556 and raw[:8] == TAPE_MAGIC,
             "compact tape framing differs")
    _require(hashlib.sha256(TAPE_CHECKSUM_DOMAIN + raw[:-32]).digest()
             == raw[-32:], "compact tape checksum differs")
    version, schema, reserved = struct.unpack_from("<HHI", raw, 8)
    _require((version, schema, reserved) == (1, 1, 0),
             "compact tape version differs")
    offset = 16
    names = (
        "program_sha256", "input_sha256", "session_sha256",
        "entry_memory_sha256", "exit_memory_sha256",
        "entry_boundary_sha256", "exit_boundary_sha256",
    )
    digests = {}
    for name in names:
        digests[name] = raw[offset:offset + 32].hex()
        offset += 32
    segment_index = struct.unpack_from("<I", raw, offset)[0]
    offset += 4
    global_first_cycle = struct.unpack_from("<Q", raw, offset)[0]
    offset += 8
    cycle_count, core_cycle_count = struct.unpack_from("<II", raw, offset)
    offset += 8
    entry_cpu_sha256 = _cpu_identity(raw[offset:offset + 132])
    offset += 132
    exit_cpu_sha256 = _cpu_identity(raw[offset:offset + 132])
    _require(
        segment_index == segment["segment_index"]
        and global_first_cycle == segment["global_first_cycle"]
        and cycle_count == segment["cycle_count"]
        and core_cycle_count == segment["core_trace_rows"]
        and digests["entry_memory_sha256"]
        == segment["entry"]["rw_memory_sha256"]
        and digests["exit_memory_sha256"]
        == segment["exit"]["rw_memory_sha256"]
        and entry_cpu_sha256 == segment["entry"]["cpu_sha256"]
        and exit_cpu_sha256 == segment["exit"]["cpu_sha256"],
        f"compact tape segment {segment['segment_index']} journal binding differs",
    )
    return {
        "segment_index": segment_index,
        "global_first_cycle": global_first_cycle,
        "cycle_count": cycle_count,
        "core_cycle_count": core_cycle_count,
        **digests,
        "entry_cpu_sha256": entry_cpu_sha256,
        "exit_cpu_sha256": exit_cpu_sha256,
    }


def _incremental_join(value: dict[str, Any], segments: list[dict[str, Any]],
                      input_sha256: str) -> dict[str, Any]:
    aggregate = value["aggregate"]
    tapes = value["tapes"]
    _require(value["ranking"]["reference_65_admitted"] is True
             and aggregate["segment_count"] == len(tapes) == 65
             and len(tapes) <= len(segments),
             "incremental profile corpus coverage differs")
    projections = [
        _compact_tape(Path(tape["path"]), tape, segments[index])
        for index, tape in enumerate(tapes)
    ]
    _require(all(item["input_sha256"] == input_sha256 for item in projections)
             and len({item["program_sha256"] for item in projections}) == 1
             and len({item["session_sha256"] for item in projections}) == 1,
             "incremental compact tape source authority differs")
    join_payload = [{
        "segment_index": item["segment_index"],
        "tape_sha256": tapes[index]["sha256"],
        "entry_cpu_sha256": item["entry_cpu_sha256"],
        "exit_cpu_sha256": item["exit_cpu_sha256"],
        "entry_memory_sha256": item["entry_memory_sha256"],
        "exit_memory_sha256": item["exit_memory_sha256"],
    } for index, item in enumerate(projections)]
    return {
        "coverage": {
            "kind": "canonical-contiguous-prefix",
            "first_segment_index": 0,
            "segment_count": len(projections),
            "corpus_segment_count": len(segments),
            "full_corpus": len(projections) == len(segments),
        },
        "journal_cross_binding": {
            "checksum_replayed": True,
            "input_identity_equal": True,
            "cycle_ranges_equal": True,
            "core_and_total_cycles_equal": True,
            "full_memory_boundaries_equal": True,
            "cpu_boundaries_equal": True,
            "join_sha256": protocol.sha256_bytes(
                b"stwo.ethereum.incremental-journal-prefix-join.v1\0"
                + protocol.canonical_bytes(join_payload)
            ),
        },
        "program_sha256": projections[0]["program_sha256"],
        "session_sha256": projections[0]["session_sha256"],
    }


def _inventory_by_family(corpus: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["family"]: item for item in corpus["family_inventory"]}


def _memory_opportunity(value: dict[str, Any], join: dict[str, Any]) -> dict[str, Any]:
    aggregate, models = value["aggregate"], value["models"]
    provider_candidate_committed = (
        aggregate["provider_padded_rows_sum"]
        * (profile_evidence.D6_POSEIDON_MAIN_COLUMNS
           + profile_evidence.D6_POSEIDON_INTERACTION_COLUMNS)
    )
    bridge_candidate_committed = (
        aggregate["bridge_padded_rows_sum"]
        * (profile_evidence.BRIDGE_MAIN_COLUMNS
           + profile_evidence.BRIDGE_INTERACTION_COLUMNS)
    )
    _require(provider_candidate_committed + bridge_candidate_committed
             == aggregate["d6_committed_cells"],
             "incremental committed-cell closure differs")
    return {
        "opportunity_id": "incremental-memory-changed-only-v2",
        "family": "memory-commitment",
        "coverage": copy.deepcopy(join["coverage"]),
        "family_metrics": [
            {
                "family": "poseidon-provider",
                "active_rows": aggregate["total_hash_calls"],
                "padded_rows": aggregate["provider_padded_rows_sum"],
                "current_main_cells": models["fixed_legacy_main_cells"],
                "candidate_main_cells": aggregate["d6_poseidon_main_cells"],
                "current_committed_cell_burden": None,
                "candidate_committed_cells": provider_candidate_committed,
                "candidate_main_cell_savings": (
                    models["fixed_legacy_main_cells"]
                    - aggregate["d6_poseidon_main_cells"]
                ),
            },
            {
                "family": "incremental-transition-bridge",
                "active_rows": aggregate["bridge_rows"],
                "padded_rows": aggregate["bridge_padded_rows_sum"],
                "current_main_cells": 0,
                "candidate_main_cells": aggregate["bridge_main_cells"],
                "current_committed_cell_burden": 0,
                "candidate_committed_cells": bridge_candidate_committed,
                "candidate_main_cell_savings": -aggregate["bridge_main_cells"],
            },
        ],
        "aggregate_cells": {
            "scope": "main-trace-m31-cells-over-cross-bound-prefix",
            "current_main_cells": models["fixed_legacy_main_cells"],
            "candidate_main_cells": models["changed_only_combined_main_cells"],
            "main_cell_savings": copy.deepcopy(models["main_cell_reduction"]),
            "current_committed_cell_burden": None,
            "current_committed_unavailable_reason": (
                "incremental-v2-retains-no-exact-legacy-tree2-profile"
            ),
            "candidate_committed_cells": models["changed_only_committed_cells"],
        },
        "measured_stage_speedups": [],
        "evidence": {
            "class": "replayed-cross-bound-prefix-geometry",
            "confidence": "exact-for-retained-65-segment-prefix-only",
            "corpus_bound": True,
            "proof_correctness": None,
            "fresh_verification": None,
            "ranking_eligible": True,
        },
        "estimated_end_to_end_wall_ns": None,
        "production_promotion_eligible": False,
    }


def _provider_opportunity(value: dict[str, Any],
                          topology: dict[str, Any]) -> dict[str, Any]:
    measured = value["measured"]
    receipt = value["source_receipt"]
    workload, profile = receipt["workload"], receipt["profile"]
    topology_receipt = topology["source_receipt"]
    batch_proofs = receipt["proofs"]["concurrent"]
    topology_proofs = topology_receipt["arms"][0]["proofs"]
    _require(workload == topology_receipt["workload"]
             and profile == topology_receipt["profile"]
             and [{key: item[key] for key in ("bytes", "sha256")}
                  for item in batch_proofs]
             == [{key: item["proof"][key] for key in ("bytes", "sha256")}
                 for item in topology_proofs],
             "provider batch/topology custody join differs")
    padded_rows = workload["batch_size"] * (1 << workload["log_size"])
    _require(padded_rows == workload["slice_call_count"],
             "provider batch padded rows differ")
    trace_columns = (
        profile["preprocessed_columns"] + profile["main_columns"]
        + profile["tree2_columns"]
    )
    trace_cells = padded_rows * trace_columns
    serial = measured["proof_batch_serial_wall_ns"]
    concurrent = measured["proof_batch_concurrent_wall_ns"]
    stage_serial = measured["stage_a_serial"]["wall_ns"]
    stage_concurrent = measured["stage_a_concurrent"]["wall_ns"]
    topology_arms = topology["measured_arms"]
    topology_reference = topology_arms[0]["proof_batch_wall_ns"]
    topology_best = topology["best_measured_arm"]
    return {
        "opportunity_id": "provider-raw-batch-concurrency-v2",
        "family": "poseidon-provider-concurrency",
        "coverage": {
            "kind": "standalone-n4-log16-batch",
            "corpus_bound": False,
            "batch_size": workload["batch_size"],
            "log_size": workload["log_size"],
        },
        "family_metrics": [{
            "family": "ordered-provider-v2-trace-trees",
            "active_rows": workload["slice_call_count"],
            "padded_rows": padded_rows,
            "current_committed_cell_burden": trace_cells,
            "candidate_committed_cells": trace_cells,
            "candidate_cell_savings": 0,
            "cell_scope": "tree0-plus-tree1-plus-tree2-excludes-composition",
        }],
        "measured_stage_speedups": [
            {
                "stage": "stage-a",
                "serial_wall_ns": stage_serial,
                "concurrent_wall_ns": stage_concurrent,
                "wall_savings": _ratio(
                    stage_serial - stage_concurrent, stage_serial,
                ),
                "speedup": copy.deepcopy(measured["stage_a_speedup"]),
            },
            {
                "stage": "raw-proof-batch",
                "serial_wall_ns": serial,
                "concurrent_wall_ns": concurrent,
                "wall_savings": _ratio(serial - concurrent, serial),
                "speedup": copy.deepcopy(measured["proof_batch_speedup"]),
            },
        ],
        "measured_topology_sweep": {
            "scope": "same-n4-log16-workload-stage-local",
            "arms": copy.deepcopy(topology_arms),
            "best_arm": copy.deepcopy(topology_best),
            "best_vs_2x8_proof_batch_wall_savings": _ratio(
                topology_reference - topology_best["proof_batch_wall_ns"],
                topology_reference,
            ),
            "all_proofs_cross_arm_byte_identical_and_fresh_verified": True,
            "estimated_end_to_end_wall_ns": None,
        },
        "batch_topology_cross_binding": {
            "workload_equal": True,
            "profile_equal": True,
            "canonical_proof_identities_equal": True,
        },
        "evidence": {
            "class": "measured-stage-local-fresh-verified",
            "confidence": (
                "exact-for-retained-n4-log16-batch-and-2x8-3x5-4x4-sweep-only"
            ),
            "corpus_bound": False,
            "proof_correctness": True,
            "fresh_verification": True,
            "ranking_eligible": True,
        },
        "estimated_end_to_end_wall_ns": None,
        "production_promotion_eligible": False,
    }


def _workload_only_opportunity(
    inventory: dict[str, dict[str, Any]], *, opportunity_id: str,
    family: str, exclusion: dict[str, Any] | None, reason: str,
) -> dict[str, Any]:
    item = inventory[family]
    return {
        "opportunity_id": opportunity_id,
        "family": family,
        "coverage": {"kind": "full-journal", "segment_count": 210},
        "family_metrics": [{
            "family": family,
            "active_rows": item["active_rows"],
            "padded_rows": item["diagnostic_padded_rows"],
            "shard_count": item["diagnostic_shard_count"],
            "padding_policy": item["padding_policy"],
            "current_committed_cell_burden": None,
            "candidate_committed_cells": None,
            "candidate_savings": None,
        }],
        "measured_stage_speedups": [],
        "evidence": {
            "class": "journal-workload-only",
            "confidence": "exact-workload-no-admitted-candidate-geometry",
            "corpus_bound": True,
            "proof_correctness": None,
            "fresh_verification": None,
            "ranking_eligible": False,
            "unavailable_reason": reason,
            "excluded_artifact": copy.deepcopy(exclusion),
        },
        "estimated_end_to_end_wall_ns": None,
        "production_promotion_eligible": False,
    }


def _scheduler_projection(value: dict[str, Any], profile_path: Path,
                          batch_path: Path) -> dict[str, Any]:
    expected = {
        "incremental-memory-changed-only-v2": _identity(
            profile_path, "incremental profile evidence",
        ),
        "provider-raw-batch-concurrency-v2": _identity(
            batch_path, "provider batch evidence",
        ),
    }
    leads = []
    for lead in value["ranked_leads"]:
        candidate = lead["candidate_id"]
        _require(candidate in expected and lead["source_evidence"] == expected[candidate],
                 "scheduler evidence join differs")
        leads.append({
            "source_schedule_rank": lead["schedule_rank"],
            "candidate_id": candidate,
            "scope": lead["scope"],
            "within_scope_impact": copy.deepcopy(lead["impact"]),
            "ledger_role": "diagnostic-within-scope-context-only",
        })
    _require({item["candidate_id"] for item in leads} == set(expected),
             "scheduler candidates differ")
    return {
        "source_rankings": leads,
        "source_opportunity_model_used": False,
        "source_opportunity_model_exclusion_reason": (
            "ledger-does-not-multiply-independent-stage-gains"
        ),
        "cross_family_speedup": None,
        "measured_end_to_end_wall_ns": None,
    }


def _next_experiments(opportunities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {item["opportunity_id"]: item for item in opportunities}
    rows = [
        (
            "full-corpus-incremental-v2-profile",
            "memory-commitment",
            "extend the exact changed-only profile from 65 to all 210 leaves",
            "requires-create-only-210-tape-materialization-authority",
            by_id["incremental-memory-changed-only-v2"]["evidence"]["class"],
        ),
        (
            "provider-cross-log-topology-sweep-v2",
            "poseidon-provider-concurrency",
            "test whether 4x4 remains best across other logs and shard counts",
            "requires-retained-immutable-executable-and-typed-producer-argv",
            by_id["provider-raw-batch-concurrency-v2"]["evidence"]["class"],
        ),
        (
            "load-store-subtype-census-v1",
            "load_store",
            "bind LB/LH/LBU/LHU/LW/SB/SH/SW rows before proposing geometry",
            "requires-typed-journal-bound-subtype-census-artifact",
            "journal-workload-only",
        ),
        (
            "keccak-projection-source-envelope-v2",
            "stwo.keccakf-1600.permute-in-place@1",
            "retain a sealed source-reopenable adaptive projection",
            "requires-v2-create-only-source-envelope-adapter",
            "journal-workload-only",
        ),
    ]
    return [{
        "rank": index,
        "experiment_id": experiment_id,
        "family": family,
        "objective": objective,
        "maximum_wall_seconds": MAX_EXPERIMENT_SECONDS,
        "measurement_command": None,
        "launch_ready": False,
        "unavailable_reason": unavailable,
        "source_evidence_class": evidence_class,
        "cross_family_numeric_score": None,
        "full_proof_forbidden": True,
        "whole_block_or_recursive_work_forbidden": True,
        "production_promotion_eligible": False,
    } for index, (experiment_id, family, objective, unavailable,
                  evidence_class) in enumerate(rows, 1)]


def build(journal_path: Path, profile_path: Path, batch_path: Path,
          topology_path: Path, schedule_path: Path) -> dict[str, Any]:
    journal_path, profile_path = journal_path.absolute(), profile_path.absolute()
    batch_path, topology_path = batch_path.absolute(), topology_path.absolute()
    schedule_path = schedule_path.absolute()
    corpus, segments = _journal(journal_path)
    profile_value = profile_evidence.load(profile_path)
    batch_value = batch_evidence.load(batch_path)
    topology_value = topology_evidence.load(topology_path)
    schedule_value = schedule_protocol.load(schedule_path)
    join = _incremental_join(
        profile_value, segments, corpus["header"]["input_sha256"],
    )
    scheduler = _scheduler_projection(schedule_value, profile_path, batch_path)
    exclusions = copy.deepcopy(schedule_value["excluded_inputs"])
    keccak = next((item for item in exclusions if item["schema"]
                   == "stwo.riscv.keccak-adaptive-corpus-projection.v1"), None)
    _require(keccak is not None and keccak["reason"]
             == "digest-only-source-authorities-and-no-content-seal",
             "Keccak exclusion authority differs")
    inventory = _inventory_by_family(corpus)
    opportunities = [
        _memory_opportunity(profile_value, join),
        _provider_opportunity(batch_value, topology_value),
        _workload_only_opportunity(
            inventory,
            opportunity_id="load-store-specialization-unadmitted",
            family="load_store",
            exclusion=None,
            reason="no-journal-bound-typed-load-store-subtype-artifact",
        ),
        _workload_only_opportunity(
            inventory,
            opportunity_id="keccak-adaptive-profile-unadmitted",
            family="stwo.keccakf-1600.permute-in-place@1",
            exclusion=keccak,
            reason="digest-only-v1-projection-has-no-reopenable-source-envelope",
        ),
    ]
    return protocol.seal({
        "schema": SCHEMA,
        "status": STATUS,
        "inputs": {
            "journal": corpus["identity"],
            "incremental_profile_v2": _identity(
                profile_path, "incremental profile evidence",
            ),
            "provider_batch_v2": _identity(
                batch_path, "provider batch evidence",
            ),
            "provider_topology_v1": _identity(
                topology_path, "provider topology evidence",
            ),
            "scheduler_v2": _identity(schedule_path, "microbenchmark schedule"),
        },
        "corpus": corpus,
        "incremental_corpus_join": join,
        "scheduler": scheduler,
        "opportunities": opportunities,
        "excluded_inputs": exclusions,
        "next_experiments": _next_experiments(opportunities),
        "claims": {
            "ranking_policy": (
                "categorical-evidence-and-actionability-order-only;"
                "no-cross-family-numeric-comparison"
            ),
            "independent_gain_multiplication_used": False,
            "cross_family_speedup": None,
            "measured_end_to_end_wall_ns": None,
            "modeled_end_to_end_wall_ns": None,
            "full_block_proof_complete": None,
            "fresh_full_block_verification": None,
            "production_promotion_eligible": False,
        },
    })


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "inputs", "corpus", "incremental_corpus_join",
        "scheduler", "opportunities", "excluded_inputs", "next_experiments",
        "claims", "content_sha256",
    }, "opportunity ledger keys differ")
    _require(value["schema"] == SCHEMA and value["status"] == STATUS
             and value["content_sha256"] == protocol.content_sha256(value),
             "opportunity ledger authority differs")
    inputs = value["inputs"]
    _require(type(inputs) is dict and set(inputs) == {
        "journal", "incremental_profile_v2", "provider_batch_v2",
        "provider_topology_v1", "scheduler_v2",
    }, "opportunity ledger inputs differ")
    for name, identity in inputs.items():
        _validate_identity(identity, f"opportunity ledger {name}")
    expected = build(
        Path(inputs["journal"]["path"]),
        Path(inputs["incremental_profile_v2"]["path"]),
        Path(inputs["provider_batch_v2"]["path"]),
        Path(inputs["provider_topology_v1"]["path"]),
        Path(inputs["scheduler_v2"]["path"]),
    )
    _require(value == expected, "opportunity ledger replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "opportunity ledger", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "opportunity ledger is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--journal", type=Path, required=True)
    create.add_argument("--incremental-profile", type=Path, required=True)
    create.add_argument("--provider-batch", type=Path, required=True)
    create.add_argument("--provider-topology", type=Path, required=True)
    create.add_argument("--schedule", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--staging-directory", type=Path, required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--ledger", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "replay":
            load(arguments.ledger)
            return 0
        output = arguments.output.absolute()
        staging = arguments.staging_directory.absolute()
        store.require_directory(output.parent, "opportunity ledger parent")
        store.require_directory(staging, "opportunity ledger staging", create=True)
        value = build(
            arguments.journal, arguments.incremental_profile,
            arguments.provider_batch, arguments.provider_topology,
            arguments.schedule,
        )
        store.publish_new_or_identical(
            output, protocol.canonical_bytes(value), staging_directory=staging,
        )
        return 0
    except (
        OpportunityLedgerError,
        profile_evidence.IncrementalProfileV2EvidenceError,
        batch_evidence.ProviderRawBatchEvidenceError,
        topology_evidence.ProviderTopologyEvidenceError,
        schedule_protocol.MicrobenchmarkScheduleError,
        protocol.ProofProtocolError,
        segmented.ContractError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
