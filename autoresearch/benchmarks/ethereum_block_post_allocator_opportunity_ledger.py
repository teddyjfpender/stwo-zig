"""Seal post-allocator Ethereum geometry opportunities without proof claims.

The 72-segment allocator-candidate journal is the workload authority.  Opcode
and external-call rows are reconstructed from every journal record.  Candidate
column profiles are bound to their exact source files, while the adaptive
Keccak result is accepted only through its retained journal-bound Zig receipt.
The memcpy observation contains marginal histograms, so this ledger exposes
only sound bounds and deliberately leaves its joined geometry unavailable.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_allocator_execution_evidence as allocator_evidence  # noqa: E402
import ethereum_block_memcpy_hotspot_evidence as memcpy_evidence  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402
from scripts import riscv_segmented_execution as segmented  # noqa: E402


SCHEMA = "stwo.ethereum.post-allocator-opportunity-ledger.v1"
STATUS = "exact-and-bounded-geometry-diagnostic-nonpromotable"
KECCAK_SCHEMA = "stwo.riscv.keccak-adaptive-corpus-projection.v1"
MAX_DIAGNOSTIC_WALL_NS = 60_000_000_000
FIXED_PROVIDER_LOG = 24
FIXED_PROVIDER_ROWS = 1 << FIXED_PROVIDER_LOG
M31_BYTES = 4
SHA256 = re.compile(r"^[0-9a-f]{64}$")

SOURCE_PATHS = (
    ("register-read-alias-v1",
     "src/frontends/riscv/air/lang/typed_register_read_alias_candidate_v1.zig"),
    ("two-read-register-alias-v1",
     "src/frontends/riscv/air/lang/typed_two_read_register_alias_candidate_v1.zig"),
    ("load-store-selector-alias-v1",
     "src/frontends/riscv/air/lang/typed_load_store_selector_alias_candidate_v1.zig"),
    ("legacy-poseidon2-air",
     "src/frontends/riscv/air/memory_commitment/poseidon2_air.zig"),
    ("degree-bounded-poseidon2-candidate",
     "src/frontends/riscv/air/lang/typed_poseidon2_degree_bounded_candidate.zig"),
    ("bulk-memcpy-opcode-candidate-v1",
     "src/frontends/riscv/isa/bulk_memcpy_candidate_v1.zig"),
    ("bulk-memcpy-word-candidate-v1",
     "src/frontends/riscv/air/guest_precompile/bulk_memcpy_word_candidate_v1.zig"),
    ("bulk-memcpy-caller-candidate-v1",
     "src/frontends/riscv/air/guest_precompile/bulk_memcpy_caller_candidate_v1.zig"),
)

ALIAS_PROFILES = (
    ("register-read-alias-v1", (
        ("base_alu_imm", 35, 31),
        ("branch_eq", 30, 22),
        ("branch_lt", 37, 29),
    )),
    ("two-read-register-alias-v1", (
        ("lt_reg", 44, 36),
        ("mul", 39, 31),
        ("mulh", 47, 39),
    )),
    ("load-store-selector-alias-v1", (("load_store", 50, 48),)),
)

KECCAK_KEYS = (
    "schema", "schema_version", "production_active", "measurement_kind",
    "proof_or_fresh_verification", "journal_sha256", "executable_sha256",
    "executable_bytes", "elf_sha256", "leaf_count", "total_core_rows",
    "total_keccak_calls", "modes", "log_sizes", "adaptive_cells",
    "compact_baseline_cells", "saved_cells", "selected_profile_plan_sha256",
    "projection_wall_ns", "max_rss_bytes", "projection_identity",
)
KECCAK_ROW_KEYS = (
    "leaves", "calls", "adaptive_cells", "compact_baseline_cells",
)


class PostAllocatorOpportunityLedgerError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PostAllocatorOpportunityLedgerError(message)


def _integer(value: Any, where: str, minimum: int = 0) -> int:
    _require(type(value) is int and value >= minimum, f"{where} differs")
    return value


def _sha(value: Any, where: str) -> str:
    _require(type(value) is str and SHA256.fullmatch(value) is not None,
             f"{where} differs")
    return value


def _identity(path: Path, where: str) -> dict[str, Any]:
    path = path.absolute()
    return {"path": str(path), **store.file_identity(path, where)}


def _validate_identity(value: Any, where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {"path", "bytes", "sha256"},
             f"{where} keys differ")
    _require(type(value["path"]) is str and Path(value["path"]).is_absolute()
             and value == _identity(Path(value["path"]), where),
             f"{where} identity differs")
    return value


def _padded_rows(rows: int) -> int:
    return 0 if rows == 0 else 1 << max(4, (rows - 1).bit_length())


def _sharded_padding(rows: list[int]) -> tuple[int, int]:
    padded = shards = 0
    for leaf_rows in rows:
        remaining = leaf_rows
        while remaining:
            shard_rows = min(remaining, 1 << 16)
            padded += _padded_rows(shard_rows)
            shards += 1
            remaining -= shard_rows
    return padded, shards


def _family_inventory(segments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    families = (
        ("core-opcode-family", segmented.FAMILIES, "opcode_family_rows", "rows"),
        ("external-call-family",
         segmented.EXTERNAL_FAMILIES[segmented.PROFILE_ETHEREUM],
         "external_family_rows", "execution_rows"),
    )
    for kind, names, record_key, value_key in families:
        for family in names:
            rows = []
            for segment_index, segment in enumerate(segments):
                records = segment[record_key]
                record = next((item for item in records
                               if item["family"] == family), None)
                _require(record is not None,
                         f"segment {segment_index} family {family} is absent")
                rows.append(_integer(
                    record[value_key], f"segment {segment_index} {family} rows",
                ))
            padded, shards = _sharded_padding(rows)
            result.append({
                "family": family,
                "inventory_kind": kind,
                "active_rows": sum(rows),
                "diagnostic_padded_rows": padded,
                "diagnostic_shard_count": shards,
                "nonzero_segments": sum(row > 0 for row in rows),
                "padding_policy": "per-leaf-contiguous-max-log16-min-log4",
                "evidence_class": "complete-v3-journal-row-inventory",
            })
    return result


def _journal(path: Path, allocator: dict[str, Any],
             memcpy: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = path.absolute()
    raw = store.read_regular(
        path, "allocator candidate V3 journal", maximum=segmented.MAX_JOURNAL_BYTES,
    )
    lines = raw.splitlines(keepends=True)
    try:
        summary = segmented.validate_records(lines, require_complete=True)
        records = [json.loads(line)["payload"] for line in lines]
    except (segmented.ContractError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise PostAllocatorOpportunityLedgerError(str(error)) from error
    _require(summary is not None and len(records) >= 3,
             "allocator candidate V3 journal is incomplete")
    header, segments = records[0], records[1:-1]
    candidate = allocator["executions"]["candidate"]
    allocator_inputs = allocator["inputs"]
    memcpy_inputs = memcpy["inputs"]
    memcpy_sample = memcpy["sample"]
    identity = _identity(path, "allocator candidate V3 journal")
    _require(
        header["schema"] == segmented.HEADER_SCHEMA
        and header["profile"] == segmented.PROFILE_ETHEREUM
        and header["clock_frame"] == segmented.CLOCK_FRAME_LEAF_LOCAL
        and header["claim_boundary"] == segmented.CLAIM_BOUNDARY
        and header["strict_completion"] is True
        and header["trace_retention"] == "segment-owned"
        and identity == memcpy_inputs["candidate_journal"]
        and memcpy_inputs["allocator_execution_evidence"]
        == allocator["_evidence_identity"]
        and header["elf_sha256"] == candidate["elf_sha256"]
        == allocator_inputs["candidate_elf"]["sha256"]
        and header["input_sha256"] == candidate["input_sha256"]
        == allocator_inputs["common_input"]["sha256"]
        and summary["segment_count"] == candidate["segment_count"]
        == memcpy_sample["full_journal_segment_count"]
        and summary["total_cycles"] == candidate["total_cycles"]
        == memcpy_sample["full_journal_total_cycles"]
        and summary["total_core_trace_rows"]
        == candidate["total_core_trace_rows"]
        == memcpy_sample["full_journal_total_core_trace_rows"]
        and summary["total_external_trace_rows"]
        == candidate["total_external_trace_rows"]
        == memcpy_sample["full_journal_total_external_trace_rows"]
        and summary["output_bytes"] == candidate["output_bytes"]
        == memcpy_sample["full_journal_output_bytes"]
        and summary["output_sha256"] == candidate["output_sha256"]
        == memcpy_sample["full_journal_output_sha256"],
        "allocator candidate V3 semantic join differs",
    )
    inventory = _family_inventory(segments)
    return ({
        "identity": identity,
        "header": copy.deepcopy(header),
        "segment_count": summary["segment_count"],
        "total_cycles": summary["total_cycles"],
        "total_core_trace_rows": summary["total_core_trace_rows"],
        "total_external_trace_rows": summary["total_external_trace_rows"],
        "output_bytes": summary["output_bytes"],
        "output_sha256": summary["output_sha256"],
        "family_inventory": inventory,
        "claim_boundary": "execution-workload-only-not-a-proof",
    }, segments)


def _keccak_projection(path: Path, executable_path: Path,
                       corpus: dict[str, Any]) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "post-allocator Keccak projection receipt",
        maximum=store.MAX_JSON_BYTES,
    )
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise PostAllocatorOpportunityLedgerError(
            "post-allocator Keccak projection is not JSON",
        ) from error
    canonical = (json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"),
    ) + "\n").encode("ascii")
    _require(type(value) is dict and tuple(value) == KECCAK_KEYS
             and raw == canonical, "Keccak projection encoding differs")
    executable = _identity(executable_path, "Keccak projection executable")
    _require(
        value["schema"] == KECCAK_SCHEMA
        and value["schema_version"] == 1
        and type(value["schema_version"]) is int
        and value["production_active"] is False
        and value["measurement_kind"] == "exact-committed-m31-cell-projection"
        and value["proof_or_fresh_verification"] is False
        and value["journal_sha256"] == corpus["identity"]["sha256"]
        and value["executable_sha256"] == executable["sha256"]
        and value["executable_bytes"] == executable["bytes"]
        and value["elf_sha256"] == corpus["header"]["elf_sha256"]
        and value["leaf_count"] == corpus["segment_count"]
        and value["total_core_rows"] == corpus["total_core_trace_rows"],
        "Keccak projection custody/workload differs",
    )
    _sha(value["selected_profile_plan_sha256"], "Keccak selected profile plan")
    _sha(value["projection_identity"], "Keccak projection identity")
    for field in (
        "executable_bytes", "leaf_count", "total_core_rows", "total_keccak_calls",
        "adaptive_cells", "compact_baseline_cells", "saved_cells",
        "projection_wall_ns", "max_rss_bytes",
    ):
        _integer(value[field], f"Keccak projection {field}")
    _require(0 < value["projection_wall_ns"] <= MAX_DIAGNOSTIC_WALL_NS
             and value["max_rss_bytes"] > 0,
             "Keccak projection process envelope differs")
    for name, rows, expected_count in (
        ("modes", value["modes"], 4),
        ("log_sizes", value["log_sizes"], 17),
    ):
        _require(type(rows) is list and len(rows) == expected_count,
                 f"Keccak projection {name} count differs")
        for index, row in enumerate(rows):
            _require(type(row) is dict and tuple(row) == KECCAK_ROW_KEYS,
                     f"Keccak projection {name} row {index} differs")
            for field in KECCAK_ROW_KEYS:
                _integer(row[field], f"Keccak projection {name} {index} {field}")
        _require(
            sum(row["leaves"] for row in rows) == value["leaf_count"]
            and sum(row["calls"] for row in rows) == value["total_keccak_calls"]
            and sum(row["adaptive_cells"] for row in rows)
            == value["adaptive_cells"]
            and sum(row["compact_baseline_cells"] for row in rows)
            == value["compact_baseline_cells"],
            f"Keccak projection {name} closure differs",
        )
    inventory = {row["family"]: row for row in corpus["family_inventory"]}
    _require(
        value["total_keccak_calls"]
        == inventory["stwo.keccakf-1600.permute-in-place@1"]["active_rows"]
        and value["saved_cells"]
        == value["compact_baseline_cells"] - value["adaptive_cells"] > 0,
        "Keccak projection totals differ",
    )
    return {"receipt": copy.deepcopy(value), "executable": executable}


def _source_authorities(
    paths: list[tuple[str, Path]] | None = None,
) -> list[dict[str, Any]]:
    selected = paths if paths is not None else [
        (role, REPOSITORY / relative) for role, relative in SOURCE_PATHS
    ]
    _require([role for role, _ in selected] == [role for role, _ in SOURCE_PATHS],
             "post-allocator source authority roles differ")
    return [{
        "role": role,
        "identity": _identity(path, f"{role} source"),
    } for role, path in selected]


def _capture_source_authorities(output: Path, staging: Path) -> list[dict[str, Any]]:
    directory = output.with_name(f"{output.stem}.sources")
    store.require_directory(directory, "post-allocator source custody", create=True)
    captured = []
    for role, relative in SOURCE_PATHS:
        source = REPOSITORY / relative
        raw = store.read_regular(source, f"{role} workspace source")
        destination = directory / f"{role}.source"
        store.publish_new_or_identical(
            destination, raw, staging_directory=staging,
        )
        captured.append((role, destination))
    return _source_authorities(captured)


def _inventory_map(corpus: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["family"]: row for row in corpus["family_inventory"]}


def _alias_opportunities(corpus: dict[str, Any]) -> list[dict[str, Any]]:
    inventory = _inventory_map(corpus)
    result = []
    for opportunity_id, profiles in ALIAS_PROFILES:
        families = []
        for family, canonical_columns, candidate_columns in profiles:
            row = inventory[family]
            current = row["diagnostic_padded_rows"] * canonical_columns
            candidate = row["diagnostic_padded_rows"] * candidate_columns
            families.append({
                "family": family,
                "active_rows": row["active_rows"],
                "padded_rows": row["diagnostic_padded_rows"],
                "shard_count": row["diagnostic_shard_count"],
                "canonical_main_columns": canonical_columns,
                "candidate_main_columns": candidate_columns,
                "current_main_cells": current,
                "candidate_main_cells": candidate,
                "saved_main_cells": current - candidate,
            })
        saved = sum(row["saved_main_cells"] for row in families)
        result.append({
            "opportunity_id": opportunity_id,
            "scope": "complete-72-segment-journal-padded-main-trace-geometry",
            "source_role": opportunity_id,
            "families": families,
            "saved_main_cells": saved,
            "saved_raw_m31_bytes": saved * M31_BYTES,
            "production_active": False,
            "proof_correctness": None,
            "fresh_verification": None,
            "measured_end_to_end_wall_ns": None,
        })
    return result


def _poseidon_opportunity(corpus: dict[str, Any]) -> dict[str, Any]:
    rows = corpus["segment_count"] * FIXED_PROVIDER_ROWS
    profiles = (
        ("legacy-materialized", 445, 8, 2, 8),
        ("degree5", 239, 8, 2, 16),
        ("degree6", 161, 8, 2, 32),
    )
    modeled = []
    for name, main, interaction, preprocessed, composition in profiles:
        trace = rows * (preprocessed + main + interaction)
        all_committed = trace + rows * composition
        modeled.append({
            "profile": name,
            "fixed_rows": rows,
            "preprocessed_columns": preprocessed,
            "main_columns": main,
            "interaction_columns": interaction,
            "composition_columns_at_trace_log": composition,
            "trace_committed_cells": trace,
            "standalone_composition_cells": rows * composition,
            "standalone_all_committed_cells": all_committed,
        })
    baseline = modeled[0]
    for profile in modeled:
        profile["saved_main_cells_vs_legacy"] = (
            rows * (baseline["main_columns"] - profile["main_columns"])
        )
        profile["saved_all_committed_cells_vs_legacy"] = (
            baseline["standalone_all_committed_cells"]
            - profile["standalone_all_committed_cells"]
        )
    return {
        "opportunity_id": "fixed-log24-poseidon-degree-profile-model",
        "scope": "72-independent-fixed-log24-provider-traces",
        "row_model": "one-log24-provider-domain-per-journal-segment",
        "profiles": modeled,
        "production_active": False,
        "proof_correctness": None,
        "fresh_verification": None,
        "measured_end_to_end_wall_ns": None,
    }


def _memcpy_model(memcpy: dict[str, Any]) -> dict[str, Any]:
    observation = memcpy["source_observation"]
    lengths = observation["length_histogram"]
    alignments = observation["alignment_histogram"]
    total_calls = observation["call_count"]
    length_calls = sum(row["call_count"] for row in lengths if row["length"] >= 32)
    length_bytes = sum(row["total_bytes"] for row in lengths if row["length"] >= 32)
    alignment_calls = sum(
        row["call_count"] for row in alignments
        if row["source_mod_16"] % 4 == row["destination_mod_16"] % 4
    )
    joint_lower = max(0, length_calls + alignment_calls - total_calls)
    joint_upper = min(length_calls, alignment_calls)
    word_rows = [sum(
        row["call_count"] * ((row["length"] + offset + 3) // 4)
        for row in lengths if row["length"] >= 32
    ) for offset in range(4)]
    return {
        "opportunity_id": "bulk-memcpy-prefix-marginal-model-v1",
        "scope": "sealed-candidate-first-64-segment-prefix",
        "source_evidence_content_sha256": memcpy["content_sha256"],
        "observed_call_count": total_calls,
        "observed_requested_bytes": observation["total_requested_bytes"],
        "minimum_length_eligible_calls": length_calls,
        "minimum_length_eligible_bytes": length_bytes,
        "same-mod4-alignment-eligible-calls": alignment_calls,
        "pre-overlap_joint_call_lower_bound": joint_lower,
        "pre-overlap_joint_call_upper_bound": joint_upper,
        "length_only_word_row_bounds_across_unknown_destination_offsets": {
            "minimum": min(word_rows), "maximum": max(word_rows),
        },
        "caller_main_columns": 89,
        "word_main_columns": 37,
        "nonoverlap_observed": None,
        "exact_admitted_calls": None,
        "exact_candidate_word_rows": None,
        "exact_candidate_committed_cells": None,
        "unavailable_reason": (
            "retained-prefix-histograms-do-not-join-length-alignment-and-overlap"
        ),
        "full_72_segment_extrapolation": None,
        "production_active": False,
        "proof_correctness": None,
        "fresh_verification": None,
        "measured_end_to_end_wall_ns": None,
    }


def _build_loaded(
    allocator: dict[str, Any], allocator_identity: dict[str, Any],
    memcpy: dict[str, Any], memcpy_identity: dict[str, Any],
    journal_path: Path, keccak_receipt_path: Path, keccak_executable_path: Path,
    source_authorities: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    _require(allocator["schema"] == allocator_evidence.SCHEMA
             and memcpy["schema"] == memcpy_evidence.EVIDENCE_SCHEMA,
             "post-allocator source evidence schema differs")
    allocator = copy.deepcopy(allocator)
    allocator["_evidence_identity"] = allocator_identity
    corpus, _ = _journal(journal_path, allocator, memcpy)
    del allocator["_evidence_identity"]
    keccak = _keccak_projection(
        keccak_receipt_path, keccak_executable_path, corpus,
    )
    _require(
        memcpy["inputs"]["allocator_execution_evidence"] == allocator_identity
        and memcpy["claim_boundary"]["prefix_only"] is True
        and memcpy["claim_boundary"]["no_extrapolation"] is True
        and memcpy["claim_boundary"]["production_active"] is False
        and memcpy["claim_boundary"]["proof_correctness"] is None
        and memcpy["claim_boundary"]["fresh_proof_verification"] is None
        and memcpy["claim_boundary"]["measured_end_to_end_wall_ns"] is None,
        "post-allocator memcpy evidence scope differs",
    )
    return protocol.seal({
        "schema": SCHEMA,
        "status": STATUS,
        "inputs": {
            "allocator_execution_evidence": allocator_identity,
            "candidate_v3_journal": corpus["identity"],
            "memcpy_hotspot_evidence": memcpy_identity,
            "keccak_projection_receipt": _identity(
                keccak_receipt_path, "post-allocator Keccak projection receipt",
            ),
            "keccak_projection_executable": keccak["executable"],
        },
        "source_authorities": (
            copy.deepcopy(source_authorities)
            if source_authorities is not None else _source_authorities()
        ),
        "corpus": corpus,
        "alias_opportunities": _alias_opportunities(corpus),
        "poseidon_opportunity": _poseidon_opportunity(corpus),
        "keccak_opportunity": {
            "opportunity_id": "journal-bound-adaptive-keccak-profile",
            "scope": "complete-72-segment-journal-exact-cell-projection",
            "source_receipt": copy.deepcopy(keccak["receipt"]),
            "compact_baseline_cells": keccak["receipt"]["compact_baseline_cells"],
            "adaptive_cells": keccak["receipt"]["adaptive_cells"],
            "saved_cells": keccak["receipt"]["saved_cells"],
            "production_active": False,
            "proof_correctness": None,
            "fresh_verification": None,
            "measured_end_to_end_wall_ns": None,
        },
        "memcpy_opportunity": _memcpy_model(memcpy),
        "claims": {
            "all_geometry_scopes_explicit": True,
            "cross_candidate_combination": None,
            "independent_gain_multiplication_used": False,
            "full_block_air_complete": None,
            "full_block_proof_complete": None,
            "fresh_full_block_verification": None,
            "measured_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
    })


def build(
    allocator_path: Path, journal_path: Path, memcpy_path: Path,
    keccak_receipt_path: Path, keccak_executable_path: Path,
) -> dict[str, Any]:
    allocator_path, memcpy_path = allocator_path.absolute(), memcpy_path.absolute()
    allocator = allocator_evidence.load(allocator_path)
    memcpy = memcpy_evidence.load(memcpy_path)
    return _build_loaded(
        allocator, _identity(allocator_path, "allocator execution evidence"),
        memcpy, _identity(memcpy_path, "memcpy hotspot evidence"),
        journal_path.absolute(), keccak_receipt_path.absolute(),
        keccak_executable_path.absolute(),
    )


def create(
    allocator_path: Path, journal_path: Path, memcpy_path: Path,
    keccak_receipt_path: Path, keccak_executable_path: Path,
    output: Path, staging: Path,
) -> dict[str, Any]:
    output, staging = output.absolute(), staging.absolute()
    store.require_directory(output.parent, "post-allocator ledger parent")
    store.require_directory(staging, "post-allocator ledger staging", create=True)
    sources = _capture_source_authorities(output, staging)
    allocator_path, memcpy_path = allocator_path.absolute(), memcpy_path.absolute()
    allocator = allocator_evidence.load(allocator_path)
    memcpy = memcpy_evidence.load(memcpy_path)
    value = _build_loaded(
        allocator, _identity(allocator_path, "allocator execution evidence"),
        memcpy, _identity(memcpy_path, "memcpy hotspot evidence"),
        journal_path.absolute(), keccak_receipt_path.absolute(),
        keccak_executable_path.absolute(), sources,
    )
    store.publish_new_or_identical(
        output, protocol.canonical_bytes(value), staging_directory=staging,
    )
    return value


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "inputs", "source_authorities", "corpus",
        "alias_opportunities", "poseidon_opportunity", "keccak_opportunity",
        "memcpy_opportunity", "claims", "content_sha256",
    }, "post-allocator opportunity ledger keys differ")
    _require(value["schema"] == SCHEMA and value["status"] == STATUS
             and value["content_sha256"] == protocol.content_sha256(value),
             "post-allocator opportunity ledger authority differs")
    inputs = value["inputs"]
    _require(type(inputs) is dict and set(inputs) == {
        "allocator_execution_evidence", "candidate_v3_journal",
        "memcpy_hotspot_evidence", "keccak_projection_receipt",
        "keccak_projection_executable",
    }, "post-allocator opportunity ledger inputs differ")
    for name, identity in inputs.items():
        _validate_identity(identity, f"post-allocator ledger {name}")
    sources = value["source_authorities"]
    _require(type(sources) is list and len(sources) == len(SOURCE_PATHS),
             "post-allocator source authorities differ")
    source_paths = []
    for index, ((role, _), authority) in enumerate(zip(SOURCE_PATHS, sources)):
        _require(type(authority) is dict and set(authority) == {"role", "identity"}
                 and authority["role"] == role,
                 f"post-allocator source authority {index} differs")
        _validate_identity(authority["identity"], f"{role} captured source")
        source_paths.append(authority)
    allocator_path = Path(inputs["allocator_execution_evidence"]["path"])
    memcpy_path = Path(inputs["memcpy_hotspot_evidence"]["path"])
    expected = _build_loaded(
        allocator_evidence.load(allocator_path), inputs["allocator_execution_evidence"],
        memcpy_evidence.load(memcpy_path), inputs["memcpy_hotspot_evidence"],
        Path(inputs["candidate_v3_journal"]["path"]),
        Path(inputs["keccak_projection_receipt"]["path"]),
        Path(inputs["keccak_projection_executable"]["path"]),
        source_paths,
    )
    _require(protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
             "post-allocator opportunity ledger replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "post-allocator opportunity ledger",
        maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "post-allocator opportunity ledger is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    for name in (
        "allocator-evidence", "candidate-journal", "memcpy-evidence",
        "keccak-receipt", "keccak-executable", "output", "staging-directory",
    ):
        create.add_argument(f"--{name}", type=Path, required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--ledger", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "replay":
            load(arguments.ledger)
            return 0
        create(
            arguments.allocator_evidence, arguments.candidate_journal,
            arguments.memcpy_evidence, arguments.keccak_receipt,
            arguments.keccak_executable, arguments.output,
            arguments.staging_directory,
        )
        return 0
    except (
        PostAllocatorOpportunityLedgerError,
        allocator_evidence.AllocatorExecutionEvidenceError,
        memcpy_evidence.MemcpyHotspotEvidenceError,
        protocol.ProofProtocolError,
        segmented.ContractError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
