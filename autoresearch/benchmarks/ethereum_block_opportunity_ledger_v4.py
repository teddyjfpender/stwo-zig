"""Publish the V6-current retained-corpus opportunity ledger.

The changed-program V6 execution result is the only current memcpy candidate.
The V5 execution and its 64-segment PC observation remain joined as predecessor
diagnostics and are never transferred to V6.  The retained degree5 Poseidon
tool stream is also stage-local: it has no executable/proof custody and cannot
be used as a block-proof or E2E result.
"""

from __future__ import annotations

import argparse
import copy
from pathlib import Path
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_memcpy_execution_evidence as memcpy_execution  # noqa: E402
import ethereum_block_pc_hotspot_retained_evidence as pc_evidence  # noqa: E402
import ethereum_block_poseidon_d5_telemetry_evidence as d5_evidence  # noqa: E402
import ethereum_block_post_allocator_opportunity_ledger as post_ledger  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SCHEMA = "stwo.ethereum.retained-corpus-opportunity-ledger.v4"
STATUS = "memcpy-v6-current-with-predecessor-and-stage-diagnostics-nonpromotable"


class OpportunityLedgerV4Error(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise OpportunityLedgerV4Error(message)


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


def _execution_join(
    value: dict[str, Any], identity: dict[str, Any],
    post: dict[str, Any], post_identity: dict[str, Any], where: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _require(value["schema"] == memcpy_execution.SCHEMA,
             f"{where} schema differs")
    baseline = value["executions"]["allocator_baseline"]
    candidate = value["executions"]["memcpy_candidate"]
    equivalence = value["equivalence"]
    boundary = value["claim_boundary"]
    _require(
        value["inputs"]["post_allocator_ledger"] == post_identity
        and value["inputs"]["baseline_journal"]
        == post["inputs"]["candidate_v3_journal"]
        and baseline["journal"] == post["corpus"]["identity"]
        and baseline["segment_count"] == post["corpus"]["segment_count"]
        and baseline["total_cycles"] == post["corpus"]["total_cycles"]
        and baseline["total_core_trace_rows"]
        == post["corpus"]["total_core_trace_rows"]
        and baseline["total_external_trace_rows"]
        == post["corpus"]["total_external_trace_rows"]
        and baseline["output_sha256"] == post["corpus"]["output_sha256"]
        and equivalence["same_input_bytes_and_sha256"] is True
        and equivalence["same_output_bytes_and_sha256"] is True
        and equivalence["same_external_family_rows"] is True
        and equivalence["same_external_trace_rows"] is True
        and equivalence["program_and_elf_equal"] is False
        and equivalence["full_state_equivalence_claim"] is None
        and boundary["production_active"] is False
        and boundary["candidate_air_complete"] is None
        and boundary["proof_correctness"] is None
        and boundary["fresh_proof_verification"] is None
        and boundary["measured_proving_end_to_end_wall_ns"] is None
        and boundary["production_promotion_eligible"] is False
        and value["measurements"]["wall_comparison_fully_file_backed"] is True,
        f"{where} baseline/equivalence boundary differs",
    )
    _require(
        type(candidate["segment_count"]) is int
        and type(candidate["total_cycles"]) is int
        and type(candidate["total_core_trace_rows"]) is int
        and type(candidate["total_external_trace_rows"]) is int
        and candidate["segment_count"] > 0
        and candidate["total_cycles"]
        == candidate["total_core_trace_rows"]
        + candidate["total_external_trace_rows"],
        f"{where} candidate totals differ",
    )
    _require(type(identity) is dict, f"{where} identity differs")
    return baseline, candidate


def _build_loaded(
    post: dict[str, Any], post_identity: dict[str, Any],
    current: dict[str, Any], current_identity: dict[str, Any],
    predecessor: dict[str, Any], predecessor_identity: dict[str, Any],
    pc: dict[str, Any], pc_identity: dict[str, Any],
    d5: dict[str, Any], d5_identity: dict[str, Any],
) -> dict[str, Any]:
    _require(post["schema"] == post_ledger.SCHEMA,
             "opportunity ledger v4 post schema differs")
    current_baseline, current_candidate = _execution_join(
        current, current_identity, post, post_identity, "current memcpy V6",
    )
    predecessor_baseline, predecessor_candidate = _execution_join(
        predecessor, predecessor_identity, post, post_identity,
        "predecessor memcpy V5",
    )
    _require(
        current_baseline == predecessor_baseline
        and current["inputs"]["common_input"]
        == predecessor["inputs"]["common_input"]
        and current_candidate["output_sha256"]
        == predecessor_candidate["output_sha256"]
        and current_candidate["total_external_trace_rows"]
        == predecessor_candidate["total_external_trace_rows"]
        and current["inputs"]["candidate_elf"]
        != predecessor["inputs"]["candidate_elf"]
        and current["inputs"]["candidate_journal"]
        != predecessor["inputs"]["candidate_journal"]
        and current_candidate["total_cycles"]
        < predecessor_candidate["total_cycles"]
        and current_candidate["segment_count"]
        <= predecessor_candidate["segment_count"],
        "memcpy V6/V5 supersession authority differs",
    )
    _require(
        pc["schema"] == pc_evidence.SCHEMA
        and pc["inputs"]["memcpy_execution_evidence"]
        == predecessor_identity
        and pc["inputs"]["candidate_elf"]
        == predecessor["inputs"]["candidate_elf"]
        and pc["inputs"]["candidate_journal"]
        == predecessor["inputs"]["candidate_journal"]
        and pc["inputs"]["input"] == predecessor["inputs"]["common_input"]
        and pc["inputs"]["candidate_elf"]
        != current["inputs"]["candidate_elf"]
        and pc["sample"]["segment_count"]
        <= predecessor_candidate["segment_count"]
        and pc["sample"]["retired_instructions"]
        <= predecessor_candidate["total_core_trace_rows"]
        and pc["claim_boundary"]["prefix_only"] is True
        and pc["claim_boundary"]["no_extrapolation"] is True
        and pc["claim_boundary"]["production_active"] is False
        and pc["claim_boundary"]["proof_correctness"] is None
        and pc["process_measurement"]["performance_claim_eligible"] is False,
        "predecessor memcpy V5 PC join differs",
    )
    d5_boundary = d5["claim_boundary"]
    _require(
        d5["schema"] == d5_evidence.SCHEMA
        and d5["source_records"]["ab"]["production"] is False
        and d5["stage_ranking"]["best_measured_arm"] in {
            "legacy_never", "degree5_never", "legacy_always", "degree5_always",
        }
        and d5["stage_ranking"][
            "degree5_never_faster_than_legacy_never"
        ] is True
        and type(d5["stage_ranking"][
            "degree5_retained_regresses_vs_legacy_retained"
        ]) is bool
        and d5_boundary["production_active"] is False
        and d5_boundary["executable_custody"] is None
        and d5_boundary["proof_artifacts_retained"] is False
        and d5_boundary["proof_correctness"] is None
        and d5_boundary["fresh_proof_verification"] is None
        and d5_boundary["measured_end_to_end_wall_ns"] is None
        and d5_boundary["performance_claim_eligible"] is False
        and d5_boundary["production_promotion_eligible"] is False,
        "degree5 stage diagnostic boundary differs",
    )
    return protocol.seal({
        "schema": SCHEMA,
        "status": STATUS,
        "inputs": {
            "post_allocator_ledger": post_identity,
            "current_memcpy_v6_execution_evidence": current_identity,
            "predecessor_memcpy_v5_execution_evidence": predecessor_identity,
            "predecessor_memcpy_v5_pc_evidence": pc_identity,
            "poseidon_d5_telemetry_evidence": d5_identity,
        },
        "allocator_baseline_geometry": {
            "source_evidence": post_identity,
            "program_elf_sha256": post["corpus"]["header"]["elf_sha256"],
            "segment_count": post["corpus"]["segment_count"],
            "alias_opportunities": copy.deepcopy(post["alias_opportunities"]),
            "poseidon_opportunity": copy.deepcopy(post["poseidon_opportunity"]),
            "keccak_opportunity": copy.deepcopy(post["keccak_opportunity"]),
            "memcpy_marginal_opportunity": copy.deepcopy(
                post["memcpy_opportunity"]
            ),
            "applies_to_current_memcpy_v6_program": False,
        },
        "current_memcpy_v6_execution": {
            "source_evidence": current_identity,
            "baseline": copy.deepcopy(current_baseline),
            "candidate": copy.deepcopy(current_candidate),
            "equivalence": copy.deepcopy(current["equivalence"]),
            "reductions": copy.deepcopy(current["reductions"]),
            "measurements": copy.deepcopy(current["measurements"]),
            "current_candidate": True,
            "candidate_air_complete": None,
            "proof_correctness": None,
            "fresh_proof_verification": None,
            "measured_proving_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
        "predecessor_memcpy_v5": {
            "execution_source_evidence": predecessor_identity,
            "candidate": copy.deepcopy(predecessor_candidate),
            "reductions": copy.deepcopy(predecessor["reductions"]),
            "superseded_by_current": True,
            "pc_prefix": {
                "source_evidence": pc_identity,
                "sample": copy.deepcopy(pc["sample"]),
                "canonical_totals": copy.deepcopy(pc["canonical_totals"]),
                "candidate_pc_range_projection": copy.deepcopy(
                    pc["candidate_pc_range_projection"]
                ),
                "process_measurement": copy.deepcopy(
                    pc["process_measurement"]
                ),
                "prefix_only": True,
                "no_extrapolation": True,
                "applies_to_current_memcpy_v6": False,
            },
            "proof_correctness": None,
            "fresh_proof_verification": None,
            "measured_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
        "poseidon_d5_stage_diagnostic": {
            "source_evidence": d5_identity,
            "workload": copy.deepcopy(d5["source_records"]["ab"]),
            "prepared_telemetry": copy.deepcopy(
                d5["source_records"]["prepared_telemetry"]
            ),
            "stage_ranking": copy.deepcopy(d5["stage_ranking"]),
            "process_measurement": copy.deepcopy(d5["process_measurement"]),
            "scope": "standalone-log16-tool-stream-stage-only",
            "applies_to_current_memcpy_v6_block_proof": False,
            "executable_custody": None,
            "proof_correctness": None,
            "fresh_proof_verification": None,
            "measured_end_to_end_wall_ns": None,
            "performance_claim_eligible": False,
            "production_promotion_eligible": False,
        },
        "scope_separation": {
            "allocator_geometry_reused_for_current_memcpy_v6": False,
            "current_memcpy_v6_full_journal_geometry_recomputed": False,
            "current_memcpy_v6_geometry_unavailable_reason": (
                "changed-program-requires-own-journal-bound-profile-projections"
            ),
            "predecessor_pc_prefix_transferred_to_current": False,
            "degree5_stage_timing_transferred_to_block_proof": False,
            "cross_candidate_combination": None,
            "independent_gain_multiplication_used": False,
        },
        "claims": {
            "current_execution_output_and_external_equivalence_only": True,
            "full_state_equivalence": None,
            "full_block_air_complete": None,
            "full_block_proof_complete": None,
            "fresh_full_block_verification": None,
            "measured_proving_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
    })


def build(
    post_path: Path, current_path: Path, predecessor_path: Path,
    pc_path: Path, d5_path: Path,
) -> dict[str, Any]:
    paths = tuple(path.absolute() for path in (
        post_path, current_path, predecessor_path, pc_path, d5_path,
    ))
    return _build_loaded(
        post_ledger.load(paths[0]), _identity(paths[0], "post-allocator ledger"),
        memcpy_execution.load(paths[1]),
        _identity(paths[1], "current memcpy V6 execution evidence"),
        memcpy_execution.load(paths[2]),
        _identity(paths[2], "predecessor memcpy V5 execution evidence"),
        pc_evidence.load(paths[3]),
        _identity(paths[3], "predecessor memcpy V5 PC evidence"),
        d5_evidence.load(paths[4]),
        _identity(paths[4], "degree5 telemetry evidence"),
    )


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "inputs", "allocator_baseline_geometry",
        "current_memcpy_v6_execution", "predecessor_memcpy_v5",
        "poseidon_d5_stage_diagnostic", "scope_separation", "claims",
        "content_sha256",
    }, "opportunity ledger v4 keys differ")
    _require(value["schema"] == SCHEMA and value["status"] == STATUS
             and value["content_sha256"] == protocol.content_sha256(value),
             "opportunity ledger v4 authority differs")
    inputs = value["inputs"]
    input_names = (
        "post_allocator_ledger", "current_memcpy_v6_execution_evidence",
        "predecessor_memcpy_v5_execution_evidence",
        "predecessor_memcpy_v5_pc_evidence",
        "poseidon_d5_telemetry_evidence",
    )
    _require(type(inputs) is dict and set(inputs) == set(input_names),
             "opportunity ledger v4 inputs differ")
    for name in input_names:
        _validate_identity(inputs[name], f"opportunity ledger v4 {name}")
    expected = build(*(Path(inputs[name]["path"]) for name in input_names))
    _require(protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
             "opportunity ledger v4 replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "opportunity ledger v4", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "opportunity ledger v4 is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    for name in (
        "post-ledger", "current-execution-evidence",
        "predecessor-execution-evidence", "predecessor-pc-evidence",
        "d5-telemetry-evidence", "output", "staging-directory",
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
        output = arguments.output.absolute()
        staging = arguments.staging_directory.absolute()
        store.require_directory(output.parent, "opportunity ledger v4 parent")
        store.require_directory(staging, "opportunity ledger v4 staging", create=True)
        value = build(
            arguments.post_ledger, arguments.current_execution_evidence,
            arguments.predecessor_execution_evidence,
            arguments.predecessor_pc_evidence, arguments.d5_telemetry_evidence,
        )
        store.publish_new_or_identical(
            output, protocol.canonical_bytes(value), staging_directory=staging,
        )
        return 0
    except (
        OpportunityLedgerV4Error,
        post_ledger.PostAllocatorOpportunityLedgerError,
        memcpy_execution.MemcpyExecutionEvidenceError,
        pc_evidence.RetainedPcHotspotEvidenceError,
        d5_evidence.PoseidonD5TelemetryEvidenceError,
        protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
