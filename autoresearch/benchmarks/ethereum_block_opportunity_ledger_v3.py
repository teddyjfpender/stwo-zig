"""Supersede the retained-corpus ledger with allocator/retention diagnostics.

Every source evidence object is reopened by its strict adapter.  Execution
cycle reductions, a standalone provider-retention speedup, and a memcpy prefix
distribution remain distinct scopes; none is promoted to an AIR, proof, or
end-to-end claim.
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

import ethereum_block_allocator_execution_evidence as allocator_evidence  # noqa: E402
import ethereum_block_memcpy_hotspot_evidence as memcpy_evidence  # noqa: E402
import ethereum_block_opportunity_ledger_v2 as ledger_v2  # noqa: E402
import ethereum_block_provider_retention_evidence as retention_evidence  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SCHEMA = "stwo.ethereum.retained-corpus-opportunity-ledger.v3"
STATUS = "diagnostic-opportunities-with-execution-and-stage-evidence-nonpromotable"


class OpportunityLedgerV3Error(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise OpportunityLedgerV3Error(message)


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


def _build_loaded(
    base: dict[str, Any], base_identity: dict[str, Any],
    allocator: dict[str, Any], allocator_identity: dict[str, Any],
    retention: dict[str, Any], retention_identity: dict[str, Any],
    memcpy: dict[str, Any], memcpy_identity: dict[str, Any],
) -> dict[str, Any]:
    _require(base["schema"] == ledger_v2.SCHEMA,
             "base opportunity ledger schema differs")
    base_v1 = base["base_ledger_v1"]
    corpus = base_v1["corpus"]
    journal = base_v1["inputs"]["journal"]
    allocator_inputs = allocator["inputs"]
    baseline = allocator["executions"]["baseline"]
    candidate = allocator["executions"]["candidate"]
    _require(
        allocator["schema"] == allocator_evidence.SCHEMA
        and allocator_inputs["baseline_journal"] == journal
        and baseline["segment_count"] == corpus["segment_count"]
        and baseline["total_cycles"] == corpus["total_cycles"]
        and baseline["total_core_trace_rows"] == corpus["total_core_trace_rows"]
        and baseline["total_external_trace_rows"]
        == corpus["total_external_trace_rows"]
        and baseline["output_bytes"] == corpus["output_bytes"]
        and baseline["output_sha256"] == corpus["output_sha256"]
        and allocator["equivalence"]["same_input_bytes_and_sha256"] is True
        and allocator["equivalence"]["same_output_bytes_and_sha256"] is True
        and allocator["equivalence"]["program_and_elf_equal"] is False
        and allocator["promotion"]["proof_completion"] is None
        and allocator["promotion"]["measured_end_to_end_wall_ns"] is None,
        "allocator execution/base corpus join differs",
    )
    _require(
        retention["schema"] == retention_evidence.EVIDENCE_SCHEMA
        and retention["ranking"]["scope"]
        == "standalone-provider-coefficient-retention-stage-only"
        and retention["ranking"]["fresh_verification"] is True
        and retention["ranking"]["estimated_end_to_end_wall_ns"] is None
        and retention["ranking"]["production_promotion_eligible"] is False,
        "provider retention evidence scope differs",
    )
    memcpy_inputs = memcpy["inputs"]
    sample = memcpy["sample"]
    _require(
        memcpy["schema"] == memcpy_evidence.EVIDENCE_SCHEMA
        and memcpy_inputs["allocator_execution_evidence"] == allocator_identity
        and memcpy_inputs["candidate_elf"] == allocator_inputs["candidate_elf"]
        and memcpy_inputs["input"] == allocator_inputs["common_input"]
        and sample["full_journal_segment_count"] == candidate["segment_count"]
        and sample["full_journal_total_cycles"] == candidate["total_cycles"]
        and sample["full_journal_total_core_trace_rows"]
        == candidate["total_core_trace_rows"]
        and sample["full_journal_total_external_trace_rows"]
        == candidate["total_external_trace_rows"]
        and sample["full_journal_output_sha256"] == candidate["output_sha256"]
        and memcpy["claim_boundary"]["prefix_only"] is True
        and memcpy["claim_boundary"]["no_extrapolation"] is True
        and memcpy["claim_boundary"]["proof_correctness"] is None
        and memcpy["claim_boundary"]["measured_end_to_end_wall_ns"] is None,
        "memcpy/allocator execution join differs",
    )
    return protocol.seal({
        "schema": SCHEMA,
        "status": STATUS,
        "inputs": {
            "base_ledger_v2": base_identity,
            "allocator_execution_evidence": allocator_identity,
            "provider_retention_evidence": retention_identity,
            "memcpy_hotspot_evidence": memcpy_identity,
        },
        "base_ledger_v2": copy.deepcopy(base),
        "allocator_execution_candidate": {
            "source_evidence": allocator_identity,
            "source_content_sha256": allocator["content_sha256"],
            "baseline_program": allocator_inputs["baseline_elf"],
            "candidate_program": allocator_inputs["candidate_elf"],
            "candidate_journal_schema": candidate["journal_schema"],
            "output_equivalent_execution_observed": True,
            "program_and_elf_changed": True,
            "cycle_reduction": copy.deepcopy(allocator["reductions"]["cycles"]),
            "core_trace_row_reduction": copy.deepcopy(
                allocator["reductions"]["core_trace_rows"]
            ),
            "segment_reduction": copy.deepcopy(
                allocator["reductions"]["segments"]
            ),
            "reported_wall_reduction": copy.deepcopy(
                allocator["reductions"]["reported_wall_ns"]
            ),
            "wall_reduction_fully_file_backed": False,
            "full_state_equivalence_claim": None,
            "proof_correctness": None,
            "fresh_proof_verification": None,
            "measured_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
        "provider_retention_stage": {
            "source_evidence": retention_identity,
            "source_content_sha256": retention["content_sha256"],
            "measured_arms": copy.deepcopy(retention["measured_arms"]),
            "measured_retention_speedup_milli": retention[
                "measured_retention_speedup_milli"
            ],
            "measurement_scope": retention["ranking"]["scope"],
            "fresh_standalone_provider_verification": True,
            "full_block_proof_correctness": None,
            "measured_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
        "memcpy_candidate_prefix": {
            "source_evidence": memcpy_identity,
            "source_content_sha256": memcpy["content_sha256"],
            "candidate_journal_schema": candidate["journal_schema"],
            "sample": copy.deepcopy(sample),
            "process_measurement": copy.deepcopy(memcpy["process_measurement"]),
            "scope": "candidate-first-64-segment-retirement-prefix-only",
            "no_extrapolation": True,
            "air_component_complete": None,
            "proof_correctness": None,
            "fresh_proof_verification": None,
            "measured_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
        "ranked_next_experiments": [
            {
                "rank": 1,
                "experiment_id": "allocator-exact-layout-proof-diagnostic-v1",
                "basis": "journal-backed-cycle-reduction",
                "maximum_wall_seconds": 60,
                "full_block_proof_forbidden": True,
                "launch_ready": False,
                "unavailable_reason": "requires-production-air-and-proof-admission",
            },
            {
                "rank": 2,
                "experiment_id": "memcpy-length-alignment-component-microproof-v1",
                "basis": "replayed-prefix-histogram",
                "maximum_wall_seconds": 60,
                "full_block_proof_forbidden": True,
                "launch_ready": False,
                "unavailable_reason": "requires-typed-air-candidate-receipt",
            },
            {
                "rank": 3,
                "experiment_id": "provider-retention-real-shell-microproof-v1",
                "basis": "standalone-stage-retention-speedup",
                "maximum_wall_seconds": 60,
                "full_block_proof_forbidden": True,
                "launch_ready": False,
                "unavailable_reason": "requires-full-core-integration",
            },
        ],
        "claims": {
            "base_ledger_claims_preserved": True,
            "execution_output_equivalence_only": True,
            "stage_local_provider_measurement_only": True,
            "memcpy_prefix_observation_only": True,
            "independent_gain_multiplication_used": False,
            "sample_to_full_corpus_extrapolation": None,
            "cross_family_speedup": None,
            "full_block_air_complete": None,
            "full_block_proof_complete": None,
            "fresh_full_block_verification": None,
            "measured_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
    })


def build(
    base_path: Path, allocator_path: Path, retention_path: Path,
    memcpy_path: Path,
) -> dict[str, Any]:
    paths = [path.absolute() for path in (
        base_path, allocator_path, retention_path, memcpy_path,
    )]
    base = ledger_v2.load(paths[0])
    allocator = allocator_evidence.load(paths[1])
    retention = retention_evidence.load(paths[2])
    memcpy = memcpy_evidence.load(paths[3])
    return _build_loaded(
        base, _identity(paths[0], "base ledger v2"),
        allocator, _identity(paths[1], "allocator execution evidence"),
        retention, _identity(paths[2], "provider retention evidence"),
        memcpy, _identity(paths[3], "memcpy hotspot evidence"),
    )


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "inputs", "base_ledger_v2",
        "allocator_execution_candidate", "provider_retention_stage",
        "memcpy_candidate_prefix", "ranked_next_experiments", "claims",
        "content_sha256",
    }, "opportunity ledger v3 keys differ")
    _require(value["schema"] == SCHEMA and value["status"] == STATUS
             and value["content_sha256"] == protocol.content_sha256(value),
             "opportunity ledger v3 authority differs")
    inputs = value["inputs"]
    _require(type(inputs) is dict and set(inputs) == {
        "base_ledger_v2", "allocator_execution_evidence",
        "provider_retention_evidence", "memcpy_hotspot_evidence",
    }, "opportunity ledger v3 inputs differ")
    for name, identity in inputs.items():
        _validate_identity(identity, f"opportunity ledger v3 {name}")
    expected = build(
        Path(inputs["base_ledger_v2"]["path"]),
        Path(inputs["allocator_execution_evidence"]["path"]),
        Path(inputs["provider_retention_evidence"]["path"]),
        Path(inputs["memcpy_hotspot_evidence"]["path"]),
    )
    _require(protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
             "opportunity ledger v3 replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "opportunity ledger v3", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "opportunity ledger v3 is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    for name in (
        "base-ledger-v2", "allocator-evidence", "retention-evidence",
        "memcpy-evidence", "output", "staging-directory",
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
        output, staging = arguments.output.absolute(), arguments.staging_directory.absolute()
        store.require_directory(output.parent, "opportunity ledger v3 parent")
        store.require_directory(staging, "opportunity ledger v3 staging", create=True)
        value = build(
            arguments.base_ledger_v2, arguments.allocator_evidence,
            arguments.retention_evidence, arguments.memcpy_evidence,
        )
        store.publish_new_or_identical(
            output, protocol.canonical_bytes(value), staging_directory=staging,
        )
        return 0
    except (
        OpportunityLedgerV3Error, ledger_v2.OpportunityLedgerV2Error,
        allocator_evidence.AllocatorExecutionEvidenceError,
        retention_evidence.ProviderRetentionEvidenceError,
        memcpy_evidence.MemcpyHotspotEvidenceError,
        protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
