"""Join the latest retained execution diagnostics without an E2E claim.

V5 preserves the V4 allocator/V6/D5 ledger, adds the measured word-sponge and
successful-path ECRECOVER executions, and binds the bulk-call and PC/symbol
censuses separately.  It never synthesizes a post-bulk journal or multiplies
independent gains, and keeps AIR/proof/fresh/E2E/production unavailable.
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

import ethereum_block_bulk_memcpy_admission_evidence as word_bulk  # noqa: E402
import ethereum_block_ecrecover_bulk_memcpy_evidence as recover_bulk  # noqa: E402
import ethereum_block_ecrecover_execution_evidence as recover_execution  # noqa: E402
import ethereum_block_ecrecover_pc_census_evidence as recover_pc  # noqa: E402
import ethereum_block_keccak_words_execution_evidence as word_execution  # noqa: E402
import ethereum_block_opportunity_ledger_v4 as ledger_v4  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SCHEMA = "stwo.ethereum.retained-corpus-opportunity-ledger.v5"
STATUS = "latest-execution-and-projection-diagnostics-nonpromotable"


class OpportunityLedgerV5Error(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise OpportunityLedgerV5Error(message)


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
    prior: dict[str, Any], prior_identity: dict[str, Any],
    words: dict[str, Any], words_identity: dict[str, Any],
    words_bulk: dict[str, Any], words_bulk_identity: dict[str, Any],
    recovery: dict[str, Any], recovery_identity: dict[str, Any],
    recovery_bulk_value: dict[str, Any], recovery_bulk_identity: dict[str, Any],
    pc: dict[str, Any], pc_identity: dict[str, Any],
) -> dict[str, Any]:
    _require(
        prior["schema"] == ledger_v4.SCHEMA
        and words["schema"] == word_execution.SCHEMA
        and words_bulk["schema"] == word_bulk.SCHEMA
        and recovery["schema"] == recover_execution.SCHEMA
        and recovery_bulk_value["schema"] == recover_bulk.SCHEMA
        and pc["schema"] == recover_pc.SCHEMA,
        "opportunity ledger v5 source schema differs",
    )
    v6_identity = prior["inputs"]["current_memcpy_v6_execution_evidence"]
    _require(
        words["inputs"]["memcpy_v6_execution_evidence"] == v6_identity
        and words["executions"]["memcpy_v6_comparator"]
        == prior["current_memcpy_v6_execution"]["candidate"]
        and words["claim_boundary"]["production_active"] is False
        and words["claim_boundary"]["proof_correctness"] is None
        and words["claim_boundary"]["fresh_proof_verification"] is None
        and words["claim_boundary"][
            "measured_proving_end_to_end_wall_ns"
        ] is None
        and words_bulk["inputs"]["keccak_words_execution_evidence"]
        == words_identity
        and words_bulk["inputs"]["candidate_journal"]
        == words["inputs"]["candidate_journal"]
        and words_bulk["claim_boundary"]["predicted_execution_only"] is True
        and words_bulk["claim_boundary"]["candidate_execution_measured"] is False,
        "opportunity ledger v5 word-sponge join differs",
    )
    _require(
        recovery["inputs"]["keccak_words_execution_evidence"] == words_identity
        and recovery["executions"]["keccak_words_comparator"]
        == words["executions"]["keccak_words_candidate"]
        and recovery["semantics"][
            "general_invalid_input_semantics_satisfied"
        ] is False
        and recovery["semantics"]["full_program_semantic_equivalence"] is None
        and recovery["claim_boundary"]["production_active"] is False
        and recovery["claim_boundary"]["proof_correctness"] is None
        and recovery_bulk_value["inputs"]["ecrecover_execution_evidence"]
        == recovery_identity
        and recovery_bulk_value["inputs"]["candidate_journal"]
        == recovery["inputs"]["candidate_journal"]
        and recovery_bulk_value["execution_projection"][
            "synthesized_post_bulk_journal"
        ] is None
        and recovery_bulk_value["claim_boundary"][
            "general_invalid_ecrecover_semantics_satisfied"
        ] is False,
        "opportunity ledger v5 ECRECOVER/bulk join differs",
    )
    _require(
        pc["inputs"]["ecrecover_execution_evidence"] == recovery_identity
        and pc["inputs"]["candidate_elf"] == recovery["inputs"]["candidate_elf"]
        and pc["inputs"]["candidate_journal"]
        == recovery["inputs"]["candidate_journal"]
        and pc["inputs"]["input"] == recovery["inputs"]["common_input"]
        and pc["sample"]["sample_is_complete_execution"] is True
        and pc["sample"]["no_extrapolation"] is True
        and pc["claim_boundary"]["production_active"] is False
        and pc["claim_boundary"]["proof_correctness"] is None
        and pc["claim_boundary"]["performance_claim_eligible"] is False
        and pc["canonical_totals"]["retired_instructions"]
        == recovery["executions"]["ecrecover_success_candidate"][
            "total_core_trace_rows"
        ],
        "opportunity ledger v5 PC join differs",
    )
    return protocol.seal({
        "schema": SCHEMA,
        "status": STATUS,
        "inputs": {
            "prior_ledger_v4": prior_identity,
            "word_sponge_execution_evidence": words_identity,
            "word_sponge_bulk_projection_evidence": words_bulk_identity,
            "ecrecover_execution_evidence": recovery_identity,
            "ecrecover_bulk_projection_evidence": recovery_bulk_identity,
            "ecrecover_pc_census_evidence": pc_identity,
        },
        "retained_prior_scopes": {
            "source_ledger": prior_identity,
            "allocator_baseline_geometry": copy.deepcopy(
                prior["allocator_baseline_geometry"]
            ),
            "memcpy_v6_execution": copy.deepcopy(
                prior["current_memcpy_v6_execution"]
            ),
            "poseidon_d5_stage_diagnostic": copy.deepcopy(
                prior["poseidon_d5_stage_diagnostic"]
            ),
        },
        "word_sponge_execution": {
            "source_evidence": words_identity,
            "candidate": copy.deepcopy(
                words["executions"]["keccak_words_candidate"]
            ),
            "equivalence": copy.deepcopy(words["equivalence"]),
            "reductions": copy.deepcopy(words["reductions"]),
            "measurements": copy.deepcopy(words["measurements"]),
            "candidate_air_complete": None,
            "proof_correctness": None,
            "fresh_proof_verification": None,
            "measured_proving_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
        "word_sponge_bulk_projection": {
            "source_evidence": words_bulk_identity,
            "sample": copy.deepcopy(words_bulk["sample"]),
            "execution_projection": copy.deepcopy(
                words_bulk["execution_projection"]
            ),
            "measured_post_projection_execution": False,
            "synthesized_post_projection_journal": None,
            "proof_correctness": None,
            "measured_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
        "ecrecover_success_execution": {
            "source_evidence": recovery_identity,
            "candidate": copy.deepcopy(
                recovery["executions"]["ecrecover_success_candidate"]
            ),
            "observed_equivalence": copy.deepcopy(
                recovery["observed_equivalence"]
            ),
            "reductions": copy.deepcopy(recovery["reductions"]),
            "measurements": copy.deepcopy(recovery["measurements"]),
            "semantics": copy.deepcopy(recovery["semantics"]),
            "candidate_air_complete": None,
            "proof_correctness": None,
            "fresh_proof_verification": None,
            "measured_proving_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
        "ecrecover_bulk_projection": {
            "source_evidence": recovery_bulk_identity,
            "sample": copy.deepcopy(recovery_bulk_value["sample"]),
            "execution_projection": copy.deepcopy(
                recovery_bulk_value["execution_projection"]
            ),
            "measured_post_projection_execution": False,
            "synthesized_post_projection_journal": None,
            "proof_correctness": None,
            "measured_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
        "ecrecover_pc_census": {
            "source_evidence": pc_identity,
            "sample": copy.deepcopy(pc["sample"]),
            "canonical_totals": copy.deepcopy(pc["canonical_totals"]),
            "symbol_projection": copy.deepcopy(pc["symbol_projection"]),
            "no_extrapolation": True,
            "proof_correctness": None,
            "measured_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
        "scope_separation": {
            "current_execution_diagnostic": "ecrecover-success-path-only",
            "general_invalid_ecrecover_semantics_satisfied": False,
            "word_bulk_projection_applied_to_measured_execution": False,
            "ecrecover_bulk_projection_applied_to_measured_execution": False,
            "synthesized_post_bulk_journal": None,
            "cross_candidate_combination": None,
            "independent_gain_multiplication_used": False,
        },
        "claims": {
            "full_program_semantic_equivalence": None,
            "full_block_air_complete": None,
            "full_block_proof_complete": None,
            "fresh_full_block_verification": None,
            "measured_proving_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
    })


def build(
    prior_path: Path, words_path: Path, words_bulk_path: Path,
    recovery_path: Path, recovery_bulk_path: Path, pc_path: Path,
) -> dict[str, Any]:
    paths = tuple(path.absolute() for path in (
        prior_path, words_path, words_bulk_path, recovery_path,
        recovery_bulk_path, pc_path,
    ))
    return _build_loaded(
        ledger_v4.load(paths[0]), _identity(paths[0], "prior ledger v4"),
        word_execution.load(paths[1]), _identity(paths[1], "word execution"),
        word_bulk.load(paths[2]), _identity(paths[2], "word bulk projection"),
        recover_execution.load(paths[3]),
        _identity(paths[3], "ECRECOVER execution"),
        recover_bulk.load(paths[4]), _identity(paths[4], "ECRECOVER bulk"),
        recover_pc.load(paths[5]), _identity(paths[5], "ECRECOVER PC census"),
    )


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "inputs", "retained_prior_scopes",
        "word_sponge_execution", "word_sponge_bulk_projection",
        "ecrecover_success_execution", "ecrecover_bulk_projection",
        "ecrecover_pc_census", "scope_separation", "claims",
        "content_sha256",
    }, "opportunity ledger v5 keys differ")
    _require(value["schema"] == SCHEMA and value["status"] == STATUS
             and value["content_sha256"] == protocol.content_sha256(value),
             "opportunity ledger v5 authority differs")
    names = (
        "prior_ledger_v4", "word_sponge_execution_evidence",
        "word_sponge_bulk_projection_evidence", "ecrecover_execution_evidence",
        "ecrecover_bulk_projection_evidence", "ecrecover_pc_census_evidence",
    )
    inputs = value["inputs"]
    _require(type(inputs) is dict and set(inputs) == set(names),
             "opportunity ledger v5 inputs differ")
    for name in names:
        _validate_identity(inputs[name], f"opportunity ledger v5 {name}")
    expected = build(*(Path(inputs[name]["path"]) for name in names))
    _require(protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
             "opportunity ledger v5 replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "opportunity ledger v5", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "opportunity ledger v5 is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser("create")
    for name in (
        "prior-ledger", "word-execution", "word-bulk", "ecrecover-execution",
        "ecrecover-bulk", "ecrecover-pc", "output", "staging-directory",
    ):
        create_parser.add_argument(f"--{name}", type=Path, required=True)
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
        store.require_directory(output.parent, "opportunity ledger v5 parent")
        store.require_directory(staging, "opportunity ledger v5 staging", create=True)
        value = build(
            arguments.prior_ledger, arguments.word_execution,
            arguments.word_bulk, arguments.ecrecover_execution,
            arguments.ecrecover_bulk, arguments.ecrecover_pc,
        )
        store.publish_new_or_identical(
            output, protocol.canonical_bytes(value), staging_directory=staging,
        )
        return 0
    except (
        OpportunityLedgerV5Error,
        ledger_v4.OpportunityLedgerV4Error,
        word_execution.KeccakWordsExecutionEvidenceError,
        word_bulk.BulkMemcpyAdmissionEvidenceError,
        recover_execution.EcrecoverExecutionEvidenceError,
        recover_bulk.EcrecoverBulkMemcpyEvidenceError,
        recover_pc.EcrecoverPcCensusEvidenceError,
        protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
