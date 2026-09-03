"""Matrix admission for compact Ethereum capture/replay diagnostics."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import ethereum_block_compact_replay_evidence as compact_evidence


EVIDENCE_KIND = compact_evidence.EVIDENCE_KIND
REFERENCE_FIXTURE_ID = "mainnet-24628607-representative-medium"
REFERENCE_BLOCK_NUMBER = 24_628_607
REFERENCE_SEGMENT_COUNT = 210
REFERENCE_SEGMENT_STEP_BUDGET = 4_194_304
REFERENCE_TOTAL_CYCLES = 880_760_229
REFERENCE_CORE_CYCLES = 880_727_328
REFERENCE_EXTERNAL_CALLS = 32_901


class ReplayAdmissionError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReplayAdmissionError(message)


def validate_stage(evidence: Any, fixture: dict[str, Any]) -> dict[str, Any]:
    """Replay one retained receipt and return a nonpromotable matrix stage."""
    _require(type(evidence) is dict and set(evidence) == {
        "kind", "receipt", "materialization_manifest",
        "execution_profile_receipt", "replay_executable", "projection",
    }, "compact replay evidence keys differ")
    _require(evidence["kind"] == EVIDENCE_KIND,
             "compact replay evidence kind differs")
    receipt = evidence["receipt"]
    _require(type(receipt) is dict and type(receipt.get("path")) is str,
             "compact replay receipt identity differs")
    receipt_path = Path(receipt["path"])
    _require(receipt_path.is_absolute(), "compact replay receipt path differs")
    expected = compact_evidence.validate(receipt_path)
    _require(evidence == expected, "compact replay evidence replay differs")
    _require(fixture["fixture_id"] == REFERENCE_FIXTURE_ID
             and fixture["block"]["number"] == REFERENCE_BLOCK_NUMBER,
             "compact replay is attached to a non-reference corpus fixture")
    transports = fixture["semantic_io"]["guest_transports"]
    guest_input = transports["stwo_input"]
    guest_output = transports["stwo_output"]
    _require(guest_input is not None and guest_output is not None,
             "compact replay corpus transport is unavailable")
    projection = evidence["projection"]
    _require(projection["input"] == {
        "bytes": guest_input["bytes"], "sha256": guest_input["sha256"],
    }, "compact replay input differs from corpus")
    _require(projection["expected_output"] == {
        "bytes": guest_output["bytes"], "sha256": guest_output["sha256"],
    }, "compact replay output differs from corpus")
    _require(projection["execution_profile"] == "rv32im-zkvm-ethereum-v1"
             and projection["execution_profile_abi_version"] == 1,
             "compact replay execution profile differs")
    _require(projection["segment_count"] == REFERENCE_SEGMENT_COUNT
             and projection["segment_step_budget"]
             == REFERENCE_SEGMENT_STEP_BUDGET
             and projection["total_cycles"] == REFERENCE_TOTAL_CYCLES
             and projection["total_core_cycles"] == REFERENCE_CORE_CYCLES
             and projection["total_keccak_calls"] > 0
             and projection["total_recovery_calls"] > 0
             and projection["total_keccak_calls"]
             + projection["total_recovery_calls"] == REFERENCE_EXTERNAL_CALLS,
             "compact replay reference geometry differs")
    _require(projection["matrix_timing_admissible"] is False
             and projection["proof_complete"] is False,
             "compact replay diagnostic boundary differs")
    return {
        "scope": "execution",
        "status": "retained_nonpromotable",
        "reason": (
            "complete-compact-capture-and-parallel-replay-diagnostic-"
            "without-comparable-process-timing-or-proof"
        ),
        "evidence": evidence,
        "timing": None,
        "timing_authority": None,
        "security_target_bits": None,
        "fresh_verification": None,
    }
