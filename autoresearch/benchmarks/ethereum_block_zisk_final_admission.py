"""Strict matrix projection for a retained ZisK whole-block final proof."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import ethereum_block_zisk_final_evidence as final_evidence


EVIDENCE_KIND = final_evidence.EVIDENCE_KIND
REFERENCE_FIXTURE_ID = final_evidence.REFERENCE_FIXTURE_ID
SUPPORTED_SCOPES = ("aggregation", "fresh_verification", "end_to_end")


class ZiskFinalAdmissionError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ZiskFinalAdmissionError(message)


def validate_stage(
    evidence: Any, fixture: dict[str, Any], manifest_identity: dict[str, Any],
    scope: str,
) -> dict[str, Any]:
    """Replay evidence and return one deliberately nonpromotable stage."""
    _require(scope in SUPPORTED_SCOPES, "ZisK final-proof scope differs")
    _require(type(evidence) is dict and set(evidence) == {
        "kind", "receipt", "projection",
    }, "ZisK final-proof evidence keys differ")
    _require(evidence["kind"] == EVIDENCE_KIND,
             "ZisK final-proof evidence kind differs")
    receipt = evidence["receipt"]
    _require(type(receipt) is dict and type(receipt.get("path")) is str,
             "ZisK final-proof receipt identity differs")
    path = Path(receipt["path"])
    _require(path.is_absolute(), "ZisK final-proof receipt path differs")
    expected = final_evidence.evidence(path)
    _require(evidence == expected, "ZisK final-proof evidence replay differs")
    projection = evidence["projection"]
    _require(fixture["fixture_id"] == REFERENCE_FIXTURE_ID
             and projection["fixture_id"] == REFERENCE_FIXTURE_ID
             and all(fixture["block"][key] == item
                     for key, item in projection["block"].items()),
             "ZisK final proof is attached to a different corpus fixture")
    _require(projection["reference_manifest"] == {
        key: manifest_identity[key] for key in ("bytes", "sha256")
    } and projection["statement_sha256"]
             == manifest_identity["statement_sha256"],
             "ZisK final proof reference manifest differs")
    _require(projection["proof_kind"] == final_evidence.PROOF_KIND
             and projection["proof_scope"]
             == "one-final-proof-covering-the-entire-block"
             and projection["fresh_process_verification"] is True,
             "ZisK final-proof scope or verification differs")
    _require(projection["security_target_bits"] is None
             and projection["exclusive_stage_timings_available"] is False
             and projection["timing_classification"]
             == "diagnostic_nonpromotable"
             and projection["matrix_timing_admissible"] is False
             and projection["comparison_ready"] is False,
             "ZisK final-proof promotion boundary differs")
    common = {
        "scope": scope,
        "evidence": evidence,
        "timing": None,
        "timing_authority": None,
        "security_target_bits": None,
        "fresh_verification": scope in ("fresh_verification", "end_to_end"),
    }
    if scope == "aggregation":
        return {
            **common,
            "status": "complete_nonpromotable",
            "reason": (
                "retained-whole-block-vadcop-final-proof-without-"
                "matched-security-or-exclusive-aggregation-timing"
            ),
        }
    if scope == "fresh_verification":
        return {
            **common,
            "status": "complete_nonpromotable",
            "reason": (
                "fresh-process-final-proof-verification-retained-without-"
                "matched-security-or-matrix-timing-authority"
            ),
        }
    return {
        **common,
        "status": "retained_nonpromotable",
        "reason": (
            "whole-block-final-proof-correctness-retained-without-"
            "exclusive-execute-witness-base-aggregation-verify-buckets"
        ),
    }
