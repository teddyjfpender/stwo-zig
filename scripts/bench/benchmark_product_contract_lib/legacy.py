"""Explicit non-promotion scope for historical aggregate harnesses."""

from __future__ import annotations


def aggregate_diagnostic_scope(surface: str) -> dict[str, object]:
    return {
        "classification": "legacy_aggregate_diagnostic",
        "surface": surface,
        "logical_product": "stwo-zig",
        "canonical_product_identity": None,
        "promotion_eligible": False,
        "focused_successor": "native_proof_cross_backend_matrix_v6",
        "reason": (
            "historical aggregate interop harness retained for continuity; "
            "only focused product receipts may support promotion"
        ),
    }
