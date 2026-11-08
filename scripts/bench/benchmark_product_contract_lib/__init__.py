"""Focused-product identity and measurement-receipt authority."""

from .identity import (
    PRODUCT_SPECS,
    ProductEvidenceError,
    comparable_identity,
    revision_identity,
    validate_product_identity,
)
from .receipt import (
    MIN_PROMOTION_VERIFIED_SAMPLES,
    MIN_PROMOTION_WARMUPS,
    RECEIPT_PROTOCOL,
    build_receipt,
    validate_receipt,
)
from .legacy import aggregate_diagnostic_scope

__all__ = [
    "PRODUCT_SPECS",
    "MIN_PROMOTION_VERIFIED_SAMPLES",
    "MIN_PROMOTION_WARMUPS",
    "RECEIPT_PROTOCOL",
    "ProductEvidenceError",
    "build_receipt",
    "aggregate_diagnostic_scope",
    "comparable_identity",
    "revision_identity",
    "validate_product_identity",
    "validate_receipt",
]
