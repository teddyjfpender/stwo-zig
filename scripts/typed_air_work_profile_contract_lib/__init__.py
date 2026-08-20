"""Stable source authority for typed-AIR whole-prover work coverage."""

from .matrix import (
    COUNTER_PARTITION,
    FAMILY_IDS,
    INVENTORY_PATH,
    INVENTORY_SCHEMA_VERSION,
    MATRIX_PATH,
    MATRIX_SCHEMA,
    SCHEMA_VERSION,
    SITE_IDS,
    MatrixContractError,
    inventory_authority,
    validate_matrix,
)

__all__ = [
    "COUNTER_PARTITION",
    "FAMILY_IDS",
    "INVENTORY_PATH",
    "INVENTORY_SCHEMA_VERSION",
    "MATRIX_PATH",
    "MATRIX_SCHEMA",
    "MatrixContractError",
    "SCHEMA_VERSION",
    "SITE_IDS",
    "inventory_authority",
    "validate_matrix",
]
