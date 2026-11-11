"""Public schema-v2 canonical product identity validation contract."""

from .identity import (
    IDENTITY_KEYS,
    IDENTITY_SCHEMA_VERSION,
    ProductIdentityError,
    canonical_identity_sha256,
    validate_canonical_identity,
)

__all__ = [
    "IDENTITY_KEYS",
    "IDENTITY_SCHEMA_VERSION",
    "ProductIdentityError",
    "canonical_identity_sha256",
    "validate_canonical_identity",
]
