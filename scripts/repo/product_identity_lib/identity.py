"""Generic schema-v2 canonical product identity validation.

This module mirrors `build_support/graph/identity.zig` without imposing any
frontend, backend, role, or benchmark-lane policy.
"""

from __future__ import annotations

import hashlib
from typing import Any


IDENTITY_SCHEMA_VERSION = 2
IDENTITY_KEYS = {
    "schema_version",
    "name",
    "frontend",
    "backend",
    "role",
    "protocol_features",
    "protocol_manifest_sha256",
    "identity_sha256",
    "implementation_repository",
    "implementation_commit",
    "implementation_tree",
    "implementation_dirty",
    "dirty_content_sha256",
    "zig_version",
    "target_arch",
    "target_os",
    "target_abi",
    "cpu_model",
    "cpu_features_sha256",
    "optimize",
    "runtime_manifest",
    "sdk_manifest",
    "aot_manifest",
}


class ProductIdentityError(ValueError):
    """A canonical product identity is malformed or internally inconsistent."""


def _require_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProductIdentityError(f"{context} must be a nonempty string")
    return value


def _require_hex(value: Any, size: int, context: str) -> str:
    text = _require_string(value, context)
    if len(text) != size or any(character not in "0123456789abcdef" for character in text):
        raise ProductIdentityError(f"{context} must be {size} lowercase hex characters")
    return text


def _hash_int(hasher: Any, value: int) -> None:
    hasher.update(value.to_bytes(8, byteorder="big", signed=False))


def _hash_field(hasher: Any, value: str) -> None:
    encoded = value.encode("utf-8")
    _hash_int(hasher, len(encoded))
    hasher.update(encoded)


def _hash_bool(hasher: Any, value: bool) -> None:
    hasher.update(b"\x01" if value else b"\x00")


def canonical_identity_sha256(identity: dict[str, Any]) -> str:
    """Mirror the schema-v2 Zig canonical encoding byte-for-byte."""

    digest = hashlib.sha256()
    _hash_field(digest, "stwo-product-identity-v2")
    _hash_int(digest, identity["schema_version"])
    for field in (
        "name",
        "frontend",
        "backend",
        "role",
        "implementation_repository",
        "implementation_commit",
    ):
        _hash_field(digest, identity[field])
    tree = identity["implementation_tree"]
    _hash_bool(digest, tree is not None)
    if tree is not None:
        _hash_field(digest, tree)
    dirty = identity["implementation_dirty"]
    _hash_bool(digest, dirty)
    dirty_digest = identity["dirty_content_sha256"]
    _hash_bool(digest, dirty_digest is not None)
    if dirty_digest is not None:
        digest.update(bytes.fromhex(dirty_digest))
    for field in (
        "zig_version",
        "target_arch",
        "target_os",
        "target_abi",
        "cpu_model",
    ):
        _hash_field(digest, identity[field])
    digest.update(bytes.fromhex(identity["cpu_features_sha256"]))
    _hash_field(digest, identity["optimize"])
    _hash_field(digest, identity["protocol_features"])
    digest.update(bytes.fromhex(identity["protocol_manifest_sha256"]))
    for field in ("runtime_manifest", "sdk_manifest", "aot_manifest"):
        _hash_field(digest, identity[field])
    return digest.hexdigest()


def validate_canonical_identity(
    value: Any,
    *,
    context: str = "product_identity",
) -> dict[str, Any]:
    """Validate any canonical identity without applying product policy."""

    if not isinstance(value, dict) or set(value) != IDENTITY_KEYS:
        raise ProductIdentityError(f"{context} has an unsupported schema")
    if value["schema_version"] != IDENTITY_SCHEMA_VERSION:
        raise ProductIdentityError(f"{context} schema is unsupported")
    for field in (
        "name",
        "frontend",
        "backend",
        "role",
        "protocol_features",
        "implementation_repository",
        "zig_version",
        "target_arch",
        "target_os",
        "target_abi",
        "cpu_model",
        "optimize",
        "runtime_manifest",
        "sdk_manifest",
        "aot_manifest",
    ):
        _require_string(value[field], f"{context}.{field}")
    _require_hex(value["implementation_commit"], 40, f"{context}.implementation_commit")
    _require_hex(value["implementation_tree"], 40, f"{context}.implementation_tree")
    _require_hex(value["cpu_features_sha256"], 64, f"{context}.cpu_features_sha256")
    _require_hex(
        value["protocol_manifest_sha256"],
        64,
        f"{context}.protocol_manifest_sha256",
    )
    protocol_digest = hashlib.sha256(value["protocol_features"].encode()).hexdigest()
    if value["protocol_manifest_sha256"] != protocol_digest:
        raise ProductIdentityError(f"{context} protocol digest is invalid")
    _require_hex(value["identity_sha256"], 64, f"{context}.identity_sha256")
    dirty = value["implementation_dirty"]
    if not isinstance(dirty, bool):
        raise ProductIdentityError(f"{context}.implementation_dirty must be boolean")
    dirty_digest = value["dirty_content_sha256"]
    if dirty != (dirty_digest is not None):
        raise ProductIdentityError(f"{context} dirty state is inconsistent")
    if dirty_digest is not None:
        _require_hex(dirty_digest, 64, f"{context}.dirty_content_sha256")
    if value["identity_sha256"] != canonical_identity_sha256(value):
        raise ProductIdentityError(f"{context} canonical digest is invalid")
    return value


__all__ = [
    "IDENTITY_KEYS",
    "IDENTITY_SCHEMA_VERSION",
    "ProductIdentityError",
    "canonical_identity_sha256",
    "validate_canonical_identity",
]
