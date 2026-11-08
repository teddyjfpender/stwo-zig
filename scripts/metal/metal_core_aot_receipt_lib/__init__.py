"""Authenticated two-phase Native Metal AOT evidence protocol."""

from .artifacts import (
    checksum_path,
    load_bundle,
    recorded_bundle_identity,
    require_reproducible,
    write_receipt,
)
from .controller import main
from .environment import require_hosted_ci_identity
from .model import (
    ANCHOR,
    BUILD_CHECKS,
    BUILD_SCHEMA,
    DEVICE_CHECKS,
    DEVICE_SCHEMA,
    FILES,
    FORMAT,
    MANIFEST,
    ReceiptError,
)

__all__ = [
    "ANCHOR",
    "BUILD_CHECKS",
    "BUILD_SCHEMA",
    "DEVICE_CHECKS",
    "DEVICE_SCHEMA",
    "FILES",
    "FORMAT",
    "MANIFEST",
    "ReceiptError",
    "checksum_path",
    "load_bundle",
    "main",
    "recorded_bundle_identity",
    "require_hosted_ci_identity",
    "require_reproducible",
    "write_receipt",
]
