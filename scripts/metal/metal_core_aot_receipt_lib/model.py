"""Stable schemas and invariants for Native Metal AOT receipts."""

from __future__ import annotations

import re

BUILD_SCHEMA = "stwo_zig_metal_core_aot_build_v1"
DEVICE_SCHEMA = "stwo_zig_metal_core_aot_device_acceptance_v1"
FORMAT = "stwo-zig-metal-core-aot-v2"
MANIFEST = "stwo_zig_core.manifest.json"
ANCHOR = "stwo_zig_core.manifest.sha256"
FILES = (
    "stwo_zig_core.metal",
    "stwo_zig_core.air",
    "stwo_zig_core.metallib",
    MANIFEST,
    ANCHOR,
)
BUNDLE_NAMES = ("build-a", "build-b")
BUILD_CHECKS = {
    "bundle_manifest_measurements_valid": True,
    "bundle_manifest_trust_anchors_valid": True,
    "independent_builds_byte_identical": True,
}
DEVICE_CHECKS = {
    "hosted_receipt_checksum_valid": True,
    "hosted_receipt_schema_valid": True,
    "hosted_receipt_commit_bound": True,
    "hosted_bundle_identities_match": True,
    "independent_builds_byte_identical": True,
    "device_probe_build_a": True,
    "device_probe_build_b": True,
    "authenticated_bundle_admission": True,
    "aot_jit_transcript_output_parity": True,
    "exact_export_set_and_function_constants": True,
}
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DECIMAL_RE = re.compile(r"^[0-9]+$")


class ReceiptError(RuntimeError):
    """The evidence cannot support the acceptance claim."""
