"""Independent validation of canonical identities emitted by focused products."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

try:
    from scripts.product_identity_lib import (
        ProductIdentityError,
        canonical_identity_sha256,
        validate_canonical_identity,
    )
except ModuleNotFoundError:
    from product_identity_lib import (
        ProductIdentityError,
        canonical_identity_sha256,
        validate_canonical_identity,
    )


ProductEvidenceError = ProductIdentityError


@dataclass(frozen=True)
class ProductSpec:
    name: str
    frontend: str
    backend: str
    report_backend: str
    protocol_features: str


PRODUCT_SPECS = {
    "cpu": ProductSpec(
        name="stwo-native-cpu",
        frontend="native-examples",
        backend="cpu",
        report_backend="cpu_native",
        protocol_features="native-examples-v1+lifted-pcs-v1",
    ),
    "metal": ProductSpec(
        name="stwo-native-metal",
        frontend="native-examples",
        backend="metal",
        report_backend="metal_hybrid",
        protocol_features="native-examples-v1+lifted-pcs-v1+metal-runtime-v1",
    ),
}


def _parse_manifest(
    value: str,
    *,
    prefix: str,
    fields: tuple[str, ...],
    context: str,
) -> dict[str, str]:
    actual_prefix, separator, payload = value.partition(":")
    if separator != ":" or actual_prefix != prefix:
        raise ProductEvidenceError(f"{context} has an unsupported schema")
    result: dict[str, str] = {}
    for item in payload.split(";"):
        key, separator, field_value = item.partition("=")
        if separator != "=" or not key or not field_value or key in result:
            raise ProductEvidenceError(f"{context} is malformed")
        result[key] = field_value
    if tuple(result) != fields:
        raise ProductEvidenceError(f"{context} has unsupported fields")
    return result


def _require_hex64(value: str, context: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ProductEvidenceError(f"{context} must be 64 lowercase hex characters")


def _validate_runtime(identity: dict[str, Any], lane: str) -> None:
    if lane == "cpu":
        for field in ("runtime_manifest", "sdk_manifest", "aot_manifest"):
            if identity[field] != "none":
                raise ProductEvidenceError(
                    f"{lane}.product_identity.{field} does not identify a host-only CPU product"
                )
        return

    runtime = _parse_manifest(
        identity["runtime_manifest"],
        prefix="metal-runtime-v2",
        fields=("mode", "shader-amalgamation-sha256", "runtime-objc-sha256"),
        context="metal.product_identity.runtime_manifest",
    )
    if runtime["mode"] != "source-jit":
        raise ProductEvidenceError(
            "metal.product_identity.runtime_manifest is not the source-JIT product"
        )
    for field in ("shader-amalgamation-sha256", "runtime-objc-sha256"):
        _require_hex64(runtime[field], f"metal.product_identity.runtime_manifest.{field}")

    sdk = _parse_manifest(
        identity["sdk_manifest"],
        prefix="apple-metal-sdk-v2",
        fields=(
            "sdk-path",
            "sdk-version",
            "sdk-build",
            "objc-compiler",
            "objc-compiler-version-sha256",
            "compile-profile-sha256",
        ),
        context="metal.product_identity.sdk_manifest",
    )
    for field in ("objc-compiler-version-sha256", "compile-profile-sha256"):
        _require_hex64(sdk[field], f"metal.product_identity.sdk_manifest.{field}")
    if identity["aot_manifest"] != "none":
        raise ProductEvidenceError(
            "metal.product_identity.aot_manifest does not identify the source-JIT product"
        )


def validate_product_identity(
    value: Any,
    lane: str,
    *,
    provenance: dict[str, Any] | None = None,
    required_role: str = "benchmark",
) -> dict[str, Any]:
    if lane not in PRODUCT_SPECS:
        raise ProductEvidenceError(f"unknown focused-product lane: {lane}")
    validate_canonical_identity(value, context=f"{lane}.product_identity")
    spec = PRODUCT_SPECS[lane]
    expected = {
        "name": spec.name,
        "frontend": spec.frontend,
        "backend": spec.backend,
        "role": required_role,
        "protocol_features": spec.protocol_features,
    }
    for field, expected_value in expected.items():
        if value[field] != expected_value:
            raise ProductEvidenceError(
                f"{lane}.product_identity.{field} does not identify {spec.name}"
            )
    _validate_runtime(value, lane)
    if provenance is not None:
        bindings = {
            "implementation_commit": "git_commit",
            "implementation_dirty": "git_dirty",
            "zig_version": "zig_version",
            "target_arch": "target_arch",
            "target_os": "target_os",
            "optimize": "optimization",
        }
        for identity_field, provenance_field in bindings.items():
            if value[identity_field] != provenance.get(provenance_field):
                raise ProductEvidenceError(
                    f"{lane}.product_identity.{identity_field} disagrees with report provenance"
                )
    return value


def comparable_identity(identity: dict[str, Any]) -> dict[str, Any]:
    """Fields that must match for timing comparisons across source revisions."""

    comparable = {
        field: identity[field]
        for field in (
            "schema_version",
            "name",
            "frontend",
            "backend",
            "role",
            "protocol_features",
            "protocol_manifest_sha256",
            "zig_version",
            "target_arch",
            "target_os",
            "target_abi",
            "cpu_model",
            "cpu_features_sha256",
            "optimize",
        )
    }
    if identity["backend"] == "metal":
        runtime = _parse_manifest(
            identity["runtime_manifest"],
            prefix="metal-runtime-v2",
            fields=("mode", "shader-amalgamation-sha256", "runtime-objc-sha256"),
            context="metal.product_identity.runtime_manifest",
        )
        sdk = _parse_manifest(
            identity["sdk_manifest"],
            prefix="apple-metal-sdk-v2",
            fields=(
                "sdk-path",
                "sdk-version",
                "sdk-build",
                "objc-compiler",
                "objc-compiler-version-sha256",
                "compile-profile-sha256",
            ),
            context="metal.product_identity.sdk_manifest",
        )
        comparable["runtime_configuration"] = {
            "schema": "metal-runtime-v2",
            "mode": runtime["mode"],
        }
        comparable["sdk_configuration"] = {
            "schema": "apple-metal-sdk-v2",
            "sdk_version": sdk["sdk-version"],
            "sdk_build": sdk["sdk-build"],
            "objc_compiler_version_sha256": sdk[
                "objc-compiler-version-sha256"
            ],
            "compile_profile_sha256": sdk["compile-profile-sha256"],
        }
        comparable["aot_mode"] = (
            "none" if identity["aot_manifest"] == "none" else "authenticated"
        )
    else:
        comparable["runtime_configuration"] = {"schema": "none", "mode": "none"}
        comparable["sdk_configuration"] = {"schema": "none"}
        comparable["aot_mode"] = "none"
    return comparable


def revision_identity(identity: dict[str, Any]) -> dict[str, Any]:
    """Source and binary inputs that may change between comparable revisions."""

    revision = {
        field: identity[field]
        for field in (
            "identity_sha256",
            "implementation_repository",
            "implementation_commit",
            "implementation_tree",
            "implementation_dirty",
            "dirty_content_sha256",
            "runtime_manifest",
            "aot_manifest",
        )
    }
    if identity["backend"] == "metal":
        runtime = _parse_manifest(
            identity["runtime_manifest"],
            prefix="metal-runtime-v2",
            fields=("mode", "shader-amalgamation-sha256", "runtime-objc-sha256"),
            context="metal.product_identity.runtime_manifest",
        )
        revision["runtime_artifacts"] = {
            "shader_amalgamation_sha256": runtime[
                "shader-amalgamation-sha256"
            ],
            "runtime_objc_sha256": runtime["runtime-objc-sha256"],
        }
    else:
        revision["runtime_artifacts"] = None
    return revision
