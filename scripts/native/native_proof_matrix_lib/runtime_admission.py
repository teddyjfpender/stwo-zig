"""Fail-closed binding between Metal runtime admission and product identity."""

from __future__ import annotations

import argparse
from typing import Any

try:
    from scripts.benchmark_product_contract_lib import revision_identity
except ModuleNotFoundError:
    from benchmark_product_contract_lib import revision_identity

from .model import MatrixError, RUNTIME_ADMISSION_KEYS
from .validation import (
    require_bool,
    require_digest,
    require_exact_keys,
    require_int,
    require_string,
)


def validate_runtime_admission(
    report: dict[str, Any],
    lane: str,
    args: argparse.Namespace,
    product_identity: dict[str, Any],
) -> None:
    admission = report["runtime_admission"]
    if lane == "cpu":
        if admission is not None:
            raise MatrixError("CPU report must not claim a Metal runtime admission")
        return
    if not isinstance(admission, dict):
        raise MatrixError("metal.runtime_admission must be an object")
    require_exact_keys(
        admission,
        RUNTIME_ADMISSION_KEYS,
        "metal.runtime_admission",
        optional={"platform_identity"},
    )
    if require_bool(
        admission["initialized"], "metal.runtime_admission.initialized"
    ) is not True:
        raise MatrixError("metal.runtime_admission must be initialized")
    origin = require_string(admission["origin"], "metal.runtime_admission.origin")
    if origin not in {"diagnostic_source_jit", "authenticated_core_aot"}:
        raise MatrixError("metal.runtime_admission.origin is unsupported")
    require_digest(admission["source_sha256"], "metal.runtime_admission.source_sha256")
    for field in (
        "active_call_leases",
        "live_resident_resources",
        "initialization_count",
        "shutdown_count",
    ):
        require_int(admission[field], f"metal.runtime_admission.{field}")
    if admission["initialization_count"] != admission["shutdown_count"] + 1:
        raise MatrixError("metal.runtime_admission lifecycle counts are inconsistent")
    if admission["active_call_leases"] != 0:
        raise MatrixError("metal.runtime_admission was captured with an active call lease")

    requested = getattr(args, "metal_runtime", "source-jit")
    expected_origin = {
        "source-jit": "diagnostic_source_jit",
        "authenticated-aot": "authenticated_core_aot",
    }.get(requested)
    if expected_origin is None or origin != expected_origin:
        raise MatrixError("metal.runtime_admission does not match the controller request")
    runtime_artifacts = revision_identity(product_identity)["runtime_artifacts"]
    if admission["source_sha256"] != runtime_artifacts["shader_amalgamation_sha256"]:
        raise MatrixError(
            "metal runtime shader source digest disagrees with product identity"
        )
    if requested == "source-jit":
        if any(
            admission[field] is not None
            for field in ("manifest_sha256", "metallib_sha256", "metallib_bytes")
        ):
            raise MatrixError("source JIT must not claim authenticated AOT identity")
        return

    manifest_sha256 = require_digest(
        admission["manifest_sha256"], "metal.runtime_admission.manifest_sha256"
    )
    expected_manifest_sha256 = getattr(args, "metal_aot_manifest_sha256", None)
    if manifest_sha256 != expected_manifest_sha256:
        raise MatrixError(
            "metal.runtime_admission manifest does not match the controller request"
        )
    require_digest(
        admission["metallib_sha256"], "metal.runtime_admission.metallib_sha256"
    )
    require_int(
        admission["metallib_bytes"],
        "metal.runtime_admission.metallib_bytes",
        positive=True,
    )
