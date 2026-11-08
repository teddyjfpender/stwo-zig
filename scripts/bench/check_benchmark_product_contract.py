#!/usr/bin/env python3
"""Validate the BG-12 product, schema, receipt, and history registry."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("STWO_ZIG_EXECUTION_ROOT", SCRIPT_DIR.parent)).resolve()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from benchmark_product_contract_lib import (  # noqa: E402
    MIN_PROMOTION_VERIFIED_SAMPLES,
    MIN_PROMOTION_WARMUPS,
    PRODUCT_SPECS,
    RECEIPT_PROTOCOL,
)
from scripts.product_identity_lib import IDENTITY_SCHEMA_VERSION  # noqa: E402
from benchmark_product_contract_lib.legacy import aggregate_diagnostic_scope  # noqa: E402
from benchmark_delta_lib.controller import (  # noqa: E402
    LEGACY_V5_PRODUCT_ALIASES,
    NATIVE_PROTOCOL_V6,
)
from native_profile_capture import parse_args as parse_profile_args  # noqa: E402
from native_proof_matrix import parse_args as parse_matrix_args  # noqa: E402
from native_profile_capture_lib.controller import (  # noqa: E402
    _product_receipts as profile_receipts,
)
from native_proof_matrix_lib.controller import (  # noqa: E402
    product_receipts as benchmark_receipts,
)
from native_proof_matrix_lib.evidence import SUMMARY_PROTOCOL  # noqa: E402
from native_proof_matrix_lib.model import MIN_HEADLINE_WARMUPS  # noqa: E402
from native_proof_matrix_lib.evidence import MIN_FORMAL_MEASURED_PROOFS  # noqa: E402


POLICY = SCRIPT_DIR.parent / "conformance" / "benchmark-profiler-product-contract-v1.json"
AUTHORITY = ROOT / "build_support" / "benchmark_product_authority.zig"


def _live_product_authority() -> dict[str, object]:
    result = subprocess.run(
        ["zig", "run", str(AUTHORITY)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise ValueError(f"live Zig product authority failed: {result.stderr.strip()}")
    try:
        authority = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("live Zig product authority did not emit JSON") from error
    if (
        not isinstance(authority, dict)
        or set(authority) != {"identity_schema_version", "products"}
        or authority["identity_schema_version"] != IDENTITY_SCHEMA_VERSION
        or not isinstance(authority["products"], dict)
        or set(authority["products"]) != set(PRODUCT_SPECS)
    ):
        raise ValueError("live Zig product authority has an unsupported schema")
    return authority


def validate() -> dict[str, object]:
    document = json.loads(POLICY.read_text(encoding="utf-8"))
    authority = _live_product_authority()
    if document.get("schema") != "stwo-benchmark-profiler-product-contract-v1":
        raise ValueError("benchmark/profiler policy schema is unsupported")
    if document["promotion_surface"]["benchmark"]["protocol"] != SUMMARY_PROTOCOL:
        raise ValueError("benchmark policy protocol drifted from the controller")
    if SUMMARY_PROTOCOL != NATIVE_PROTOCOL_V6:
        raise ValueError("benchmark and delta protocol registries disagree")
    if MIN_PROMOTION_WARMUPS != MIN_HEADLINE_WARMUPS:
        raise ValueError("receipt and matrix warmup thresholds disagree")
    if MIN_PROMOTION_VERIFIED_SAMPLES != MIN_FORMAL_MEASURED_PROOFS:
        raise ValueError("receipt and matrix verified-sample thresholds disagree")
    expected_promotion_policy = {
        "derivation": "validated receipt policy plus every measurement row",
        "formal": True,
        "profiled": False,
        "protocol": "functional",
        "minimum_excluded_warmups": MIN_PROMOTION_WARMUPS,
        "minimum_verified_samples_per_lane": MIN_PROMOTION_VERIFIED_SAMPLES,
        "requires_release_fast_clean_identity": True,
        "requires_every_measured_proof_locally_verified": True,
        "requires_verified_samples_equal_measured_samples": True,
        "requires_byte_identical_samples": True,
        "requires_cpu_metal_canonical_equality": True,
        "requires_pinned_rust_stwo": True,
        "requires_every_row_headline_eligible": True,
        "requires_every_row_stable": True,
        "required_evidence_class": "verified_unprofiled",
    }
    if document.get("promotion_policy") != expected_promotion_policy:
        raise ValueError("machine promotion policy drifted from receipt authority")
    for surface in ("benchmark", "profiler"):
        if document["promotion_surface"][surface]["receipt_protocol"] != RECEIPT_PROTOCOL:
            raise ValueError(f"{surface} receipt protocol drifted")

    matrix = parse_matrix_args(["--allow-non-headline"])
    profile = parse_profile_args([])
    expected_paths = {
        "cpu": matrix.cpu_bin.relative_to(ROOT).as_posix(),
        "metal": matrix.metal_bin.relative_to(ROOT).as_posix(),
    }
    if profile.cpu_bin != matrix.cpu_bin or profile.metal_bin != matrix.metal_bin:
        raise ValueError("benchmark and profiler default binaries differ")
    for lane, spec in PRODUCT_SPECS.items():
        live = authority["products"][lane]
        expected_live = {
            "name": spec.name,
            "frontend": spec.frontend,
            "backend": spec.backend,
            "role": "benchmark",
            "protocol_features": spec.protocol_features,
        }
        if live != expected_live:
            raise ValueError(f"{lane} Python product spec drifted from Zig descriptor authority")
        policy = document["products"][lane]
        expected = {
            "logical_name": spec.name,
            "frontend": spec.frontend,
            "backend": spec.backend,
            "role": "benchmark",
            "binary": expected_paths[lane],
        }
        for field, value in expected.items():
            if policy.get(field) != value:
                raise ValueError(f"{lane} policy field {field} drifted")

    aliases = document["historical_identity_aliases"][
        "native_proof_cross_backend_matrix_v5"
    ]
    for lane, expected in LEGACY_V5_PRODUCT_ALIASES.items():
        actual = aliases[lane]
        if actual["historical_executable"] != expected["historical_executable"]:
            raise ValueError(f"{lane} historical executable alias drifted")
        if actual["maps_to"] != expected["focused_product"]:
            raise ValueError(f"{lane} focused product alias drifted")

    if not callable(benchmark_receipts) or not callable(profile_receipts):
        raise ValueError("focused receipt producers are unavailable")
    for surface in ("benchmark_full", "benchmark_smoke", "profile_smoke"):
        scope = aggregate_diagnostic_scope(surface)
        if scope["promotion_eligible"] is not False or scope["logical_product"] != "stwo-zig":
            raise ValueError(f"{surface} legacy diagnostic scope is unsafe")
    return {
        "status": "ok",
        "schema": document["schema"],
        "benchmark_protocol": SUMMARY_PROTOCOL,
        "receipt_protocol": RECEIPT_PROTOCOL,
        "products": sorted(spec.name for spec in PRODUCT_SPECS.values()),
        "legacy_aliases": sorted(LEGACY_V5_PRODUCT_ALIASES),
    }


def main() -> int:
    print(json.dumps(validate(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
