#!/usr/bin/env python3
"""Validate one published Cairo Metal proof report against its proof bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any

LOWER_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate(
    report: dict[str, Any],
    proof_sha256: str,
    proof_bytes: int,
    runtime_mode: str,
) -> None:
    require(report.get("schema_version") == 2, "unsupported report schema")
    require(report.get("backend") == "metal", "report backend is not Metal")
    product = report.get("product")
    require(isinstance(product, dict), "missing product identity")
    require(product.get("name") == "stwo-cairo-metal", "wrong product identity")
    require(product.get("backend") == "metal", "wrong product backend")

    proof = report.get("proof")
    require(isinstance(proof, dict), "missing proof receipt")
    require(proof.get("format") == "json", "oracle gate requires JSON proof")
    require(proof.get("bytes") == proof_bytes, "proof byte count mismatch")
    require(proof.get("sha256") == proof_sha256, "proof digest mismatch")
    require(LOWER_SHA256.fullmatch(proof_sha256) is not None, "invalid proof digest")

    verification = report.get("verification")
    require(isinstance(verification, dict), "missing verification receipt")
    require(verification.get("requested") is True, "verification was not requested")
    require(verification.get("zig") is True, "Zig verification did not pass")

    evidence = report.get("backend_evidence")
    require(isinstance(evidence, dict), "missing backend evidence")
    require(evidence.get("execution") == "metal-pcs", "wrong Metal execution class")
    require(
        evidence.get("classification") == "accelerated_without_fallbacks",
        "Metal execution was not fallback-free",
    )
    require(
        isinstance(evidence.get("metal_dispatches"), int)
        and evidence["metal_dispatches"] > 0,
        "no Metal dispatch was recorded",
    )
    require(evidence.get("cpu_fallbacks") == 0, "CPU fallback was recorded")
    require(evidence.get("runtime_initializations") == 1, "runtime init count mismatch")
    require(evidence.get("runtime_shutdowns") == 1, "runtime shutdown count mismatch")

    runtime = product.get("runtime")
    require(isinstance(runtime, dict), "missing runtime identity")
    manifest = runtime.get("manifest")
    require(isinstance(manifest, str), "missing runtime manifest")
    require(f"mode={runtime_mode}" in manifest, "runtime mode identity mismatch")
    if runtime_mode == "source-jit":
        require(runtime.get("aot") == "none", "source-JIT report claims AOT")
    else:
        require(runtime.get("aot") != "none", "AOT report lacks AOT identity")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument(
        "--runtime-mode",
        choices=("source-jit", "authenticated-aot"),
        required=True,
    )
    args = parser.parse_args()

    proof_bytes = args.proof.read_bytes()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    require(isinstance(report, dict), "report root must be an object")
    validate(
        report,
        hashlib.sha256(proof_bytes).hexdigest(),
        len(proof_bytes),
        args.runtime_mode,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
