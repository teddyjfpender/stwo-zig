"""Validation and installation helpers for generated refinement artifacts."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import codec
from .model import LEAN_TOOLCHAIN, SCHEMA_VERSION, Paths, RefinementError


def write_artifacts(paths: Paths, outputs: dict[Path, bytes]) -> None:
    ordered = sorted(
        outputs.items(),
        key=lambda item: (
            item[0] == Path("generated-manifest.json"),
            item[0].as_posix(),
        ),
    )
    for relative, data in ordered:
        destination = paths.formal / relative
        if destination.is_file() and destination.read_bytes() == data:
            continue
        codec.atomic_write(destination, data)


def check_artifacts(paths: Paths, outputs: dict[Path, bytes]) -> None:
    errors: list[str] = []
    for relative, expected in outputs.items():
        destination = paths.formal / relative
        if not destination.is_file():
            errors.append(f"missing generated artifact {relative}")
        elif destination.read_bytes() != expected:
            errors.append(f"generated artifact drifted: {relative}")
    if errors:
        raise RefinementError("; ".join(errors))


def validate_manifest(
    paths: Paths,
    manifest: dict[str, Any],
    *,
    production_sources: dict[str, str],
    generators: dict[str, str],
    proof_sources: dict[str, str],
    manifest_artifacts: frozenset[str],
) -> None:
    if set(manifest) != {
        "artifacts",
        "canonical_digest",
        "claim_boundary",
        "generators",
        "kind",
        "lean_toolchain",
        "opcodes",
        "production_sources",
        "proof_sources",
        "sail",
        "schema_version",
        "tier",
    }:
        raise RefinementError("generated refinement manifest schema drifted")
    if (
        manifest.get("schema_version") != SCHEMA_VERSION
        or manifest.get("kind")
        != "stwo-riscv-refinement-generated-manifest"
        or manifest.get("tier") != "level-1-normalized-pilot"
        or manifest.get("lean_toolchain") != LEAN_TOOLCHAIN
        or manifest.get("claim_boundary")
        != {
            "lui_air_ir_v2_roundtrip": True,
            "lean_serialized_m31_air_interpreter": True,
            "lui_air_to_normalized_composition": True,
            "addi_air_to_normalized_composition": True,
            "generated_sail_ast_translation_receipt": True,
            "lean_generated_sail_monad_normalization": True,
            "lean_generated_sail_step_loop_framing": False,
            "kernel_checked_normalized_refinement": True,
        }
        or manifest.get("canonical_digest") != codec.content_digest(manifest)
    ):
        raise RefinementError("generated refinement manifest identity is invalid")
    if manifest.get("production_sources") != production_sources:
        raise RefinementError(
            "generated refinement manifest production-source closure drifted"
        )
    if manifest.get("generators") != generators:
        raise RefinementError(
            "generated refinement manifest generator closure drifted"
        )
    if manifest.get("proof_sources") != proof_sources:
        raise RefinementError(
            "generated refinement manifest proof-source closure drifted"
        )
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != manifest_artifacts:
        raise RefinementError("generated refinement artifact closure drifted")
    for relative, expected in artifacts.items():
        if (
            not isinstance(expected, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected)
        ):
            raise RefinementError(
                f"generated refinement artifact digest is invalid: {relative}"
            )
        path = paths.formal / relative
        if path.is_symlink() or not path.is_file():
            raise RefinementError(
                f"generated refinement artifact is missing: {relative}"
            )
        if codec.sha256_file(path) != expected:
            raise RefinementError(
                f"generated refinement artifact digest drifted: {relative}"
            )
