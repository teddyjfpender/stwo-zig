"""Validation and installation helpers for generated refinement artifacts."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

from . import codec
from .model import LEAN_TOOLCHAIN, SCHEMA_VERSION, Paths, RefinementError
from .sail_contract import CARRIED_EVIDENCE, LIVE_EVIDENCE


MANIFEST_PATH = Path("generated-manifest.json")
MANIFEST_CLAIM_BOUNDARY = {
    "lui_air_ir_v2_roundtrip": True,
    "lean_serialized_m31_air_interpreter": True,
    "lui_air_to_normalized_composition": True,
    "addi_air_to_normalized_composition": True,
    "generated_sail_ast_translation_receipt": True,
    "lean_generated_sail_monad_normalization": True,
    "lean_generated_sail_step_loop_framing": True,
    "kernel_checked_normalized_refinement": True,
}
_EVIDENCE_SOURCES = frozenset((LIVE_EVIDENCE, CARRIED_EVIDENCE))


def _manifest_evidence_source(manifest: dict[str, Any]) -> str:
    sail = manifest.get("sail")
    if not isinstance(sail, dict):
        raise RefinementError(
            "generated refinement manifest Sail provenance is invalid"
        )
    source = sail.get("evidence_source")
    if not isinstance(source, str) or source not in _EVIDENCE_SOURCES:
        raise RefinementError(
            "generated refinement manifest Sail evidence source is invalid"
        )
    return source


def manifest_content_digest(manifest: dict[str, Any]) -> str:
    """Hash manifest content independently of its audited evidence grade."""

    _manifest_evidence_source(manifest)
    unsigned = copy.deepcopy(manifest)
    del unsigned["sail"]["evidence_source"]
    return codec.content_digest(unsigned)


def _rendered_manifest(data: bytes) -> dict[str, Any]:
    try:
        manifest = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RefinementError(
            f"fresh generated refinement manifest is invalid JSON: {exc}"
        ) from exc
    if not isinstance(manifest, dict):
        raise RefinementError(
            "fresh generated refinement manifest must be a JSON object"
        )
    if codec.pretty_bytes(manifest) != data:
        raise RefinementError(
            "fresh generated refinement manifest is not canonical pretty JSON"
        )
    _manifest_evidence_source(manifest)
    return manifest


def _manifest_comparison(
    destination: Path,
    rendered_bytes: bytes,
) -> tuple[bool, str, str]:
    """Compare manifests modulo only the Sail evidence-source marker."""

    committed = codec.load_json(destination)
    rendered = _rendered_manifest(rendered_bytes)
    committed_source = _manifest_evidence_source(committed)
    rendered_source = _manifest_evidence_source(rendered)
    substituted = copy.deepcopy(rendered)
    substituted["sail"]["evidence_source"] = committed_source
    return (
        codec.pretty_bytes(substituted) == destination.read_bytes(),
        committed_source,
        rendered_source,
    )


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
        if relative == MANIFEST_PATH:
            _rendered_manifest(data)
            if destination.is_file():
                equivalent, committed_source, rendered_source = (
                    _manifest_comparison(destination, data)
                )
                if destination.read_bytes() == data:
                    continue
                if (
                    equivalent
                    and committed_source == LIVE_EVIDENCE
                    and rendered_source == CARRIED_EVIDENCE
                ):
                    continue
        elif destination.is_file() and destination.read_bytes() == data:
            continue
        codec.atomic_write(destination, data)


def check_artifacts(paths: Paths, outputs: dict[Path, bytes]) -> None:
    errors: list[str] = []
    for relative, expected in outputs.items():
        destination = paths.formal / relative
        if not destination.is_file():
            errors.append(f"missing generated artifact {relative}")
        elif relative == MANIFEST_PATH:
            equivalent, _, _ = _manifest_comparison(destination, expected)
            if not equivalent:
                errors.append(f"generated artifact drifted: {relative}")
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
        or manifest.get("claim_boundary") != MANIFEST_CLAIM_BOUNDARY
        or manifest.get("canonical_digest") != manifest_content_digest(manifest)
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
