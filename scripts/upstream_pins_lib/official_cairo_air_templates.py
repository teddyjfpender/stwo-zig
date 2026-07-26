"""Validate the authenticated all-family Stwo-Cairo AIR template library."""

from __future__ import annotations

import hashlib
import json
import struct
from collections.abc import Callable
from pathlib import Path

from .official_cairo_air import check as check_air_programs


def check(
    root: Path,
    authority: dict[str, str],
    *,
    closure_sha256: Callable[[Path], str],
) -> list[str]:
    relative_path = (
        "vectors/cairo/official/air_template_library_v1.provenance.json"
    )
    try:
        record = json.loads((root / relative_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"{relative_path}: invalid provenance: {error}"]
    if (
        not isinstance(record, dict)
        or record.get("schema") != "stwo_zig_cairo_air_template_library_v1"
    ):
        return [f"{relative_path}: invalid schema"]

    errors: list[str] = []
    source = record.get("source")
    generator = record.get("generator")
    library = record.get("library")
    sources = record.get("sources")
    if not all(
        isinstance(value, dict) for value in (source, generator, library)
    ) or not isinstance(sources, list):
        return [
            f"{relative_path}: source, generator, library, and sources are required"
        ]
    for key, expected in authority.items():
        if source.get(key) != expected:
            errors.append(
                f"{relative_path}: source {key!r} is {source.get(key)!r}, "
                f"expected {expected!r}"
            )
    if generator.get("path") != "tools/stwo-cairo-air-compiler":
        errors.append(f"{relative_path}: AIR compiler path drifted")
    else:
        closure = closure_sha256(root / generator["path"])
        if generator.get("closure_sha256") != closure:
            errors.append(f"{relative_path}: AIR compiler closure drifted")

    library_path = library.get("path")
    if not isinstance(library_path, str) or Path(library_path).is_absolute():
        return errors + [f"{relative_path}: library path is invalid"]
    try:
        library_bytes = (root / library_path).read_bytes()
        manifest = json.loads(library_bytes)
    except (OSError, json.JSONDecodeError) as error:
        return errors + [f"{relative_path}: invalid library manifest: {error}"]
    if library.get("bytes") != len(library_bytes):
        errors.append(f"{relative_path}: library byte count drifted")
    if library.get("sha256") != hashlib.sha256(library_bytes).hexdigest():
        errors.append(f"{relative_path}: library digest drifted")
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != "stwo-zig-cairo-air-template-library-v1"
        or manifest.get("version") != 1
    ):
        return errors + [f"{relative_path}: library manifest schema drifted"]
    expected_manifest_authority = {
        "stwo_cairo_revision": authority["revision"],
        "stwo_revision": authority["stwo_revision"],
    }
    if manifest.get("authority") != expected_manifest_authority:
        errors.append(f"{relative_path}: library authority drifted")

    manifest_sources = manifest.get("sources")
    if (
        not isinstance(manifest_sources, list)
        or len(manifest_sources) != 3
        or len(sources) != 3
    ):
        return errors + [
            f"{relative_path}: exactly three AIR sources are required"
        ]
    expected_roles = {"opcodes", "canonical", "canonical_small"}
    if {
        entry.get("role") for entry in sources if isinstance(entry, dict)
    } != expected_roles:
        errors.append(f"{relative_path}: provenance source roles drifted")
    if {
        entry.get("role")
        for entry in manifest_sources
        if isinstance(entry, dict)
    } != expected_roles:
        errors.append(f"{relative_path}: manifest source roles drifted")

    labels: set[str] = set()
    manifest_by_role = {
        entry.get("role"): entry
        for entry in manifest_sources
        if isinstance(entry, dict)
    }
    for entry in sources:
        if not isinstance(entry, dict):
            errors.append(f"{relative_path}: invalid AIR source")
            continue
        role = entry.get("role")
        manifest_entry = manifest_by_role.get(role)
        input_artifact = entry.get("input")
        bundle = entry.get("bundle")
        if (
            not isinstance(role, str)
            or not isinstance(manifest_entry, dict)
            or not isinstance(input_artifact, dict)
            or not isinstance(bundle, dict)
        ):
            errors.append(f"{relative_path}: incomplete AIR source")
            continue
        _check_input(
            root,
            relative_path,
            role,
            input_artifact,
            manifest_entry,
            errors,
        )
        if (
            entry.get("preprocessed_variant")
            != manifest_entry.get("preprocessed_variant")
        ):
            errors.append(f"{relative_path}: {role} variant drifted")
        manifest_bundle = manifest_entry.get("bundle")
        if not isinstance(manifest_bundle, dict):
            errors.append(f"{relative_path}: {role} manifest bundle is missing")
            continue
        bundle_path = bundle.get("path")
        if not isinstance(bundle_path, str):
            errors.append(f"{relative_path}: {role} bundle path is invalid")
            continue
        if (
            manifest_bundle.get("path") != Path(bundle_path).name
            or manifest_bundle.get("bytes") != bundle.get("bytes")
            or manifest_bundle.get("sha256") != bundle.get("sha256")
        ):
            errors.append(f"{relative_path}: {role} manifest bundle drifted")
        errors.extend(
            check_air_programs(
                root,
                relative_path,
                bundle,
                closure_sha256=closure_sha256,
            )
        )
        try:
            labels.update(_component_labels((root / bundle_path).read_bytes()))
        except (OSError, UnicodeDecodeError, ValueError, struct.error) as error:
            errors.append(f"{relative_path}: invalid {role} AIR bundle: {error}")
    if library.get("claim_field_count") != 68 or len(labels) != 68:
        errors.append(f"{relative_path}: all-family AIR coverage drifted")
    return errors


def _check_input(
    root: Path,
    relative_path: str,
    role: str,
    artifact: dict[str, object],
    manifest_entry: dict[str, object],
    errors: list[str],
) -> None:
    input_path = artifact.get("path")
    if not isinstance(input_path, str) or Path(input_path).is_absolute():
        errors.append(f"{relative_path}: {role} input path is invalid")
        return
    try:
        digest = hashlib.sha256((root / input_path).read_bytes()).hexdigest()
    except OSError as error:
        errors.append(f"{relative_path}: unable to read {role} input: {error}")
        return
    if artifact.get("sha256") != digest:
        errors.append(f"{relative_path}: {role} input digest drifted")
    if manifest_entry.get("input_sha256") != digest:
        errors.append(f"{relative_path}: {role} manifest input digest drifted")


def _component_labels(encoded: bytes) -> list[str]:
    if len(encoded) < 40 or encoded[:8] != b"STWZEVA\0":
        raise ValueError("invalid AIR bundle header")
    count = struct.unpack_from("<I", encoded, 28)[0]
    offset = 40
    labels: list[str] = []
    for _ in range(count):
        label_len = struct.unpack_from("<H", encoded, offset)[0]
        span_count, preprocessed_count, denominator_count, ext_count, parts = (
            struct.unpack_from("<5I", encoded, offset + 24)
        )
        offset += 44
        label = encoded[offset : offset + label_len].decode("ascii")
        if len(label) != label_len:
            raise ValueError("truncated AIR component label")
        labels.append(label.split("[", 1)[0])
        offset += (
            label_len
            + span_count * 12
            + preprocessed_count * 4
            + denominator_count * 4
            + ext_count * 32
        )
        for _ in range(parts):
            program_len = struct.unpack_from("<I", encoded, offset + 4)[0]
            offset += 16 + program_len
        if offset > len(encoded):
            raise ValueError("truncated AIR component")
    if offset != len(encoded) or len(labels) != len(set(labels)):
        raise ValueError("invalid AIR component set")
    return labels
