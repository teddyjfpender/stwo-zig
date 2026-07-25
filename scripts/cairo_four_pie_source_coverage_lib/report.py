from __future__ import annotations

from pathlib import Path
from typing import Any

from .identity import (
    CANONICAL_PIES,
    DECODER_BINARY_IDENTITIES,
    DEFAULT_REPORT,
    MANIFEST_PATH,
    PIE_IDENTITIES,
    REPORT_FORMAT,
    REVISION_RE,
    SHAPE_IDENTITIES,
    SHAPE_SCHEMA,
    CoverageError,
    decode_adapted,
    decode_pie,
    exact_keys,
    json_bytes,
    load_json,
    validate_execution_resources,
)
from .shape import (
    normalize_shape_report,
    normalized_shape_sha256,
    validate_normalized_shape_record,
)
from .source import authenticate_source, load_semantic_registry


AUTHORITY = {
    "pie_role": "runtime_coverage_only",
    "component_names": "pinned_stwo_cairo_source_registry",
    "geometries": "sealed_pinned_stwo_cairo_shape_exporter",
    "semantics": "source_semantic_pack_only",
    "proof_selected_semantic_artifacts_allowed": False,
}


def _validate_decoder(decoder: dict[str, Any]) -> None:
    exact_keys(
        decoder,
        {
            "cairo_source",
            "stwo_source",
            "gpu_bench",
            "kernel_emit",
            "shape_schema",
            "shape_capture",
        },
        "decoder identity",
    )
    for source_name in ("cairo_source", "stwo_source"):
        source = decoder[source_name]
        exact_keys(
            source,
            {"revision", "tree", "clean", "dirty_paths"},
            f"decoder {source_name}",
        )
        for field in ("revision", "tree"):
            if not isinstance(source[field], str) or not REVISION_RE.fullmatch(
                source[field]
            ):
                raise CoverageError(f"decoder {source_name} {field} is not 40-hex")
        if type(source["clean"]) is not bool or not isinstance(
            source["dirty_paths"], list
        ):
            raise CoverageError(f"decoder {source_name} cleanliness is invalid")
    for binary_name in ("gpu_bench", "kernel_emit"):
        binary = decoder[binary_name]
        exact_keys(binary, {"bytes", "sha256"}, f"decoder {binary_name}")
        if (
            type(binary["bytes"]) is not int
            or binary["bytes"] <= 0
            or not isinstance(binary["sha256"], str)
            or len(binary["sha256"]) != 64
        ):
            raise CoverageError(f"decoder {binary_name} identity is invalid")
    if decoder["shape_schema"] != SHAPE_SCHEMA:
        raise CoverageError("decoder shape schema differs from the accepted schema")


def _blockers(
    source: dict[str, Any],
    decoder: dict[str, Any],
    reconciliation: list[dict[str, Any]],
) -> dict[str, list[Any]]:
    return {
        "decoder_binary_identity_mismatch": sorted(
            name
            for name, expected in DECODER_BINARY_IDENTITIES.items()
            if decoder[name] != expected
        ),
        "decoder_cairo_source_mismatch": (
            []
            if (
                decoder["cairo_source"]["revision"] == source["revision"]
                and decoder["cairo_source"]["tree"] == source["tree"]
            )
            else [
                {
                    "expected_revision": source["revision"],
                    "expected_tree": source["tree"],
                    "actual_revision": decoder["cairo_source"]["revision"],
                    "actual_tree": decoder["cairo_source"]["tree"],
                }
            ]
        ),
        "decoder_cairo_worktree_dirty": (
            []
            if decoder["cairo_source"]["clean"]
            else decoder["cairo_source"]["dirty_paths"]
        ),
        "decoder_stwo_revision_mismatch": (
            []
            if (
                decoder["stwo_source"]["revision"]
                == source["stwo_resolved_revision"]
                and decoder["stwo_source"]["tree"] == source["stwo_resolved_tree"]
            )
            else [
                {
                    "expected_revision": source["stwo_resolved_revision"],
                    "expected_tree": source["stwo_resolved_tree"],
                    "actual_revision": decoder["stwo_source"]["revision"],
                    "actual_tree": decoder["stwo_source"]["tree"],
                }
            ]
        ),
        "decoder_stwo_worktree_dirty": (
            []
            if decoder["stwo_source"]["clean"]
            else decoder["stwo_source"]["dirty_paths"]
        ),
        "shape_reports_not_gate_captured": (
            []
            if decoder["shape_capture"]
            == "gate_invoked_kernel_emit_on_sealed_adapted_inputs"
            else [decoder["shape_capture"]]
        ),
        "missing_source_writers": sorted(
            entry["name"]
            for entry in reconciliation
            if not entry["source_writer_present"]
        ),
        "non_rewritable_source_writers": sorted(
            entry["name"]
            for entry in reconciliation
            if entry["census_status"] != "rewritable"
        ),
        "missing_source_semantic_packs": sorted(
            entry["name"]
            for entry in reconciliation
            if not entry["semantic_pack_registered"]
        ),
    }


def build_report(
    pies: dict[str, Path],
    adapted: dict[str, Path],
    shapes: dict[str, Path],
    source_root: Path,
    census_path: Path,
    decoder: dict[str, Any],
) -> dict[str, Any]:
    _validate_decoder(decoder)
    manifest = load_json(MANIFEST_PATH)
    source, census = authenticate_source(source_root, manifest, census_path)
    semantic_source, semantic_registry = load_semantic_registry(manifest)
    pie_records = {name: decode_pie(name, pies[name]) for name in CANONICAL_PIES}
    shape_records = {
        name: normalize_shape_report(name, shapes[name]) for name in CANONICAL_PIES
    }
    for name in CANONICAL_PIES:
        shape_digest = normalized_shape_sha256(shape_records[name])
        if shape_digest != SHAPE_IDENTITIES[name]:
            raise CoverageError(
                f"{name} normalized shape identity mismatch: "
                f"expected {SHAPE_IDENTITIES[name]}, got {shape_digest}"
            )
        pie_records[name]["adapted"] = decode_adapted(name, adapted[name])
        pie_records[name]["normalized_shape_sha256"] = shape_digest
        pie_records[name]["components"] = shape_records[name]["components"]

    active = sorted(
        {
            component["component"]
            for shape in shape_records.values()
            for component in shape["components"]
        }
    )
    unknown = sorted(set(active) - set(census))
    if unknown:
        raise CoverageError(f"shape reports contain unknown source components: {unknown}")

    reconciliation = []
    for name in active:
        census_entry = census[name]
        semantic = semantic_registry.get(name)
        if (
            semantic is not None
            and semantic["artifact_sha256"] != census_entry["source_sha256"]
        ):
            raise CoverageError(
                f"{name} semantic artifact differs from pinned source"
            )
        census_oracle = (
            {
                "trace_columns": census_entry["trace_columns"],
                "lookup_words": census_entry["lookup_words"],
                "sub_input_words": census_entry["sub_input_words"],
            }
            if "trace_columns" in census_entry
            else None
        )
        reconciliation.append(
            {
                "name": name,
                "source_file_sha256": census_entry["source_sha256"],
                "source_writer_present": census_entry["source_writer_present"],
                "census_status": census_entry["status"],
                "census_oracle": census_oracle,
                "semantic_pack_registered": semantic is not None,
                "semantic_artifact_sha256": (
                    semantic["artifact_sha256"] if semantic is not None else None
                ),
            }
        )

    blockers = _blockers(source, decoder, reconciliation)
    return {
        "format": REPORT_FORMAT,
        "version": 1,
        "authority": AUTHORITY,
        "source": source,
        "semantic_registry": semantic_source,
        "decoder": decoder,
        "pies": [pie_records[name] for name in CANONICAL_PIES],
        "component_union": active,
        "reconciliation": reconciliation,
        "blockers": blockers,
        "source_coverage_admissible": not any(blockers.values()),
    }


def write_report(report: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(json_bytes(report))


def _validate_recorded_pies(pies: Any) -> list[str]:
    if not isinstance(pies, list) or len(pies) != len(CANONICAL_PIES):
        raise CoverageError("coverage report does not contain exactly four PIEs")
    union: set[str] = set()
    for expected_name, pie in zip(CANONICAL_PIES, pies, strict=True):
        if not isinstance(pie, dict):
            raise CoverageError(f"{expected_name} record is not an object")
        exact_keys(
            pie,
            {
                "name",
                "bytes",
                "sha256",
                "cairo_pie_version",
                "execution_resources",
                "role",
                "adapted",
                "normalized_shape_sha256",
                "components",
            },
            f"{expected_name} record",
        )
        if pie["name"] != expected_name or pie["role"] != "runtime_coverage_only":
            raise CoverageError(f"{expected_name} identity/role is stale")
        expected = PIE_IDENTITIES[expected_name]
        if (pie["bytes"], pie["sha256"]) != (
            expected["bytes"],
            expected["sha256"],
        ):
            raise CoverageError(f"{expected_name} input identity is stale")
        if pie["adapted"] != {
            "bytes": expected["adapted_bytes"],
            "sha256": expected["adapted_sha256"],
        }:
            raise CoverageError(f"{expected_name} adapted identity is stale")
        if pie["cairo_pie_version"] != "1.1":
            raise CoverageError(f"{expected_name} decoded metadata is invalid")
        validate_execution_resources(expected_name, pie["execution_resources"])
        normalized = validate_normalized_shape_record(
            expected_name,
            {"name": expected_name, "components": pie["components"]},
        )
        digest = normalized_shape_sha256(normalized)
        if (
            pie["normalized_shape_sha256"] != digest
            or digest != SHAPE_IDENTITIES[expected_name]
        ):
            raise CoverageError(f"{expected_name} normalized shape identity is stale")
        union.update(component["component"] for component in pie["components"])
    return sorted(union)


def verify_record(report: dict[str, Any], report_path: Path = DEFAULT_REPORT) -> None:
    if json_bytes(report) != report_path.read_bytes():
        raise CoverageError(f"{report_path} is not canonical JSON")
    exact_keys(
        report,
        {
            "format",
            "version",
            "authority",
            "source",
            "semantic_registry",
            "decoder",
            "pies",
            "component_union",
            "reconciliation",
            "blockers",
            "source_coverage_admissible",
        },
        "coverage report",
    )
    if report["format"] != REPORT_FORMAT or report["version"] != 1:
        raise CoverageError("unsupported coverage report")
    if report["authority"] != AUTHORITY:
        raise CoverageError("coverage authority boundary is stale")

    manifest = load_json(MANIFEST_PATH)
    manifest_source = manifest["source"]
    exact_keys(
        report["source"],
        {
            "repository",
            "revision",
            "tree",
            "stwo_binding_kind",
            "stwo_declared_revision",
            "stwo_resolved_revision",
            "stwo_resolved_tree",
            "component_count",
            "census",
        },
        "recorded source",
    )
    exact_keys(
        report["source"]["census"],
        {
            "files_scanned",
            "with_write_trace_simd",
            "rewritable",
            "trait_extension",
            "skipped",
            "bytes",
            "sha256",
        },
        "recorded source census",
    )
    for field in (
        "repository",
        "revision",
        "tree",
        "stwo_binding_kind",
        "stwo_declared_revision",
        "stwo_resolved_revision",
        "stwo_resolved_tree",
    ):
        if report["source"][field] != manifest_source[field]:
            raise CoverageError(f"report source {field} differs from source manifest")
    semantic_source, semantic_registry = load_semantic_registry(manifest)
    if report["semantic_registry"] != semantic_source:
        raise CoverageError("report semantic registry identity is stale")
    _validate_decoder(report["decoder"])

    union = _validate_recorded_pies(report["pies"])
    if union != report["component_union"]:
        raise CoverageError("recorded PIE union is stale")
    if not isinstance(report["reconciliation"], list):
        raise CoverageError("reconciliation is not an array")
    for entry in report["reconciliation"]:
        exact_keys(
            entry,
            {
                "name",
                "source_file_sha256",
                "source_writer_present",
                "census_status",
                "census_oracle",
                "semantic_pack_registered",
                "semantic_artifact_sha256",
            },
            f"reconciliation {entry.get('name')!r}",
        )
        oracle = entry["census_oracle"]
        if oracle is not None:
            exact_keys(
                oracle,
                {"trace_columns", "lookup_words", "sub_input_words"},
                f"reconciliation oracle {entry['name']}",
            )
    names = [entry["name"] for entry in report["reconciliation"]]
    if names != sorted(set(names)) or names != union:
        raise CoverageError("component union/reconciliation differ or are not canonical")

    blockers = _blockers(report["source"], report["decoder"], report["reconciliation"])
    if report["blockers"] != blockers:
        raise CoverageError("coverage blockers are stale")
    if report["source_coverage_admissible"] != (not any(blockers.values())):
        raise CoverageError("source_coverage_admissible does not match blockers")
    for entry in report["reconciliation"]:
        semantic = semantic_registry.get(entry["name"])
        if entry["semantic_pack_registered"] != (semantic is not None):
            raise CoverageError(
                f"{entry['name']} semantic-pack registration is stale"
            )
        expected_artifact = (
            semantic["artifact_sha256"] if semantic is not None else None
        )
        if entry["semantic_artifact_sha256"] != expected_artifact:
            raise CoverageError(f"{entry['name']} semantic artifact is stale")
