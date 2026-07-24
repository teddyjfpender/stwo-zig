from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from typing import Any

from .identity import (
    CANONICAL_PIES,
    NAME_RE,
    SHAPE_SCHEMA,
    CoverageError,
    decode_adapted,
    exact_keys,
    json_bytes,
    load_json,
)


def _normalize_components(name: str, raw_components: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_components, list) or not raw_components:
        raise CoverageError(f"{name} shape components must be a non-empty array")
    components = []
    seen: set[str] = set()
    for index, component in enumerate(raw_components):
        context = f"{name} component[{index}]"
        if not isinstance(component, dict):
            raise CoverageError(f"{context} is not an object")
        exact_keys(
            component,
            {"component", "parts", "total_padded_rows"},
            context,
        )
        component_name = component["component"]
        if not isinstance(component_name, str) or not NAME_RE.fullmatch(component_name):
            raise CoverageError(f"{context} has invalid name: {component_name!r}")
        if component_name in seen:
            raise CoverageError(f"{name} repeats component {component_name}")
        seen.add(component_name)
        if not isinstance(component["parts"], list) or not component["parts"]:
            raise CoverageError(f"{context} parts must be a non-empty array")
        parts = []
        seen_parts: set[str] = set()
        for part_index, part in enumerate(component["parts"]):
            part_context = f"{context} part[{part_index}]"
            if not isinstance(part, dict):
                raise CoverageError(f"{part_context} is not an object")
            exact_keys(
                part,
                {"part", "n_real_rows", "padded_rows", "trace_log_size"},
                part_context,
            )
            part_name = part["part"]
            real = part["n_real_rows"]
            padded = part["padded_rows"]
            log_size = part["trace_log_size"]
            if not isinstance(part_name, str) or not part_name or part_name in seen_parts:
                raise CoverageError(f"{part_context} has invalid or duplicate part")
            seen_parts.add(part_name)
            if (
                type(real) is not int
                or type(padded) is not int
                or type(log_size) is not int
                or real <= 0
                or padded < real
                or padded & (padded - 1)
                or padded.bit_length() - 1 != log_size
            ):
                raise CoverageError(f"{part_context} has invalid row geometry")
            parts.append(
                {
                    "part": part_name,
                    "n_real_rows": real,
                    "padded_rows": padded,
                    "trace_log_size": log_size,
                }
            )
        parts.sort(key=lambda item: item["part"])
        total = sum(part["padded_rows"] for part in parts)
        if type(component["total_padded_rows"]) is not int or total != component[
            "total_padded_rows"
        ]:
            raise CoverageError(f"{context} total_padded_rows mismatch")
        components.append(
            {
                "component": component_name,
                "parts": parts,
                "total_padded_rows": total,
            }
        )
    components.sort(key=lambda item: item["component"])
    return components


def normalize_shape_report(name: str, path: Path) -> dict[str, Any]:
    raw = load_json(path)
    if not isinstance(raw, dict):
        raise CoverageError(f"{name} shape report is not an object")
    # Exact schemas ensure a PIE cannot smuggle a proof-selected semantic artifact.
    exact_keys(raw, {"schema_version", "input", "components"}, f"{name} shape report")
    if raw["schema_version"] != SHAPE_SCHEMA:
        raise CoverageError(f"{name} unsupported shape schema: {raw['schema_version']!r}")
    if not isinstance(raw["input"], str):
        raise CoverageError(f"{name} shape input is not a string")
    return {"name": name, "components": _normalize_components(name, raw["components"])}


def validate_normalized_shape_record(
    name: str, value: Any
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CoverageError(f"{name} normalized shape is not an object")
    exact_keys(value, {"name", "components"}, f"{name} normalized shape")
    if value["name"] != name:
        raise CoverageError(f"{name} normalized shape has name {value['name']!r}")
    normalized = {
        "name": name,
        "components": _normalize_components(name, value["components"]),
    }
    if normalized != value:
        raise CoverageError(f"{name} normalized shape ordering is not canonical")
    return normalized


def normalized_shape_sha256(value: dict[str, Any]) -> str:
    return hashlib.sha256(json_bytes(value)).hexdigest()


def capture_shape_reports(
    pies: dict[str, Path],
    work_dir: Path,
    gpu_bench: Path,
    kernel_emit: Path,
    *,
    reuse_sealed_adapted: bool,
) -> tuple[dict[str, Path], dict[str, Path]]:
    adapted: dict[str, Path] = {}
    shapes: dict[str, Path] = {}
    for name in CANONICAL_PIES:
        adapted[name] = work_dir / f"{name}.adapted.bin"
        shapes[name] = work_dir / f"{name}.shape.json"
        if reuse_sealed_adapted:
            decode_adapted(name, adapted[name])
        else:
            environment = os.environ.copy()
            environment["STWO_DUMP_INPUT"] = str(adapted[name])
            subprocess.run(
                [
                    str(gpu_bench),
                    "--pie",
                    str(pies[name]),
                    "--backend",
                    "simd",
                    "--adapt-only",
                    "--reps",
                    "1",
                ],
                check=True,
                env=environment,
            )
        shape = subprocess.run(
            [str(kernel_emit), "--shape-report-bincode", str(adapted[name])],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )
        shapes[name].write_text(shape.stdout, encoding="utf-8")
    return adapted, shapes
