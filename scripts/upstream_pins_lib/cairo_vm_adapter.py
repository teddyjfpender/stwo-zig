"""Pin and artifact validation for the official Cairo VM sidecar."""

from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path


MANIFEST = "tools/stwo-cairo-vm-adapter-rs/Cargo.toml"
PROVENANCE = "vectors/cairo/programs/all_opcodes.provenance.json"
CORPUS_PROVENANCE = "vectors/cairo/programs/official_corpus.provenance.json"
ORACLE_GATE = "build_support/products/cairo_cpu/oracle_gate.zig"
CAIRO_VM_VERSION = "3.2.0"
PROGRAM_SCHEMA = "stwo_cairo_compiled_program_vector_v1"
CORPUS_SCHEMA = "stwo_cairo_compiled_program_corpus_v1"
EXECUTION_ADAPTER = "tools/stwo-cairo-vm-adapter-rs"
EXECUTION_LAYOUT = "all_cairo_stwo"
EXECUTION_PARAMS = "vectors/cairo/official/all_opcodes.params.json"


def check(
    root: Path,
    *,
    cairo_repository: str,
    cairo_revision: str,
    stwo_repository: str,
    stwo_revision: str,
) -> list[str]:
    errors = _check_manifest(
        root,
        cairo_repository=cairo_repository,
        cairo_revision=cairo_revision,
        stwo_repository=stwo_repository,
        stwo_revision=stwo_revision,
    )
    errors.extend(
        _check_program(
            root,
            cairo_repository=cairo_repository,
            cairo_revision=cairo_revision,
        )
    )
    errors.extend(
        _check_program_corpus(
            root,
            cairo_repository=cairo_repository,
            cairo_revision=cairo_revision,
        )
    )
    return errors


def _check_manifest(
    root: Path,
    *,
    cairo_repository: str,
    cairo_revision: str,
    stwo_repository: str,
    stwo_revision: str,
) -> list[str]:
    try:
        with (root / MANIFEST).open("rb") as handle:
            manifest = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"{MANIFEST}: unable to parse manifest: {error}"]
    metadata = (
        manifest.get("package", {})
        .get("metadata", {})
        .get("official-execution-adapter", {})
    )
    expected_metadata = {
        "stwo-cairo-repository": cairo_repository,
        "stwo-cairo-revision": cairo_revision,
        "stwo-repository": stwo_repository,
        "stwo-revision": stwo_revision,
        "cairo-vm-version": CAIRO_VM_VERSION,
    }
    errors = [
        f"{MANIFEST}: metadata {key!r} is {metadata.get(key)!r}, expected {expected!r}"
        for key, expected in expected_metadata.items()
        if metadata.get(key) != expected
    ]
    dependencies = manifest.get("dependencies", {})
    adapter = dependencies.get("stwo-cairo-adapter")
    if not isinstance(adapter, dict):
        errors.append(f"{MANIFEST}: missing table dependency 'stwo-cairo-adapter'")
    elif adapter.get("git") != cairo_repository or adapter.get("rev") != cairo_revision:
        errors.append(
            f"{MANIFEST}: dependency 'stwo-cairo-adapter' is "
            f"{adapter.get('git')!r}@{adapter.get('rev')!r}, "
            f"expected {cairo_repository!r}@{cairo_revision!r}"
        )
    cairo_vm = dependencies.get("cairo-vm")
    if not isinstance(cairo_vm, dict) or cairo_vm.get("version") != f"={CAIRO_VM_VERSION}":
        errors.append(
            f"{MANIFEST}: cairo-vm must be pinned exactly to '={CAIRO_VM_VERSION}'"
        )
    for name, value in dependencies.items():
        if isinstance(value, dict) and "path" in value:
            errors.append(f"{MANIFEST}: path dependency {name!r} is forbidden")
    for key in ("patch", "replace"):
        if key in manifest:
            errors.append(f"{MANIFEST}: [{key}] is forbidden in the execution adapter")
    return errors


def _check_program(
    root: Path,
    *,
    cairo_repository: str,
    cairo_revision: str,
) -> list[str]:
    try:
        provenance = json.loads((root / PROVENANCE).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"{PROVENANCE}: unable to parse provenance: {error}"]
    errors: list[str] = []
    if provenance.get("schema") != PROGRAM_SCHEMA:
        errors.append(f"{PROVENANCE}: schema drifted")
    source = provenance.get("source", {})
    if source.get("repository") != cairo_repository:
        errors.append(f"{PROVENANCE}: source repository drifted")
    if source.get("revision") != cairo_revision:
        errors.append(f"{PROVENANCE}: source revision drifted")
    program = provenance.get("program", {})
    path = program.get("path")
    if not isinstance(path, str) or Path(path).is_absolute() or ".." in Path(path).parts:
        return [*errors, f"{PROVENANCE}: invalid program path"]
    try:
        data = (root / path).read_bytes()
    except OSError as error:
        return [*errors, f"{PROVENANCE}: unable to read program: {error}"]
    if program.get("bytes") != len(data):
        errors.append(f"{PROVENANCE}: program byte length drifted")
    if program.get("sha256") != hashlib.sha256(data).hexdigest():
        errors.append(f"{PROVENANCE}: program digest drifted")
    execution = provenance.get("execution", {})
    if execution.get("cairo_vm_version") != CAIRO_VM_VERSION:
        errors.append(f"{PROVENANCE}: Cairo VM version drifted")
    if execution.get("layout") != "all_cairo_stwo":
        errors.append(f"{PROVENANCE}: execution layout drifted")
    return errors


def _check_program_corpus(
    root: Path,
    *,
    cairo_repository: str,
    cairo_revision: str,
) -> list[str]:
    try:
        provenance = json.loads(
            (root / CORPUS_PROVENANCE).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        return [f"{CORPUS_PROVENANCE}: unable to parse provenance: {error}"]

    errors: list[str] = []
    if provenance.get("schema") != CORPUS_SCHEMA:
        errors.append(f"{CORPUS_PROVENANCE}: schema drifted")
    source = provenance.get("source", {})
    if source.get("repository") != cairo_repository:
        errors.append(f"{CORPUS_PROVENANCE}: source repository drifted")
    if source.get("revision") != cairo_revision:
        errors.append(f"{CORPUS_PROVENANCE}: source revision drifted")

    execution = provenance.get("execution", {})
    if execution.get("adapter") != EXECUTION_ADAPTER:
        errors.append(f"{CORPUS_PROVENANCE}: execution adapter drifted")
    if execution.get("cairo_vm_version") != CAIRO_VM_VERSION:
        errors.append(f"{CORPUS_PROVENANCE}: Cairo VM version drifted")
    if execution.get("layout") != EXECUTION_LAYOUT:
        errors.append(f"{CORPUS_PROVENANCE}: execution layout drifted")
    if execution.get("params") != EXECUTION_PARAMS:
        errors.append(f"{CORPUS_PROVENANCE}: proving profile drifted")
    try:
        oracle_gate = (root / ORACLE_GATE).read_text(encoding="utf-8")
    except OSError as error:
        return [*errors, f"{ORACLE_GATE}: unable to read release gate: {error}"]

    programs = provenance.get("programs")
    if not isinstance(programs, list) or not programs:
        return [*errors, f"{CORPUS_PROVENANCE}: programs must be a non-empty list"]
    seen_cases: set[str] = set()
    seen_paths: set[str] = set()
    seen_source_paths: set[str] = set()
    for index, program in enumerate(programs):
        label = f"{CORPUS_PROVENANCE}: programs[{index}]"
        if not isinstance(program, dict):
            errors.append(f"{label} must be an object")
            continue
        case = program.get("case")
        if not isinstance(case, str) or not case:
            errors.append(f"{label}: invalid case")
        elif case in seen_cases:
            errors.append(f"{label}: duplicate case {case!r}")
        else:
            seen_cases.add(case)

        source_path = program.get("source_path")
        if (
            not isinstance(source_path, str)
            or Path(source_path).is_absolute()
            or ".." in Path(source_path).parts
            or not source_path.startswith("test_data/")
            or not source_path.endswith("/compiled.json")
        ):
            errors.append(f"{label}: invalid source path")
        elif source_path in seen_source_paths:
            errors.append(f"{label}: duplicate source path {source_path!r}")
        else:
            seen_source_paths.add(source_path)

        path = program.get("path")
        if (
            not isinstance(path, str)
            or Path(path).is_absolute()
            or ".." in Path(path).parts
        ):
            errors.append(f"{label}: invalid program path")
            continue
        if path in seen_paths:
            errors.append(f"{label}: duplicate program path {path!r}")
            continue
        seen_paths.add(path)
        if f'"{path}"' not in oracle_gate:
            errors.append(f"{label}: program is absent from {ORACLE_GATE}")
        try:
            data = (root / path).read_bytes()
        except OSError as error:
            errors.append(f"{label}: unable to read program: {error}")
            continue
        if program.get("bytes") != len(data):
            errors.append(f"{label}: program byte length drifted")
        if program.get("sha256") != hashlib.sha256(data).hexdigest():
            errors.append(f"{label}: program digest drifted")
    return errors
