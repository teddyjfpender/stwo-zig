"""Pin and artifact validation for the official Cairo VM sidecar."""

from __future__ import annotations

import hashlib
import gzip
import io
import json
import tomllib
import zlib
from pathlib import Path


MANIFEST = "tools/stwo-cairo-vm-adapter-rs/Cargo.toml"
PROVENANCE = "vectors/cairo/programs/all_opcodes.provenance.json"
CORPUS_PROVENANCE = "vectors/cairo/programs/official_corpus.provenance.json"
EXECUTABLE_PROVENANCE = (
    "vectors/cairo/programs/executable/add_one.provenance.json"
)
ORACLE_GATE = "build_support/products/cairo/oracle_corpus.zig"
PROGRAM_SCHEMA = "stwo_cairo_compiled_program_vector_v1"
CORPUS_SCHEMA = "stwo_cairo_compiled_program_corpus_v1"
EXECUTABLE_SCHEMA = "stwo_cairo_executable_program_vector_v1"
EXECUTION_ADAPTER = "tools/stwo-cairo-vm-adapter-rs"
EXECUTION_LAYOUT = "all_cairo_stwo"
EXECUTION_PARAMS = "vectors/cairo/official/all_opcodes.params.json"
PIE_RESOURCES = "tools/stwo-cairo-vm-adapter-rs/resources"
RUNNER_REPOSITORY = "https://github.com/starkware-libs/proving"
RUNNER_REVISION = "5a7c5ede4299c91a61df19a07cba4f7502c14230"
BOOTLOADER_SHA256 = "f6d235eb6a7f97038105ed9b6e0e083b11def61c664a17fe157135f9615efc76"


def check(
    root: Path,
    *,
    cairo_repository: str,
    cairo_revision: str,
    stwo_repository: str,
    stwo_revision: str,
    cairo_language_repository: str,
    cairo_language_revision: str,
    cairo_language_version: str,
    cairo_vm_version: str,
) -> list[str]:
    errors = _check_manifest(
        root,
        cairo_repository=cairo_repository,
        cairo_revision=cairo_revision,
        stwo_repository=stwo_repository,
        stwo_revision=stwo_revision,
        cairo_language_version=cairo_language_version,
        cairo_vm_version=cairo_vm_version,
    )
    errors.extend(
        _check_program(
            root,
            cairo_repository=cairo_repository,
            cairo_revision=cairo_revision,
            cairo_vm_version=cairo_vm_version,
        )
    )
    errors.extend(
        _check_program_corpus(
            root,
            cairo_repository=cairo_repository,
            cairo_revision=cairo_revision,
            cairo_vm_version=cairo_vm_version,
        )
    )
    errors.extend(
        _check_executable(
            root,
            cairo_language_repository=cairo_language_repository,
            cairo_language_revision=cairo_language_revision,
            cairo_language_version=cairo_language_version,
            cairo_vm_version=cairo_vm_version,
        )
    )
    errors.extend(_check_pie_resources(root))
    return errors


def _check_manifest(
    root: Path,
    *,
    cairo_repository: str,
    cairo_revision: str,
    stwo_repository: str,
    stwo_revision: str,
    cairo_language_version: str,
    cairo_vm_version: str,
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
        "cairo-vm-version": cairo_vm_version,
        "cairo-language-version": cairo_language_version,
        "execution-runner-repository": RUNNER_REPOSITORY,
        "execution-runner-revision": RUNNER_REVISION,
        "pie-bootloader-sha256": BOOTLOADER_SHA256,
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
    runner = dependencies.get("cairo-program-runner-lib", {})
    if not isinstance(runner, dict) or runner.get("git") != RUNNER_REPOSITORY or runner.get("rev") != RUNNER_REVISION:
        errors.append(f"{MANIFEST}: PIE runner source pin drifted")
    if not isinstance(cairo_vm, dict) or cairo_vm.get("version") != f"={cairo_vm_version}":
        errors.append(
            f"{MANIFEST}: cairo-vm must be pinned exactly to '={cairo_vm_version}'"
        )
    for name in (
        "cairo-lang-executable",
        "cairo-lang-execute-utils",
        "cairo-lang-runner",
        "cairo-lang-utils",
    ):
        if dependencies.get(name) != f"={cairo_language_version}":
            errors.append(
                f"{MANIFEST}: {name} must be pinned exactly to "
                f"'={cairo_language_version}'"
            )
    for name, value in dependencies.items():
        if isinstance(value, dict) and "path" in value:
            errors.append(f"{MANIFEST}: path dependency {name!r} is forbidden")
    for key in ("patch", "replace"):
        if key in manifest:
            errors.append(f"{MANIFEST}: [{key}] is forbidden in the execution adapter")
    return errors


def _check_pie_resources(root: Path) -> list[str]:
    relative = f"{PIE_RESOURCES}/provenance.json"
    try:
        provenance = json.loads((root / relative).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"{relative}: unable to read PIE authority: {error}"]
    if not isinstance(provenance, dict):
        return [f"{relative}: PIE authority must be an object"]
    expected = {
        "schema": "stwo-zig-cairo-pie-execution-authority-v1",
        "source_repository": RUNNER_REPOSITORY,
        "source_revision": RUNNER_REVISION,
        "runner_crate": "cairo-program-runner-lib",
        "vm_version": "3.2.0",
        "layout": EXECUTION_LAYOUT,
        "task_program_hash": "blake",
        "bootloader_uncompressed_bytes": 25102387,
        "bootloader_uncompressed_sha256": BOOTLOADER_SHA256,
    }
    errors = [f"{relative}: {key} drifted" for key, value in expected.items()
              if provenance.get(key) != value]
    assets = provenance.get("assets", {})
    names = {"simple_bootloader_compiled.json.gz", "fibonacci_pie.zip"}
    if not isinstance(assets, dict) or set(assets) != names:
        return [*errors, f"{relative}: PIE asset roster drifted"]
    for name in sorted(names):
        try:
            data = (root / PIE_RESOURCES / name).read_bytes()
            artifact = assets[name]
            if artifact.get("bytes") != len(data) or artifact.get("sha256") != hashlib.sha256(data).hexdigest():
                errors.append(f"{relative}: asset {name} identity drifted")
            if name.endswith(".gz"):
                # Bound decompression even when inspecting a tampered asset.
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                    decoded = stream.read((32 << 20) + 1)
                if len(decoded) != expected["bootloader_uncompressed_bytes"] or hashlib.sha256(decoded).hexdigest() != BOOTLOADER_SHA256:
                    errors.append(f"{relative}: decoded bootloader identity drifted")
        except (OSError, EOFError, ValueError, TypeError, AttributeError, zlib.error) as error:
            errors.append(f"{relative}: unable to validate {name}: {error}")
    return errors


def _check_program(
    root: Path,
    *,
    cairo_repository: str,
    cairo_revision: str,
    cairo_vm_version: str,
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
    if execution.get("cairo_vm_version") != cairo_vm_version:
        errors.append(f"{PROVENANCE}: Cairo VM version drifted")
    if execution.get("layout") != "all_cairo_stwo":
        errors.append(f"{PROVENANCE}: execution layout drifted")
    return errors


def _check_program_corpus(
    root: Path,
    *,
    cairo_repository: str,
    cairo_revision: str,
    cairo_vm_version: str,
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
    if execution.get("cairo_vm_version") != cairo_vm_version:
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


def _check_executable(
    root: Path,
    *,
    cairo_language_repository: str,
    cairo_language_revision: str,
    cairo_language_version: str,
    cairo_vm_version: str,
) -> list[str]:
    try:
        provenance = json.loads(
            (root / EXECUTABLE_PROVENANCE).read_text(encoding="utf-8")
        )
        oracle_gate = (root / ORACLE_GATE).read_text(encoding="utf-8")
    except (OSError, json.JSONDecodeError) as error:
        return [f"{EXECUTABLE_PROVENANCE}: unable to load evidence: {error}"]

    errors: list[str] = []
    if provenance.get("schema") != EXECUTABLE_SCHEMA:
        errors.append(f"{EXECUTABLE_PROVENANCE}: schema drifted")
    compiler = provenance.get("compiler", {})
    expected_compiler = {
        "package": "cairo-execute",
        "version": cairo_language_version,
        "repository": cairo_language_repository,
        "revision": cairo_language_revision,
        "tag": f"v{cairo_language_version}",
    }
    for key, expected in expected_compiler.items():
        if compiler.get(key) != expected:
            errors.append(
                f"{EXECUTABLE_PROVENANCE}: compiler {key} drifted"
            )
    for label in ("source", "program", "arguments"):
        artifact = provenance.get(label, {})
        path = artifact.get("path")
        if (
            not isinstance(path, str)
            or Path(path).is_absolute()
            or ".." in Path(path).parts
        ):
            errors.append(
                f"{EXECUTABLE_PROVENANCE}: invalid {label} path"
            )
            continue
        try:
            data = (root / path).read_bytes()
        except OSError as error:
            errors.append(
                f"{EXECUTABLE_PROVENANCE}: unable to read {label}: {error}"
            )
            continue
        if artifact.get("bytes") != len(data):
            errors.append(
                f"{EXECUTABLE_PROVENANCE}: {label} byte length drifted"
            )
        if artifact.get("sha256") != hashlib.sha256(data).hexdigest():
            errors.append(f"{EXECUTABLE_PROVENANCE}: {label} digest drifted")
        if label != "source" and f'"{path}"' not in oracle_gate:
            errors.append(
                f"{EXECUTABLE_PROVENANCE}: {label} is absent from "
                f"{ORACLE_GATE}"
            )
    program = provenance.get("program", {})
    if program.get("entrypoint") != "Standalone":
        errors.append(f"{EXECUTABLE_PROVENANCE}: entrypoint drifted")
    if program.get("builtins") != ["output", "range_check"]:
        errors.append(f"{EXECUTABLE_PROVENANCE}: builtin list drifted")
    execution = provenance.get("execution", {})
    expected_execution = {
        "adapter": EXECUTION_ADAPTER,
        "cairo_language_version": cairo_language_version,
        "cairo_vm_version": cairo_vm_version,
        "layout": EXECUTION_LAYOUT,
        "params": EXECUTION_PARAMS,
    }
    for key, expected in expected_execution.items():
        if execution.get(key) != expected:
            errors.append(
                f"{EXECUTABLE_PROVENANCE}: execution {key} drifted"
            )
    if '"executable"' not in oracle_gate:
        errors.append(
            f"{EXECUTABLE_PROVENANCE}: executable type is absent from "
            f"{ORACLE_GATE}"
        )
    return errors
