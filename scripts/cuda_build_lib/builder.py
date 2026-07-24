"""Deterministic direct builder for the imported Stwo CUDA/C++ sources."""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .aot_identity import validate_native_aot_identity
from .aot_pack import ABI_SCHEMAS, AotPackError, write_aot_carriers, write_aot_pack
from .errors import BuildError
from .native_closure import load_native_closure


SCHEMA = "stwo-zig-cuda-native-build-v1"
ARCHIVE_NAME = "libstwo_cuda_kernels.a"
RECEIPT_NAME = "cuda_build_receipt.json"
PLAN_NAME = "cuda_build_plan.json"
AOT_PACK_NAME = "cuda_aot_pack.bin"
GENERATED = "generated"
SM_RE = re.compile(r"^(?:sm_)?([1-9][0-9])$")
IDENTITY_64_RE = re.compile(r"^[0-9a-f]{16}$")
IDENTITY_256_RE = re.compile(r"^[0-9a-f]{64}$")
KERNEL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
LABEL_RE = re.compile(r"^[a-z0-9_]+$")
ORDINARY_FIXED_FLAGS = (
    "-dc",
    "-O3",
    "--std=c++17",
    "--expt-relaxed-constexpr",
    "-Xcompiler",
    "-fPIC",
)
NATIVE_CUDA_FIXED_FLAGS = (
    "-c",
    "-O3",
    "--std=c++17",
    "--expt-relaxed-constexpr",
    "-Xcompiler",
    "-fPIC",
)


@dataclass(frozen=True)
class Toolchain:
    nvcc: Path
    host_cxx: Path
    archiver: Path
    cuda_home: Path
    cuda_library_dir: Path
    sms: tuple[int, ...]
    jobs: int


@dataclass(frozen=True)
class SourceClosure:
    root: Path
    manifest_path: Path
    closure_sha256: str
    ordinary_sources: tuple[Path, ...]
    generated_sources: tuple[Path, ...]
    include_dirs: tuple[Path, ...]
    aot_manifest: tuple[dict[str, object], ...]


@dataclass(frozen=True)
class BuildConfig:
    source_root: Path
    source_manifest: Path
    product_manifest: Path
    native_root: Path
    native_aot_root: Path
    output_dir: Path
    toolchain: Toolchain


@dataclass(frozen=True)
class ProductSelection:
    manifest_sha256: str
    ordinary_sources: tuple[Path, ...]
    aot_sources: tuple[Path, ...]
    aot_manifest: tuple[dict[str, object], ...]
    aot_closure_sha256: str


def normalize_sms(values: Iterable[str]) -> tuple[int, ...]:
    result: set[int] = set()
    for raw in values:
        for value in raw.split(","):
            match = SM_RE.fullmatch(value.strip())
            if match is None:
                raise BuildError(
                    f"invalid CUDA architecture {value!r}; use an explicit numeric SM"
                )
            result.add(int(match.group(1)))
    if not result:
        raise BuildError("at least one explicit CUDA architecture is required")
    return tuple(sorted(result))


def load_product_selection(
    config: BuildConfig,
    authority: SourceClosure,
) -> ProductSelection:
    try:
        payload = config.product_manifest.read_bytes()
        product = json.loads(payload)
    except (OSError, json.JSONDecodeError) as error:
        raise BuildError(f"cannot read CUDA product manifest: {error}") from error
    if product.get("schema") != "stwo-zig-cuda-product-closure-v1":
        raise BuildError("unsupported CUDA product-closure manifest")
    if product.get("source_authority_sha256") != authority.closure_sha256:
        raise BuildError("CUDA product selection is stale against its source authority")
    ordinary = product.get("ordinary")
    if not isinstance(ordinary, dict):
        raise BuildError("CUDA product ordinary source selection is absent")
    selected = ordinary.get("product_sources")
    candidates = ordinary.get("resident_candidates")
    if (
        not isinstance(selected, list)
        or selected != sorted(set(selected))
        or not isinstance(candidates, list)
        or candidates != sorted(set(candidates))
        or not set(selected).issubset(candidates)
    ):
        raise BuildError("CUDA product sources must be a sorted candidate subset")
    ordinary_sources = tuple(authority.root / str(path) for path in selected)
    if any(not path.is_file() for path in ordinary_sources):
        raise BuildError("CUDA resident source selection names an absent authority file")

    aot_root = config.native_aot_root.resolve()
    aot_manifest_path = aot_root / "aot_manifest.json"
    try:
        aot_manifest = json.loads(aot_manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BuildError(f"cannot read Native AOT manifest: {error}") from error
    validate_aot_manifest(aot_root, aot_manifest, allow_empty=True)
    aot_sources = tuple(aot_root / str(entry["file"]) for entry in aot_manifest)
    aot_closure = hashlib.sha256()
    manifest_payload = canonical_json_bytes(aot_manifest)
    aot_closure.update(len(manifest_payload).to_bytes(8, "little"))
    aot_closure.update(manifest_payload)
    for source in aot_sources:
        relative = source.relative_to(aot_root).as_posix().encode("utf-8")
        source_payload = source.read_bytes()
        aot_closure.update(len(relative).to_bytes(8, "little"))
        aot_closure.update(relative)
        aot_closure.update(len(source_payload).to_bytes(8, "little"))
        aot_closure.update(source_payload)
    return ProductSelection(
        manifest_sha256=hashlib.sha256(payload).hexdigest(),
        ordinary_sources=ordinary_sources,
        aot_sources=aot_sources,
        aot_manifest=tuple(aot_manifest),
        aot_closure_sha256=aot_closure.hexdigest(),
    )


def load_source_closure(source_root: Path, manifest_path: Path) -> SourceClosure:
    source_root = source_root.resolve()
    manifest_path = manifest_path.resolve()
    try:
        expected = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BuildError(f"cannot read CUDA source manifest: {error}") from error
    if expected.get("schema") != "stwo-zig-cuda-source-closure-v1":
        raise BuildError("unsupported CUDA source-closure manifest")
    if expected.get("authority") != "kernels":
        raise BuildError("CUDA builder requires the pinned kernel authority")

    files = sorted(path for path in source_root.rglob("*") if path.is_file())
    if not files:
        raise BuildError(f"CUDA source closure is empty: {source_root}")
    if any(path.is_symlink() for path in source_root.rglob("*")):
        raise BuildError("CUDA source closure must not contain symlinks")

    entries: list[dict[str, object]] = []
    closure = hashlib.sha256()
    byte_count = 0
    for path in files:
        relative = path.relative_to(source_root).as_posix()
        payload = path.read_bytes()
        encoded_path = relative.encode("utf-8")
        closure.update(len(encoded_path).to_bytes(8, "little"))
        closure.update(encoded_path)
        closure.update(len(payload).to_bytes(8, "little"))
        closure.update(payload)
        byte_count += len(payload)
        entries.append(
            {
                "path": relative,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    actual = {
        "schema": expected["schema"],
        "authority": expected["authority"],
        "upstream": expected["upstream"],
        "file_count": len(entries),
        "byte_count": byte_count,
        "closure_sha256": closure.hexdigest(),
        "files": entries,
    }
    if actual != expected:
        raise BuildError("imported CUDA sources differ from the pinned source manifest")

    ordinary = tuple(
        path
        for path in files
        if path.suffix == ".cu" and GENERATED not in path.relative_to(source_root).parts
    )
    generated_dir = source_root / GENERATED
    aot_manifest_path = generated_dir / "aot_manifest.json"
    try:
        aot_manifest = json.loads(aot_manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BuildError(f"cannot read copied AOT manifest: {error}") from error
    validate_aot_manifest(generated_dir, aot_manifest)
    generated = tuple(generated_dir / str(entry["file"]) for entry in aot_manifest)
    include_dirs = tuple(
        sorted({source_root, *(path for path in source_root.rglob("*") if path.is_dir())})
    )
    return SourceClosure(
        root=source_root,
        manifest_path=manifest_path,
        closure_sha256=actual["closure_sha256"],
        ordinary_sources=ordinary,
        generated_sources=generated,
        include_dirs=include_dirs,
        aot_manifest=tuple(aot_manifest),
    )


def validate_aot_manifest(
    generated_dir: Path,
    manifest: object,
    allow_empty: bool = False,
) -> None:
    if not isinstance(manifest, list) or (not manifest and not allow_empty):
        raise BuildError("AOT manifest must be an array with the required entries")
    seen_files: set[str] = set()
    seen_keys: set[int] = set()
    previous: tuple[str, str, int] | None = None
    required = {
        "kind",
        "label",
        "abi_schema",
        "kernel_name",
        "cache_key",
        "semantic_hash",
        "program_identity",
        "file",
    }
    for index, raw in enumerate(manifest):
        if not isinstance(raw, dict) or not required.issubset(raw):
            raise BuildError(f"AOT manifest entry {index} is incomplete")
        kind = str(raw["kind"])
        label = str(raw["label"])
        abi_schema = str(raw["abi_schema"])
        kernel_name = str(raw["kernel_name"])
        cache_key_hex = str(raw["cache_key"])
        semantic_hash = str(raw["semantic_hash"])
        program_identity = str(raw["program_identity"])
        file_name = str(raw["file"])
        if kind not in {"constraint", "witness"}:
            raise BuildError(f"AOT manifest entry {index} has invalid kind")
        if abi_schema not in ABI_SCHEMAS:
            raise BuildError(f"AOT manifest entry {index} has invalid ABI schema")
        if (
            LABEL_RE.fullmatch(label) is None
            or KERNEL_RE.fullmatch(kernel_name) is None
            or IDENTITY_64_RE.fullmatch(cache_key_hex) is None
            or IDENTITY_64_RE.fullmatch(semantic_hash) is None
            or IDENTITY_256_RE.fullmatch(program_identity) is None
        ):
            raise BuildError(f"AOT manifest entry {index} has invalid identity syntax")
        try:
            cache_key = int(cache_key_hex, 16)
            semantic_key = int(semantic_hash, 16)
        except ValueError as error:
            raise BuildError(f"AOT manifest entry {index} has invalid hex identity") from error
        if cache_key == 0 or semantic_key == 0:
            raise BuildError(f"AOT manifest entry {index} has a zero identity")
        expected_name = f"{kind}_{label}_{cache_key:016x}.cu"
        if (
            file_name != expected_name
            or Path(file_name).name != file_name
            or file_name in seen_files
            or cache_key in seen_keys
        ):
            raise BuildError(f"AOT manifest entry {index} is non-canonical")
        order = (kind, label, cache_key)
        if previous is not None and previous >= order:
            raise BuildError("AOT manifest order is not canonical")
        if not (generated_dir / file_name).is_file():
            raise BuildError(f"copied AOT source is absent: {file_name}")
        validate_native_aot_identity(generated_dir, raw, required, index)
        previous = order
        seen_files.add(file_name)
        seen_keys.add(cache_key)
    copied = {path.name for path in generated_dir.glob("*.cu")}
    if copied != seen_files:
        raise BuildError("copied generated CUDA sources do not match the AOT manifest")


def build_plan(config: BuildConfig, probe_tools: bool) -> dict[str, object]:
    closure = load_source_closure(config.source_root, config.source_manifest)
    product = load_product_selection(config, closure)
    native = load_native_closure(config.native_root)
    toolchain = config.toolchain
    if probe_tools:
        for label, directory in (
            ("CUDA toolkit", toolchain.cuda_home),
            ("CUDA library", toolchain.cuda_library_dir),
        ):
            if not directory.is_dir():
                raise BuildError(f"explicit {label} directory is absent: {directory}")
    tools: dict[str, object] = {
        "nvcc": tool_record(toolchain.nvcc, ("--version",), probe_tools),
        "host_cxx": tool_record(toolchain.host_cxx, ("--version",), probe_tools),
        "archiver": tool_record(toolchain.archiver, ("--version",), probe_tools),
    }
    fixed = {
        "ordinary": list(ORDINARY_FIXED_FLAGS),
        "native_cuda": list(NATIVE_CUDA_FIXED_FLAGS),
        "aot": ["-cubin", "-O3", "--std=c++17", "--expt-relaxed-constexpr"],
        "device_link": ["-dlink", "-Xcompiler", "-fPIC"],
        "host": ["-std=c++17", "-O3", "-fPIC", "-c"],
    }
    identity_input = {
        "schema": SCHEMA,
        "source_closure_sha256": closure.closure_sha256,
        "product_manifest_sha256": product.manifest_sha256,
        "native_runtime_closure_sha256": native["closure_sha256"],
        "native_aot_closure_sha256": product.aot_closure_sha256,
        "tools": tools,
        "target_sms": list(toolchain.sms),
        "fixed_flags": fixed,
    }
    build_identity = digest_json(identity_input)
    return {
        **identity_input,
        "build_identity_sha256": build_identity,
        "authority_ordinary_source_count": len(closure.ordinary_sources),
        "authority_aot_source_count": len(closure.generated_sources),
        "ordinary_source_count": len(product.ordinary_sources),
        "aot_source_count": len(product.aot_sources),
        "aot_cubin_count": len(product.aot_sources) * len(toolchain.sms),
        "native_runtime_source_count": len(native["sources"]),
        "native_host_source_count": len(native["host_sources"]),
        "native_cuda_source_count": len(native["cuda_sources"]),
        "native_runtime_files": native["files"],
        "include_dirs": [str(path) for path in closure.include_dirs],
        "cuda_home": str(toolchain.cuda_home),
        "cuda_library_dir": str(toolchain.cuda_library_dir),
        "jobs": toolchain.jobs,
    }


def tool_record(path: Path, version_args: Sequence[str], probe: bool) -> dict[str, object]:
    resolved = path.expanduser()
    if not probe:
        return {"path": str(resolved), "sha256": "plan-only", "version": "plan-only"}
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise BuildError(f"required CUDA build tool is not executable: {resolved}")
    try:
        completed = subprocess.run(
            [str(resolved), *version_args],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        raise BuildError(f"cannot query build tool {resolved}: {error.stderr}") from error
    version = (completed.stdout + completed.stderr).strip()
    return {
        "path": str(resolved.resolve()),
        "sha256": sha256_file(resolved),
        "version": version,
    }


def execute(config: BuildConfig) -> dict[str, object]:
    plan = build_plan(config, probe_tools=True)
    closure = load_source_closure(config.source_root, config.source_manifest)
    product = load_product_selection(config, closure)
    output = config.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    archive = output / ARCHIVE_NAME
    receipt_path = output / RECEIPT_NAME
    if archive.is_file() and receipt_path.is_file():
        previous = json.loads(receipt_path.read_text(encoding="utf-8"))
        if previous.get("build_identity_sha256") == plan["build_identity_sha256"]:
            if previous.get("archive_sha256") == sha256_file(archive):
                print(f"reused CUDA archive {archive}")
                return previous

    work = output / ".work" / str(plan["build_identity_sha256"])
    objects = work / "objects"
    cubins = work / "cubins"
    generated = work / "generated"
    for directory in (objects, cubins, generated):
        directory.mkdir(parents=True, exist_ok=True)

    ordinary_objects = compile_ordinary(
        config,
        closure,
        product.ordinary_sources,
        plan,
        objects,
    )
    native_cuda_objects = compile_native_cuda(
        config,
        closure,
        plan,
        objects,
    )
    dlink = (
        device_link(config, plan, ordinary_objects, work)
        if ordinary_objects
        else None
    )
    aot_entries = compile_aot(config, product, plan, cubins)
    aot_pack = generated / AOT_PACK_NAME
    try:
        write_aot_pack(aot_entries, aot_pack)
    except AotPackError as error:
        raise BuildError(str(error)) from error
    aot_sources = write_aot_carriers(aot_entries, aot_pack, generated)
    aot_objects = [
        compile_host(config.toolchain.host_cxx, source, generated)
        for source in aot_sources
    ]
    identity_source = write_build_identity_carrier(
        str(plan["build_identity_sha256"]), generated
    )
    identity_object = compile_host(
        config.toolchain.host_cxx, identity_source, generated
    )
    native_objects = compile_native_runtime(config, plan, generated)

    staged_archive = work / f"{ARCHIVE_NAME}.staged"
    run(
        [
            str(config.toolchain.archiver),
            "crs",
            str(staged_archive),
            *(str(path) for path in ordinary_objects),
            *(str(path) for path in native_cuda_objects),
            *([str(dlink)] if dlink is not None else []),
            *(str(path) for path in aot_objects),
            str(identity_object),
            *(str(path) for path in native_objects),
        ]
    )
    if not staged_archive.is_file() or staged_archive.stat().st_size == 0:
        raise BuildError("CUDA archive publication produced no bytes")
    if load_source_closure(config.source_root, config.source_manifest) != closure:
        raise BuildError("CUDA source closure changed during compilation; retry")

    publish(staged_archive, archive)
    publish(aot_pack, output / AOT_PACK_NAME)
    receipt = {
        **plan,
        "archive": ARCHIVE_NAME,
        "archive_sha256": sha256_file(archive),
        "aot_pack": AOT_PACK_NAME,
        "aot_pack_sha256": sha256_file(output / AOT_PACK_NAME),
        "aot_entries": len(aot_entries),
        "linked_libraries": ["cuda", "cudart", "stdc++"],
    }
    atomic_write(output / PLAN_NAME, json_bytes(plan))
    atomic_write(receipt_path, json_bytes(receipt))
    print(
        f"built {archive}: {len(ordinary_objects)} authority CUDA objects, "
        f"{len(native_cuda_objects)} Native CUDA objects, "
        f"{len(aot_entries)} AOT cubins"
    )
    return receipt


def compile_ordinary(
    config: BuildConfig,
    closure: SourceClosure,
    sources: Sequence[Path],
    plan: dict[str, object],
    output: Path,
) -> list[Path]:
    toolchain = config.toolchain
    include_flags = [
        flag
        for directory in closure.include_dirs
        for flag in ("-I", str(directory))
    ]
    gencode = [
        flag
        for sm in toolchain.sms
        for flag in ("-gencode", f"arch=compute_{sm},code=sm_{sm}")
    ]
    prefix = [
        str(toolchain.nvcc),
        *ORDINARY_FIXED_FLAGS,
        f"-ccbin={toolchain.host_cxx}",
        *include_flags,
        *gencode,
    ]
    context = digest_json(
        {
            "build": plan["build_identity_sha256"],
            "mode": "ordinary",
            "argv": prefix[1:],
        }
    )
    jobs: list[tuple[list[str], Path]] = []
    results: list[Path] = []
    for source in sources:
        key = hashlib.sha256(
            f"{context}:{sha256_file(source)}".encode("ascii")
        ).hexdigest()[:24]
        destination = output / f"{source.stem}-{key}.o"
        results.append(destination)
        if not destination.is_file():
            jobs.append(([*prefix, str(source), "-o", str(destination)], destination))
    run_parallel(jobs, toolchain.jobs)
    return results


def compile_native_cuda(
    config: BuildConfig,
    closure: SourceClosure,
    plan: dict[str, object],
    output: Path,
) -> list[Path]:
    native = load_native_closure(config.native_root)
    sources = native["cuda_sources"]
    toolchain = config.toolchain
    include_dirs = {
        config.native_root.resolve(),
        *closure.include_dirs,
    }
    include_flags = [
        flag
        for directory in sorted(include_dirs)
        for flag in ("-I", str(directory))
    ]
    gencode = [
        flag
        for sm in toolchain.sms
        for flag in ("-gencode", f"arch=compute_{sm},code=sm_{sm}")
    ]
    prefix = [
        str(toolchain.nvcc),
        *NATIVE_CUDA_FIXED_FLAGS,
        f"-ccbin={toolchain.host_cxx}",
        *include_flags,
        *gencode,
    ]
    context = digest_json(
        {
            "build": plan["build_identity_sha256"],
            "mode": "native_cuda",
            "argv": prefix[1:],
        }
    )
    jobs: list[tuple[list[str], Path]] = []
    results: list[Path] = []
    for source in sources:
        key = hashlib.sha256(
            f"{context}:{sha256_file(source)}".encode("ascii")
        ).hexdigest()[:24]
        destination = output / f"native_{source.stem}-{key}.o"
        results.append(destination)
        if not destination.is_file():
            jobs.append(([*prefix, str(source), "-o", str(destination)], destination))
    run_parallel(jobs, toolchain.jobs)
    return results


def device_link(
    config: BuildConfig,
    plan: dict[str, object],
    objects: Sequence[Path],
    output: Path,
) -> Path:
    destination = output / "stwo_cuda_kernels_dlink.o"
    command = [
        str(config.toolchain.nvcc),
        "-dlink",
        "-Xcompiler",
        "-fPIC",
        f"-ccbin={config.toolchain.host_cxx}",
        *(
            flag
            for sm in config.toolchain.sms
            for flag in ("-gencode", f"arch=compute_{sm},code=sm_{sm}")
        ),
        *(str(path) for path in objects),
        "-o",
        str(destination),
    ]
    stamp = destination.with_suffix(".json")
    command_identity = digest_json(
        {"build": plan["build_identity_sha256"], "command": command[1:]}
    )
    if not stamped_artifact_current(destination, stamp, command_identity):
        run(command)
        atomic_write(stamp, json_bytes({"identity": command_identity}))
    return destination


def compile_aot(
    config: BuildConfig,
    product: ProductSelection,
    plan: dict[str, object],
    output: Path,
) -> list[dict[str, object]]:
    source_by_name = {path.name: path for path in product.aot_sources}
    jobs: list[tuple[list[str], Path]] = []
    entries: list[dict[str, object]] = []
    for metadata in product.aot_manifest:
        source = source_by_name[str(metadata["file"])]
        for sm in config.toolchain.sms:
            key = hashlib.sha256(
                (
                    f"{plan['build_identity_sha256']}:aot:{sm}:"
                    f"{sha256_file(source)}"
                ).encode("ascii")
            ).hexdigest()[:24]
            destination = output / f"{source.stem}-sm_{sm}-{key}.cubin"
            command = aot_compile_command(config.toolchain, source, destination, sm)
            if not destination.is_file():
                jobs.append((command, destination))
            entries.append(
                {
                    "cache_key": int(str(metadata["cache_key"]), 16),
                    "sm": sm,
                    "kernel_name": str(metadata["kernel_name"]),
                    "abi_schema": ABI_SCHEMAS[str(metadata["abi_schema"])],
                    "source": source.name,
                    "cubin": destination,
                }
            )
    run_parallel(jobs, config.toolchain.jobs)
    entries.sort(key=lambda entry: (entry["cache_key"], entry["sm"]))
    return entries


def aot_compile_command(
    toolchain: Toolchain, source: Path, destination: Path, sm: int
) -> list[str]:
    command = [
        str(toolchain.nvcc),
        "-cubin",
        "-O3",
        "--std=c++17",
        "--expt-relaxed-constexpr",
        f"-ccbin={toolchain.host_cxx}",
        f"-arch=sm_{sm}",
    ]
    if (
        sm == 90
        and source.stem.startswith("witness_poseidon_3_partial_rounds_chain_")
    ):
        command.append("-Xptxas=-O0")
    command.extend((str(source), "-o", str(destination)))
    return command


def write_build_identity_carrier(identity: str, output: Path) -> Path:
    destination = output / "cuda_build_identity.cc"
    digest = bytes.fromhex(identity)
    values = ", ".join(f"0x{byte:02x}" for byte in digest)
    source = f"""#include <cstdint>
#include <cstring>

namespace {{
constexpr std::uint8_t kBuildIdentity[32] = {{{values}}};
}}

extern "C" int stwo_static_cuda_module_build_identity(std::uint8_t *out) {{
    if (out == nullptr) return 1;
    std::memcpy(out, kBuildIdentity, sizeof(kBuildIdentity));
    return 0;
}}
"""
    atomic_write(destination, source.encode("utf-8"))
    return destination


def compile_host(compiler: Path, source: Path, output: Path) -> Path:
    destination = output / f"{source.stem}.o"
    command = [
        str(compiler),
        "-std=c++17",
        "-O3",
        "-fPIC",
        "-c",
        str(source),
        "-o",
        str(destination),
    ]
    identity = digest_json(
        {"command": command[1:], "source_sha256": sha256_file(source)}
    )
    stamp = destination.with_suffix(".json")
    if not stamped_artifact_current(destination, stamp, identity):
        run(command)
        atomic_write(stamp, json_bytes({"identity": identity}))
    return destination


def compile_native_runtime(
    config: BuildConfig,
    plan: dict[str, object],
    output: Path,
) -> list[Path]:
    native = load_native_closure(config.native_root)
    include_flags = [
        "-I",
        str(config.native_root.resolve()),
        "-I",
        str((config.toolchain.cuda_home / "include").resolve()),
    ]
    results: list[Path] = []
    for source in native["host_sources"]:
        destination = output / f"native_{source.stem}.o"
        command = [
            str(config.toolchain.host_cxx),
            "-std=c++17",
            "-O3",
            "-fPIC",
            *include_flags,
            "-c",
            str(source),
            "-o",
            str(destination),
        ]
        identity = digest_json(
            {
                "build": plan["build_identity_sha256"],
                "command": command[1:],
                "source_sha256": sha256_file(source),
            }
        )
        stamp = destination.with_suffix(".json")
        if not stamped_artifact_current(destination, stamp, identity):
            run(command)
            atomic_write(stamp, json_bytes({"identity": identity}))
        results.append(destination)
    return results


def run_parallel(jobs: Sequence[tuple[list[str], Path]], workers: int) -> None:
    def one(job: tuple[list[str], Path]) -> None:
        command, destination = job
        destination.parent.mkdir(parents=True, exist_ok=True)
        staging = destination.with_suffix(destination.suffix + ".staged")
        try:
            output_index = command.index("-o") + 1
        except ValueError as error:
            raise BuildError("CUDA compile command has no output") from error
        command = list(command)
        command[output_index] = str(staging)
        run(command)
        publish(staging, destination)

    if not jobs:
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(jobs))) as pool:
        futures = [pool.submit(one, job) for job in jobs]
        for future in futures:
            future.result()


def run(command: Sequence[str]) -> None:
    try:
        completed = subprocess.run(command, capture_output=True, text=True)
    except OSError as error:
        raise BuildError(f"cannot execute {command[0]}: {error}") from error
    if completed.returncode != 0:
        rendered = shlex.join(command)
        raise BuildError(
            f"command failed ({completed.returncode}): {rendered}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )


def stamped_artifact_current(path: Path, stamp: Path, identity: str) -> bool:
    if not path.is_file() or not stamp.is_file():
        return False
    try:
        return json.loads(stamp.read_text(encoding="utf-8")).get("identity") == identity
    except (OSError, json.JSONDecodeError):
        return False


def publish(staging: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    os.replace(staging, destination)


def atomic_write(destination: Path, payload: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=destination.parent, prefix=f".{destination.name}.", delete=False
    ) as stream:
        stream.write(payload)
        staging = Path(stream.name)
    os.replace(staging, destination)


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def digest_json(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def resolve_tool(value: str) -> Path:
    path = Path(value).expanduser()
    if path.parent != Path(".") or path.is_absolute():
        return path
    discovered = shutil.which(value)
    return Path(discovered) if discovered is not None else path
