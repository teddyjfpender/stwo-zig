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


SCHEMA = "stwo-zig-cuda-native-build-v1"
ARCHIVE_NAME = "libstwo_cuda_kernels.a"
RECEIPT_NAME = "cuda_build_receipt.json"
PLAN_NAME = "cuda_build_plan.json"
AOT_PACK_NAME = "cuda_aot_pack.bin"
GENERATED = "generated"
SM_RE = re.compile(r"^(?:sm_)?([1-9][0-9])$")


class BuildError(RuntimeError):
    """A fail-closed CUDA build rejection."""


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
    output_dir: Path
    toolchain: Toolchain


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
    generated_dir: Path, manifest: object
) -> None:
    if not isinstance(manifest, list) or not manifest:
        raise BuildError("copied AOT manifest must be a non-empty array")
    seen_files: set[str] = set()
    seen_keys: set[int] = set()
    previous: tuple[str, str, int] | None = None
    required = {
        "kind",
        "label",
        "kernel_name",
        "cache_key",
        "semantic_hash",
        "file",
    }
    for index, raw in enumerate(manifest):
        if not isinstance(raw, dict) or not required.issubset(raw):
            raise BuildError(f"AOT manifest entry {index} is incomplete")
        kind = str(raw["kind"])
        label = str(raw["label"])
        file_name = str(raw["file"])
        if kind not in {"constraint", "witness"}:
            raise BuildError(f"AOT manifest entry {index} has invalid kind")
        try:
            cache_key = int(str(raw["cache_key"]), 16)
            int(str(raw["semantic_hash"]), 16)
        except ValueError as error:
            raise BuildError(f"AOT manifest entry {index} has invalid hex identity") from error
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
        previous = order
        seen_files.add(file_name)
        seen_keys.add(cache_key)
    copied = {path.name for path in generated_dir.glob("*.cu")}
    if copied != seen_files:
        raise BuildError("copied generated CUDA sources do not match the AOT manifest")


def build_plan(config: BuildConfig, probe_tools: bool) -> dict[str, object]:
    closure = load_source_closure(config.source_root, config.source_manifest)
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
        "ordinary": [
            "-dc",
            "-O3",
            "--std=c++17",
            "--expt-relaxed-constexpr",
            "-Xcompiler",
            "-fPIC",
        ],
        "aot": ["-cubin", "-O3", "--std=c++17", "--expt-relaxed-constexpr"],
        "device_link": ["-dlink", "-Xcompiler", "-fPIC"],
        "host": ["-std=c++17", "-O2", "-fPIC", "-c"],
    }
    identity_input = {
        "schema": SCHEMA,
        "source_closure_sha256": closure.closure_sha256,
        "tools": tools,
        "target_sms": list(toolchain.sms),
        "fixed_flags": fixed,
    }
    build_identity = digest_json(identity_input)
    return {
        **identity_input,
        "build_identity_sha256": build_identity,
        "ordinary_source_count": len(closure.ordinary_sources),
        "aot_source_count": len(closure.generated_sources),
        "aot_cubin_count": len(closure.generated_sources) * len(toolchain.sms),
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

    ordinary_objects = compile_ordinary(config, closure, plan, objects)
    dlink = device_link(config, plan, ordinary_objects, work)
    aot_entries = compile_aot(config, closure, plan, cubins)
    aot_pack = generated / AOT_PACK_NAME
    write_aot_pack(aot_entries, aot_pack)
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

    staged_archive = work / f"{ARCHIVE_NAME}.staged"
    run(
        [
            str(config.toolchain.archiver),
            "crs",
            str(staged_archive),
            *(str(path) for path in ordinary_objects),
            str(dlink),
            *(str(path) for path in aot_objects),
            str(identity_object),
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
        "linked_libraries": ["cuda", "cudart", "nvrtc", "stdc++"],
    }
    atomic_write(output / PLAN_NAME, json_bytes(plan))
    atomic_write(receipt_path, json_bytes(receipt))
    print(
        f"built {archive}: {len(ordinary_objects)} CUDA objects, "
        f"{len(aot_entries)} AOT cubins"
    )
    return receipt


def compile_ordinary(
    config: BuildConfig,
    closure: SourceClosure,
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
        "-dc",
        "-O3",
        "--std=c++17",
        "--expt-relaxed-constexpr",
        "-Xcompiler",
        "-fPIC",
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
    for source in closure.ordinary_sources:
        key = hashlib.sha256(
            f"{context}:{sha256_file(source)}".encode("ascii")
        ).hexdigest()[:24]
        destination = output / f"{source.stem}-{key}.o"
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
    closure: SourceClosure,
    plan: dict[str, object],
    output: Path,
) -> list[dict[str, object]]:
    source_by_name = {path.name: path for path in closure.generated_sources}
    jobs: list[tuple[list[str], Path]] = []
    entries: list[dict[str, object]] = []
    for metadata in closure.aot_manifest:
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


def write_aot_pack(entries: Sequence[dict[str, object]], destination: Path) -> None:
    staging = destination.with_suffix(".staged")
    with staging.open("wb") as pack:
        offset = 0
        for entry in entries:
            payload = Path(entry["cubin"]).read_bytes()
            if not payload:
                raise BuildError(f"empty generated cubin: {entry['cubin']}")
            entry["offset"] = offset
            entry["bytes"] = len(payload)
            entry["sha256"] = hashlib.sha256(payload).hexdigest()
            pack.write(payload)
            offset += len(payload)
    publish(staging, destination)


def write_aot_carriers(
    entries: Sequence[dict[str, object]], pack: Path, output: Path
) -> tuple[Path, Path]:
    assembly = output / "cuda_aot_pack.S"
    lookup = output / "cuda_aot_lookup.cc"
    pack_path = str(pack.resolve()).replace("\\", "\\\\").replace('"', '\\"')
    assembly_text = f""".section .rodata
.balign 16
.global stwo_cuda_aot_pack_start
.global stwo_cuda_aot_pack_end
.type stwo_cuda_aot_pack_start, @object
stwo_cuda_aot_pack_start:
.incbin "{pack_path}"
stwo_cuda_aot_pack_end:
.size stwo_cuda_aot_pack_start, stwo_cuda_aot_pack_end-stwo_cuda_aot_pack_start
.section .note.GNU-stack,"",@progbits
"""
    rows = "\n".join(
        "    {0x%016xULL, %dU, %dULL, %dULL},"
        % (
            int(entry["cache_key"]),
            int(entry["sm"]),
            int(entry["offset"]),
            int(entry["bytes"]),
        )
        for entry in entries
    )
    lookup_text = f"""#include <cstddef>
#include <cstdint>

extern "C" const unsigned char stwo_cuda_aot_pack_start[];
extern "C" const unsigned char stwo_cuda_aot_pack_end[];

namespace {{
struct Entry {{
    std::uint64_t cache_key;
    std::uint32_t sm;
    std::uint64_t offset;
    std::uint64_t size;
}};

constexpr Entry kEntries[] = {{
{rows}
}};
}}  // namespace

extern "C" bool stwo_aot_lookup(
    std::uint64_t cache_key,
    std::uint32_t sm_major,
    std::uint32_t sm_minor,
    const unsigned char **out_data,
    std::size_t *out_len) {{
    if (out_data == nullptr || out_len == nullptr || sm_minor > 9) return false;
    const std::uint32_t sm = sm_major * 10U + sm_minor;
    std::size_t low = 0;
    std::size_t high = sizeof(kEntries) / sizeof(kEntries[0]);
    while (low < high) {{
        const std::size_t mid = low + (high - low) / 2;
        const Entry &entry = kEntries[mid];
        if (entry.cache_key < cache_key ||
            (entry.cache_key == cache_key && entry.sm < sm)) {{
            low = mid + 1;
        }} else {{
            high = mid;
        }}
    }}
    if (low == sizeof(kEntries) / sizeof(kEntries[0])) return false;
    const Entry &entry = kEntries[low];
    if (entry.cache_key != cache_key || entry.sm != sm || entry.size == 0) return false;
    const std::size_t pack_size =
        static_cast<std::size_t>(stwo_cuda_aot_pack_end - stwo_cuda_aot_pack_start);
    if (entry.offset > pack_size || entry.size > pack_size - entry.offset) return false;
    *out_data = stwo_cuda_aot_pack_start + entry.offset;
    *out_len = static_cast<std::size_t>(entry.size);
    return true;
}}

extern "C" std::size_t stwo_zig_cuda_aot_entry_count() {{
    return sizeof(kEntries) / sizeof(kEntries[0]);
}}
"""
    atomic_write(assembly, assembly_text.encode("utf-8"))
    atomic_write(lookup, lookup_text.encode("utf-8"))
    return assembly, lookup


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
        "-O2",
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
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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
