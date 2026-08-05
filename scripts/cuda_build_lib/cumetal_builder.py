"""Deterministic CuMetal provider archive for the resident CUDA architecture."""

from __future__ import annotations

import concurrent.futures
import json
import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .aot_pack import ABI_SCHEMAS, AotPackError, write_aot_carriers, write_aot_pack
from .builder import (
    AOT_PACK_NAME,
    ARCHIVE_NAME,
    digest_json,
    json_bytes,
    load_source_closure,
    publish,
    sha256_file,
    tool_record,
    write_build_identity_carrier,
    atomic_write,
)
from .cumetal_toolchain import verify_checkout
from .errors import BuildError
from .native_closure import load_native_closure
from .product_selection import MODULE_GLOBAL_REQUIREMENTS, validate_aot_manifest


SCHEMA = "stwo-zig-cumetal-native-build-v1"
PLAN_NAME = "cumetal_build_plan.json"
RECEIPT_NAME = "cumetal_build_receipt.json"
TARGET_SM = 80
INLINE_THRESHOLD = 1_000_000
NATIVE_POW_KERNEL = "stwo_cumetal_pow_search"
NATIVE_DECOMMIT_KERNEL = "stwo_cumetal_decommit_normalize"


@dataclass(frozen=True)
class Toolchain:
    clang: Path
    cumetalc: Path
    archiver: Path
    cumetal_root: Path
    library: Path
    air_inspect: Path
    air_validate: Path
    compatibility_patch: Path
    jobs: int


@dataclass(frozen=True)
class Config:
    source_root: Path
    source_manifest: Path
    product_manifest: Path
    native_root: Path
    native_aot_root: Path
    support_manifest: Path
    output_dir: Path
    frontend: str
    toolchain: Toolchain


@dataclass(frozen=True)
class NativeProduct:
    manifest_sha256: str
    ordinary_sources: tuple[Path, ...]
    aot: tuple[tuple[dict[str, object], Path], ...]


def _load_support(config: Config) -> tuple[dict[str, object], str]:
    try:
        payload = config.support_manifest.read_bytes()
        manifest = json.loads(payload)
    except (OSError, json.JSONDecodeError) as error:
        raise BuildError(f"cannot read CuMetal frontend support manifest: {error}") from error
    if (
        manifest.get("schema") != "stwo-zig-cumetal-frontend-support-v1"
        or manifest.get("provider") != "cumetal"
        or manifest.get("target_sm") != TARGET_SM
        or set(manifest.get("frontends", {})) != {"native", "cairo", "riscv"}
    ):
        raise BuildError("CuMetal frontend support manifest is not canonical")
    return manifest, sha256_file(config.support_manifest)


def _load_native_product(config: Config, closure: object) -> NativeProduct:
    """Select the tracked Native closure without Cairo's generated witnesses."""

    try:
        payload = config.product_manifest.read_bytes()
        product = json.loads(payload)
    except (OSError, json.JSONDecodeError) as error:
        raise BuildError(f"cannot read CUDA product manifest: {error}") from error
    ordinary = product.get("ordinary")
    if (
        product.get("schema") != "stwo-zig-cuda-product-closure-v1"
        or product.get("source_authority_sha256") != closure.closure_sha256
        or not isinstance(ordinary, dict)
    ):
        raise BuildError("CUDA product selection is stale or malformed")
    selected = ordinary.get("product_sources")
    candidates = ordinary.get("resident_candidates")
    if (
        not isinstance(selected, list)
        or selected != sorted(set(selected))
        or not isinstance(candidates, list)
        or candidates != sorted(set(candidates))
        or not set(selected).issubset(candidates)
    ):
        raise BuildError("CUDA product sources are not a canonical candidate subset")
    ordinary_sources = tuple(closure.root / str(name) for name in selected)
    if any(not source.is_file() for source in ordinary_sources):
        raise BuildError("CUDA product selection names an absent authority source")
    try:
        manifest = json.loads(
            (config.native_aot_root / "aot_manifest.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        raise BuildError(f"cannot read Native AOT manifest: {error}") from error
    native_manifest = [
        entry for entry in manifest if entry.get("abi_schema") != "recorded_witness_v1"
    ]
    validate_aot_manifest(config.native_aot_root, native_manifest)
    aot = tuple(
        (entry, config.native_aot_root / str(entry["file"]))
        for entry in native_manifest
    )
    return NativeProduct(
        manifest_sha256=sha256_file(config.product_manifest),
        ordinary_sources=ordinary_sources,
        aot=aot,
    )


def build_plan(config: Config, *, probe_tools: bool) -> dict[str, object]:
    if config.frontend not in {"native", "cairo", "riscv"}:
        raise BuildError(f"unsupported CuMetal frontend: {config.frontend}")
    if config.toolchain.jobs <= 0:
        raise BuildError("CuMetal build jobs must be positive")
    support, support_sha256 = _load_support(config)
    frontend_support = support["frontends"][config.frontend]
    assert isinstance(frontend_support, dict)
    checkout = verify_checkout(
        config.toolchain.cumetal_root,
        config.toolchain.compatibility_patch,
    )
    if checkout["patch_sha256"] != support["toolchain"]["compatibility_patch_sha256"]:
        raise BuildError("CuMetal support and compatibility-patch identities differ")
    tools = {
        "clang": tool_record(config.toolchain.clang, ("--version",), probe_tools),
        "cumetalc": tool_record(config.toolchain.cumetalc, ("--version",), probe_tools),
        "archiver": _executable_record(config.toolchain.archiver, probe_tools),
        "air_inspect": _executable_record(config.toolchain.air_inspect, probe_tools),
        "air_validate": _executable_record(config.toolchain.air_validate, probe_tools),
        "runtime_library": _file_record(config.toolchain.library, probe_tools),
    }
    base: dict[str, object] = {
        "schema": SCHEMA,
        "provider": "cumetal",
        "frontend": config.frontend,
        "target_sm": TARGET_SM,
        "frontend_support": frontend_support,
        "support_manifest_sha256": support_sha256,
        "checkout": checkout,
        "tools": tools,
        "jobs": config.toolchain.jobs,
    }
    if frontend_support.get("execution") != "staged":
        return {
            **base,
            "available": False,
            "build_identity_sha256": digest_json(base),
        }

    closure = load_source_closure(config.source_root, config.source_manifest)
    native = load_native_closure(config.native_root)
    product = _load_native_product(config, closure)
    native_pow_source = _native_pow_source(config)
    native_decommit_source = _native_decommit_source(config)
    selected = product.aot
    if len(selected) != frontend_support.get("aot_entries"):
        raise BuildError("CuMetal Native AOT selection differs from its support contract")
    aot_identity = digest_json(
        [
            {
                "cache_key": metadata["cache_key"],
                "kernel_name": metadata["kernel_name"],
                "program_identity": metadata["program_identity"],
                "source_sha256": sha256_file(source),
            }
            for metadata, source in selected
        ]
    )
    identity_input = {
        **base,
        "available": True,
        "source_closure_sha256": closure.closure_sha256,
        "native_runtime_closure_sha256": native["closure_sha256"],
        "product_manifest_sha256": product.manifest_sha256,
        "native_aot_identity_sha256": aot_identity,
        "native_pow_source_sha256": sha256_file(native_pow_source),
        "native_decommit_source_sha256": sha256_file(native_decommit_source),
        "ordinary_source_count": len(product.ordinary_sources),
        "runtime_cuda_source_count": len(native["cuda_sources"]),
        "runtime_host_source_count": len(native["host_sources"]),
        "aot_entry_count": len(selected),
        "fixed_flags": {
            "cuda": _cuda_flags(config),
            "aot": _aot_flags(config),
            "host": ["-std=c++17", "-O3", "-fPIC", "-DSTWO_CUMETAL=1"],
        },
    }
    return {
        **identity_input,
        "build_identity_sha256": digest_json(identity_input),
    }


def execute(config: Config) -> dict[str, object]:
    plan = build_plan(config, probe_tools=True)
    if not plan["available"]:
        reason = plan["frontend_support"].get("reason", "provider support incomplete")
        raise BuildError(f"CuMetal {config.frontend} execution is unavailable: {reason}")
    output = config.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    archive = output / ARCHIVE_NAME
    receipt_path = output / RECEIPT_NAME
    if archive.is_file() and receipt_path.is_file():
        previous = json.loads(receipt_path.read_text(encoding="utf-8"))
        if (
            previous.get("build_identity_sha256") == plan["build_identity_sha256"]
            and previous.get("archive_sha256") == sha256_file(archive)
        ):
            print(f"reused CuMetal provider archive {archive}")
            return previous

    closure = load_source_closure(config.source_root, config.source_manifest)
    native = load_native_closure(config.native_root)
    product = _load_native_product(config, closure)
    selected = product.aot
    work = output / ".work" / str(plan["build_identity_sha256"])
    objects = work / "objects"
    metallibs = work / "metallibs"
    generated = work / "generated"
    for directory in (objects, metallibs, generated):
        directory.mkdir(parents=True, exist_ok=True)

    cuda_sources = [*product.ordinary_sources, *native["cuda_sources"]]
    cuda_objects = _compile_cuda_sources(config, closure, cuda_sources, objects)
    host_objects = _compile_host_sources(config, native["host_sources"], objects)
    aot_entries = _compile_aot(config, selected, metallibs)
    native_pow_metallib = _compile_native_pow(config, metallibs)
    native_decommit_metallib = _compile_native_decommit(config, metallibs)
    aot_pack = generated / AOT_PACK_NAME
    try:
        write_aot_pack(aot_entries, aot_pack)
        carriers = write_aot_carriers(
            aot_entries,
            aot_pack,
            generated,
            object_format="macho",
        )
    except AotPackError as error:
        raise BuildError(str(error)) from error
    carrier_objects = [_compile_host(config, source, generated) for source in carriers]
    native_pow_carriers = _write_native_pow_carriers(
        native_pow_metallib,
        generated,
    )
    native_pow_carrier_objects = [
        _compile_host(config, source, generated) for source in native_pow_carriers
    ]
    native_decommit_carriers = _write_native_decommit_carriers(
        native_decommit_metallib,
        generated,
    )
    native_decommit_carrier_objects = [
        _compile_host(config, source, generated)
        for source in native_decommit_carriers
    ]
    identity_source = write_build_identity_carrier(
        str(plan["build_identity_sha256"]),
        generated,
    )
    identity_object = _compile_host(config, identity_source, generated)

    staged = work / f"{ARCHIVE_NAME}.staged"
    _run(
        [
            str(config.toolchain.archiver),
            "crs",
            str(staged),
            *(str(path) for path in cuda_objects),
            *(str(path) for path in host_objects),
            *(str(path) for path in carrier_objects),
            *(str(path) for path in native_pow_carrier_objects),
            *(str(path) for path in native_decommit_carrier_objects),
            str(identity_object),
        ]
    )
    if not staged.is_file() or staged.stat().st_size == 0:
        raise BuildError("CuMetal provider archive publication produced no bytes")
    publish(staged, archive)
    publish(aot_pack, output / AOT_PACK_NAME)
    receipt = {
        **plan,
        "archive": ARCHIVE_NAME,
        "archive_sha256": sha256_file(archive),
        "aot_pack": AOT_PACK_NAME,
        "aot_pack_sha256": sha256_file(output / AOT_PACK_NAME),
        "aot_entries": len(aot_entries),
        "native_modules": [NATIVE_DECOMMIT_KERNEL, NATIVE_POW_KERNEL],
        "linked_libraries": ["cumetal", "c++", "Metal", "Foundation"],
    }
    atomic_write(output / PLAN_NAME, json_bytes(plan))
    atomic_write(receipt_path, json_bytes(receipt))
    print(
        f"built {archive}: {len(cuda_objects)} CUDA registration objects, "
        f"{len(host_objects)} host objects, {len(aot_entries)} strict metallibs, "
        "2 exact source-native metallibs"
    )
    return receipt


def _compile_cuda_sources(
    config: Config,
    closure: object,
    sources: Sequence[Path],
    output: Path,
) -> list[Path]:
    include_dirs = sorted(
        {
            config.native_root.resolve(),
            config.source_root.resolve(),
            *closure.include_dirs,
        }
    )
    prefix = [
        str(config.toolchain.clang),
        *_cuda_flags(config),
        *(flag for path in include_dirs for flag in ("-I", str(path))),
    ]
    jobs: list[tuple[list[str], Path]] = []
    results: list[Path] = []
    for index, source in enumerate(sources):
        key = sha256_file(source)[:16]
        destination = output / f"cuda-{index:03d}-{source.stem}-{key}.o"
        results.append(destination)
        if not destination.is_file():
            jobs.append(([*prefix, "-c", str(source), "-o", str(destination)], destination))
    _run_parallel(jobs, config.toolchain.jobs, _cuda_environment(config))
    return results


def _compile_host_sources(
    config: Config,
    sources: Sequence[Path],
    output: Path,
) -> list[Path]:
    return [_compile_host(config, source, output) for source in sources]


def _compile_host(config: Config, source: Path, output: Path) -> Path:
    destination = output / f"host-{source.stem}-{sha256_file(source)[:16]}.o"
    if destination.is_file():
        return destination
    command = [
        str(config.toolchain.clang),
        "-std=c++17",
        "-O3",
        "-fPIC",
        "-DSTWO_CUMETAL=1",
        "-I",
        str(config.toolchain.cumetal_root / "runtime/api"),
        "-I",
        str(config.native_root),
        "-I",
        str(config.source_root),
        "-I",
        str(_compat_root(config)),
        "-c",
        str(source),
        "-o",
        str(destination),
    ]
    _run(command)
    return destination


def _compile_aot(
    config: Config,
    selected: Sequence[tuple[dict[str, object], Path]],
    output: Path,
) -> list[dict[str, object]]:
    jobs: list[tuple[list[str], Path]] = []
    entries: list[dict[str, object]] = []
    for metadata, source in selected:
        destination = output / f"{source.stem}-sm_80.metallib"
        command = [
            str(config.toolchain.cumetalc),
            str(source),
            "-o",
            str(destination),
            *_aot_flags(config),
            "--entry",
            str(metadata["kernel_name"]),
        ]
        if not destination.is_file():
            jobs.append((command, destination))
        entries.append(
            {
                "cache_key": int(str(metadata["cache_key"]), 16),
                "sm": TARGET_SM,
                "kernel_name": str(metadata["kernel_name"]),
                "module_globals": MODULE_GLOBAL_REQUIREMENTS[
                    str(metadata["module_globals"])
                ],
                "abi_schema": ABI_SCHEMAS[str(metadata["abi_schema"])],
                "source": source.name,
                "cubin": destination,
            }
        )
    _run_parallel(jobs, config.toolchain.jobs, None)
    for entry in entries:
        checked = _capture([str(config.toolchain.air_inspect), str(entry["cubin"])])
        expected = str(entry["kernel_name"])
        if "Function count: 1" not in checked or expected not in checked:
            raise BuildError(f"CuMetal AOT output does not contain only {expected}")
        _run([str(config.toolchain.air_validate), str(entry["cubin"])])
    entries.sort(key=lambda entry: (entry["cache_key"], entry["sm"]))
    return entries


def _native_pow_source(config: Config) -> Path:
    source = config.support_manifest.parent / "native" / "pow_search.metal"
    if not source.is_file():
        raise BuildError(f"Native CuMetal PoW source is absent: {source}")
    return source


def _compile_native_pow(config: Config, output: Path) -> Path:
    source = _native_pow_source(config)
    destination = output / f"pow-search-{sha256_file(source)[:16]}.metallib"
    if not destination.is_file():
        _run(
            [
                str(config.toolchain.cumetalc),
                "--input",
                str(source),
                "--output",
                str(destination),
                "--mode",
                "xcrun",
                "--overwrite",
                "--xcrun-validate",
            ]
        )
    checked = _capture([str(config.toolchain.air_inspect), str(destination)])
    if "Function count: 1" not in checked or NATIVE_POW_KERNEL not in checked:
        raise BuildError(
            f"Native CuMetal PoW output does not contain only {NATIVE_POW_KERNEL}"
        )
    _run([str(config.toolchain.air_validate), str(destination)])
    return destination


def _native_decommit_source(config: Config) -> Path:
    source = config.support_manifest.parent / "native" / "decommit_normalize.metal"
    if not source.is_file():
        raise BuildError(f"Native CuMetal decommit source is absent: {source}")
    return source


def _compile_native_decommit(config: Config, output: Path) -> Path:
    source = _native_decommit_source(config)
    destination = output / f"decommit-normalize-{sha256_file(source)[:16]}.metallib"
    if not destination.is_file():
        _run(
            [
                str(config.toolchain.cumetalc),
                "--input",
                str(source),
                "--output",
                str(destination),
                "--mode",
                "xcrun",
                "--overwrite",
                "--xcrun-validate",
            ]
        )
    checked = _capture([str(config.toolchain.air_inspect), str(destination)])
    if "Function count: 1" not in checked or NATIVE_DECOMMIT_KERNEL not in checked:
        raise BuildError(
            "Native CuMetal decommit output does not contain only "
            f"{NATIVE_DECOMMIT_KERNEL}"
        )
    _run([str(config.toolchain.air_validate), str(destination)])
    return destination


def _write_native_pow_carriers(metallib: Path, output: Path) -> tuple[Path, Path]:
    assembly = output / "cumetal_native_pow_metallib.S"
    registration = output / "cumetal_native_pow_registration.cc"
    metallib_path = (
        str(metallib.resolve()).replace("\\", "\\\\").replace('"', '\\"')
    )
    assembly_text = f""".section __DATA,__const
.p2align 4
.globl _stwo_cumetal_pow_metallib_start
.globl _stwo_cumetal_pow_metallib_end
_stwo_cumetal_pow_metallib_start:
.incbin "{metallib_path}"
_stwo_cumetal_pow_metallib_end:
"""
    registration_text = f"""#include <cumetal_native.h>

#include <cstddef>
#include <cstdint>
#include <mutex>

extern "C" const unsigned char stwo_cumetal_pow_metallib_start[];
extern "C" const unsigned char stwo_cumetal_pow_metallib_end[];

namespace {{
std::mutex registration_mutex;
CuMetalModuleHandle module_handle = nullptr;
const void *registered_stub = nullptr;

constexpr CuMetalArgumentDescriptor kArguments[] = {{
    {{CUMETAL_NATIVE_ARGUMENT_POINTER, 8, 8,
      CUMETAL_NATIVE_ADDRESS_DEVICE, 0, 1}},
    {{CUMETAL_NATIVE_ARGUMENT_SCALAR, 4, 4,
      CUMETAL_NATIVE_ADDRESS_CONSTANT, 1, 1}},
    {{CUMETAL_NATIVE_ARGUMENT_SCALAR, 8, 8,
      CUMETAL_NATIVE_ADDRESS_CONSTANT, 2, 1}},
    {{CUMETAL_NATIVE_ARGUMENT_SCALAR, 4, 4,
      CUMETAL_NATIVE_ADDRESS_CONSTANT, 3, 1}},
    {{CUMETAL_NATIVE_ARGUMENT_POINTER, 8, 8,
      CUMETAL_NATIVE_ADDRESS_DEVICE, 4, 1}},
    {{CUMETAL_NATIVE_ARGUMENT_POINTER, 8, 8,
      CUMETAL_NATIVE_ADDRESS_DEVICE, 5, 1}},
    {{CUMETAL_NATIVE_ARGUMENT_POINTER, 8, 8,
      CUMETAL_NATIVE_ADDRESS_DEVICE, 6, 1}},
}};

constexpr CuMetalBindingDescriptor kBindings[] = {{
    {{CUMETAL_NATIVE_BINDING_BUFFER, 0, 0, 8, 8}},
    {{CUMETAL_NATIVE_BINDING_BYTES, 1, 1, 4, 4}},
    {{CUMETAL_NATIVE_BINDING_BYTES, 2, 2, 8, 8}},
    {{CUMETAL_NATIVE_BINDING_BYTES, 3, 3, 4, 4}},
    {{CUMETAL_NATIVE_BINDING_BUFFER, 4, 4, 8, 8}},
    {{CUMETAL_NATIVE_BINDING_BUFFER, 5, 5, 8, 8}},
    {{CUMETAL_NATIVE_BINDING_BUFFER, 6, 6, 8, 8}},
}};
}}  // namespace

extern "C" int stwo_cumetal_register_pow_search(const void *host_stub) {{
    if (host_stub == nullptr) return 1;
    std::lock_guard<std::mutex> lock(registration_mutex);
    if (module_handle != nullptr) return registered_stub == host_stub ? 0 : 1;

    const CuMetalKernelDescriptor kernel = {{
        "_ZN4stwo4cuda3pow13search_kernelEPKjjyjPyPjS5_",
        "{NATIVE_POW_KERNEL}",
        host_stub,
        7,
        kArguments,
        0,
        32,
    }};
    const CuMetalModuleDescriptor module = {{
        CUMETAL_NATIVE_ABI_VERSION,
        stwo_cumetal_pow_metallib_start,
        static_cast<std::size_t>(
            stwo_cumetal_pow_metallib_end - stwo_cumetal_pow_metallib_start),
        1,
        &kernel,
        7,
        kBindings,
        "precompiled_metallib",
        "exact",
    }};
    module_handle = cumetalRegisterModule(&module);
    if (module_handle == nullptr) return 1;
    registered_stub = host_stub;
    return 0;
}}
"""
    atomic_write(assembly, assembly_text.encode("utf-8"))
    atomic_write(registration, registration_text.encode("utf-8"))
    return assembly, registration


def _write_native_decommit_carriers(
    metallib: Path,
    output: Path,
) -> tuple[Path, Path]:
    assembly = output / "cumetal_native_decommit_metallib.S"
    registration = output / "cumetal_native_decommit_registration.cc"
    metallib_path = (
        str(metallib.resolve()).replace("\\", "\\\\").replace('"', '\\"')
    )
    assembly_text = f""".section __DATA,__const
.p2align 4
.globl _stwo_cumetal_decommit_metallib_start
.globl _stwo_cumetal_decommit_metallib_end
_stwo_cumetal_decommit_metallib_start:
.incbin "{metallib_path}"
_stwo_cumetal_decommit_metallib_end:
"""
    registration_text = f"""#include <cumetal_native.h>

#include <cstddef>
#include <cstdint>
#include <mutex>

extern "C" const unsigned char stwo_cumetal_decommit_metallib_start[];
extern "C" const unsigned char stwo_cumetal_decommit_metallib_end[];

namespace {{
std::mutex registration_mutex;
CuMetalModuleHandle module_handle = nullptr;
const void *registered_stub = nullptr;

constexpr CuMetalArgumentDescriptor kArguments[] = {{
    {{CUMETAL_NATIVE_ARGUMENT_POINTER, 8, 8,
      CUMETAL_NATIVE_ADDRESS_DEVICE, 0, 1}},
    {{CUMETAL_NATIVE_ARGUMENT_SCALAR, 4, 4,
      CUMETAL_NATIVE_ADDRESS_CONSTANT, 1, 1}},
    {{CUMETAL_NATIVE_ARGUMENT_SCALAR, 4, 4,
      CUMETAL_NATIVE_ADDRESS_CONSTANT, 2, 1}},
    {{CUMETAL_NATIVE_ARGUMENT_SCALAR, 4, 4,
      CUMETAL_NATIVE_ADDRESS_CONSTANT, 3, 1}},
    {{CUMETAL_NATIVE_ARGUMENT_POINTER, 8, 8,
      CUMETAL_NATIVE_ADDRESS_DEVICE, 4, 1}},
    {{CUMETAL_NATIVE_ARGUMENT_POINTER, 8, 8,
      CUMETAL_NATIVE_ADDRESS_DEVICE, 5, 1}},
    {{CUMETAL_NATIVE_ARGUMENT_POINTER, 8, 8,
      CUMETAL_NATIVE_ADDRESS_DEVICE, 6, 1}},
    {{CUMETAL_NATIVE_ARGUMENT_SCALAR, 4, 4,
      CUMETAL_NATIVE_ADDRESS_CONSTANT, 7, 1}},
}};

constexpr CuMetalBindingDescriptor kBindings[] = {{
    {{CUMETAL_NATIVE_BINDING_BUFFER, 0, 0, 8, 8}},
    {{CUMETAL_NATIVE_BINDING_BYTES, 1, 1, 4, 4}},
    {{CUMETAL_NATIVE_BINDING_BYTES, 2, 2, 4, 4}},
    {{CUMETAL_NATIVE_BINDING_BYTES, 3, 3, 4, 4}},
    {{CUMETAL_NATIVE_BINDING_BUFFER, 4, 4, 8, 8}},
    {{CUMETAL_NATIVE_BINDING_BUFFER, 5, 5, 8, 8}},
    {{CUMETAL_NATIVE_BINDING_BUFFER, 6, 6, 8, 8}},
    {{CUMETAL_NATIVE_BINDING_BYTES, 7, 7, 4, 4}},
}};
}}  // namespace

extern "C" int stwo_cumetal_register_decommit_normalize(
    const void *host_stub) {{
    if (host_stub == nullptr) return 1;
    std::lock_guard<std::mutex> lock(registration_mutex);
    if (module_handle != nullptr) return registered_stub == host_stub ? 0 : 1;

    const CuMetalKernelDescriptor kernel = {{
        "_ZN4stwo4cuda8decommit12_GLOBAL__N_124normalize_queries_kernelEPKjjjjPjS5_S5_j",
        "{NATIVE_DECOMMIT_KERNEL}",
        host_stub,
        8,
        kArguments,
        0,
        32,
    }};
    const CuMetalModuleDescriptor module = {{
        CUMETAL_NATIVE_ABI_VERSION,
        stwo_cumetal_decommit_metallib_start,
        static_cast<std::size_t>(
            stwo_cumetal_decommit_metallib_end -
            stwo_cumetal_decommit_metallib_start),
        1,
        &kernel,
        8,
        kBindings,
        "precompiled_metallib",
        "exact",
    }};
    module_handle = cumetalRegisterModule(&module);
    if (module_handle == nullptr) return 1;
    registered_stub = host_stub;
    return 0;
}}
"""
    atomic_write(assembly, assembly_text.encode("utf-8"))
    atomic_write(registration, registration_text.encode("utf-8"))
    return assembly, registration


def _cuda_flags(config: Config) -> list[str]:
    return [
        "-x",
        "cuda",
        "-std=c++17",
        "-O3",
        "-fno-jump-tables",
        "--cuda-gpu-arch=sm_80",
        "--cuda-feature=+ptx70",
        "-nocudainc",
        "-nocudalib",
        "-Wno-unknown-cuda-version",
        "-Wno-pass-failed",
        "-D__CUDACC__=1",
        "-D__NVCC__=1",
        "-DSTWO_CUMETAL=1",
        "-I",
        str(config.toolchain.cumetal_root / "runtime/api"),
        "-include",
        "cuda_runtime.h",
        "-I",
        str(_compat_root(config)),
        "-include",
        str(_compat_root(config) / "stwo_cumetal_no_device_printf.cuh"),
    ]


def _aot_flags(config: Config) -> list[str]:
    return [
        "--cuda-device",
        "--ptx-strict",
        "--overwrite",
        "--cuda-arch",
        "sm_80",
        "--cuda-clang",
        str(config.toolchain.clang),
        "--cuda-inline-threshold",
        str(INLINE_THRESHOLD),
        "--cuda-include",
        str(_compat_root(config) / "stwo_cumetal_cuda_compat.cuh"),
        "-DSTWO_CUMETAL=1",
    ]


def _compat_root(config: Config) -> Path:
    return config.support_manifest.parent / "include"


def _cuda_environment(config: Config) -> dict[str, str]:
    environment = dict(os.environ)
    prefixes = [
        config.toolchain.cumetalc.parent / "cuda_toolchain",
        config.toolchain.cumetal_root / "scripts/cuda_toolchain",
    ]
    environment["PATH"] = os.pathsep.join(
        [*(str(path) for path in prefixes), environment.get("PATH", "")]
    )
    return environment


def _file_record(path: Path, probe: bool) -> dict[str, object]:
    if not probe:
        return {"path": str(path), "sha256": "plan-only"}
    if not path.is_file():
        raise BuildError(f"required CuMetal runtime library is absent: {path}")
    return {"path": str(path.resolve()), "sha256": sha256_file(path)}


def _executable_record(path: Path, probe: bool) -> dict[str, object]:
    record = _file_record(path, probe)
    if probe and not os.access(path, os.X_OK):
        raise BuildError(f"required CuMetal build tool is not executable: {path}")
    return record


def _run_parallel(
    jobs: Sequence[tuple[list[str], Path]],
    workers: int,
    environment: dict[str, str] | None,
) -> None:
    def one(job: tuple[list[str], Path]) -> None:
        command, destination = job
        destination.parent.mkdir(parents=True, exist_ok=True)
        _run(command, environment=environment)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(jobs)) or 1) as pool:
        for future in (pool.submit(one, job) for job in jobs):
            future.result()


def _capture(command: Sequence[str]) -> str:
    completed = subprocess.run(command, check=False, text=True, capture_output=True)
    if completed.returncode != 0:
        raise BuildError(f"command failed: {shlex.join(command)}\n{completed.stderr}")
    return completed.stdout + completed.stderr


def _run(
    command: Sequence[str],
    *,
    environment: dict[str, str] | None = None,
) -> None:
    completed = subprocess.run(
        command,
        check=False,
        text=True,
        capture_output=True,
        env=environment,
    )
    if completed.returncode != 0:
        raise BuildError(
            f"command failed ({completed.returncode}): {shlex.join(command)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
