#!/usr/bin/env python3
"""Build a complete resident image from generated CPU and 15-role truth AOTs.

Every compiler owns a process-group deadline. This builds one coherent truth
catalogue, never combines cached kernels with a different partition geometry.
It does not qualify a GPU image or run a benchmark.
"""
import argparse
import concurrent.futures
import ctypes
import hashlib
import json
from pathlib import Path
import re
import subprocess
import threading
import sys

import rv64_cuda_native_library_build as N
import rv64_cuda_partition_rational as Rational
import rv64_cuda_partition_grouped as Grouped
import rv64_cuda_partition_instruction_slices as Instructions


def core_catalog(directory):
    sources, symbols, groups = [], [], []
    for role in range(49):
        source = directory / f"case-{role}-domain.cu"
        text = source.read_text()
        symbol = f"rv64_joined_domain_{role}"
        if not re.search(r'extern "C" __global__ void ' + symbol + r'\(', text):
            raise ValueError("missing CPU role entry: " + str(source))
        sources.append(source)
        symbols.append(symbol)
        groups.append(32 if re.search(r"void " + symbol + r"_part_\d+\(", text) else 0)
    signature = "const uint32_t*,const uint32_t*,const uint32_t*,const uint64_t*,const uint32_t*,const uint32_t*,const uint32_t*,uint32_t*,uint32_t,uint32_t,uint32_t,uint32_t"
    header = "#pragma once\n#include <cuda_runtime.h>\n#include <cstdint>\n"
    header += "\n".join(f'extern "C" __global__ void {symbol}({signature});' for symbol in symbols)
    header += "\nstatic const void *real_kernels[]={" + ",".join("(const void*)" + s for s in symbols) + "};\n"
    header += "static const uint32_t real_root_group_sizes[]={" + ",".join(map(str, groups)) + "};\n"
    return sources, header


def truth_sources(raw, partitions):
    manifest = json.loads((partitions / "partition.json").read_text())
    if len(manifest["roles"]) != 15:
        raise ValueError("complete image requires all fifteen truth roles")
    available = {}
    for directory in (raw, partitions):
        for source in directory.rglob("*.cu"):
            if source.name in available:
                raise ValueError("ambiguous generated source: " + source.name)
            available[source.name] = source
    sources = []
    for role, entry in enumerate(manifest["roles"]):
        if Path(entry["input"]).name != f"case-{role}-domain.cu" or not entry["modules"]:
            raise ValueError("truth catalogue role order/coverage mismatch")
        for module in entry["modules"]:
            source = available[Path(module["source"]).name]
            if module.get("sha256") and N.sha(source) != module["sha256"]:
                raise ValueError("truth partition changed: " + str(source))
            sources.append(source)
    if len(set(sources)) != len(sources):
        raise ValueError("truth source reused across catalogue entries")
    return sources


def outer_sources(directory):
    manifest = json.loads((directory / "outer-manifest.json").read_text())
    groups = manifest.get("groups", [])
    if manifest.get("profile") != "native-om31-circuit" or manifest.get("geometry_independent") is not True or len(groups) != 12:
        raise ValueError("complete geometry-independent outer catalogue required")
    sources = []
    for i, group in enumerate(groups):
        if group.get("id") != i or group.get("filename") != f"outer-group-{i}.cu":
            raise ValueError("outer group coverage/order mismatch")
        for key in ("program_identity", "source_identity"):
            if not re.fullmatch(r"[0-9a-f]{64}", group.get(key, "")):
                raise ValueError("outer authority identity missing")
        sources.append((directory / group["filename"]).resolve(strict=True))
    return sources + [(directory / "outer-dispatch.cu").resolve(strict=True)]


def split_core(directory, build, roles, max_module_bytes=128 << 10):
    """Keep global RLC indices while bounding individual optimizer units."""
    original, _ = core_catalog(directory)
    if max_module_bytes < 1:
        raise ValueError("positive core compiler-unit byte bound required")
    if len(set(roles)) != len(roles) or any(role not in range(49) for role in roles):
        raise ValueError("distinct existing core role IDs required")
    signature = "const uint32_t*,const uint32_t*,const uint32_t*,const uint64_t*,const uint32_t*,const uint32_t*,const uint32_t*,uint32_t*,uint32_t,uint32_t,uint32_t,uint32_t"
    lines = ["#pragma once", "#include <cuda_runtime.h>", "#include <cstdint>",
             "struct CorePart { const void *kernel; uint32_t grouping, groups; };",
             "struct CoreSpan { const CorePart *parts; uint32_t count; };"]
    sources, counts = [], []
    for role, source in enumerate(original):
        if role in roles:
            destination = build / "core-parts" / str(role)
            destination.mkdir(parents=True, exist_ok=True)
            modules = Grouped.partition(source, destination, 1, max_module_bytes)["modules"]
            grouping = 32
        else:
            symbol = f"rv64_joined_domain_{role}"
            grouping = 32 if re.search(r"void " + symbol + r"_part_\d+\(", source.read_text()) else 0
            modules = [{"source": str(source), "symbol": symbol, "groups": 0}]
        entries = []
        for module in modules:
            sources.append(Path(module["source"]))
            lines.append(f'extern "C" __global__ void {module["symbol"]}({signature});')
            entries.append(f'{{(const void*){module["symbol"]},{grouping}u,{module["groups"]}u}}')
        lines.append(f"static const CorePart core_parts_{role}[]={{" + ",".join(entries) + "};")
        counts.append(len(modules))
    lines.append("static const CoreSpan core_catalog[]={" + ",".join(f"{{core_parts_{role},{count}u}}" for role, count in enumerate(counts)) + "};")
    (build / "real_composition_launches.h").write_text("\n".join(lines) + "\n")
    dispatcher = build / "core_composition_dispatch.cu"
    dispatcher.write_text('''#include "real_composition_launches.h"
#include "rv64/composition_dispatch.cuh"
extern "C" int stwo_rv64_composition_role_on(void *ctx,uint32_t lane,
    const StwoRv64CompositionRole *job,uint32_t *launches) {
  if (launches) *launches=0;
  if (!job || !launches || job->role>=49) return int(cudaErrorInvalidValue);
  const auto &span=core_catalog[job->role];
  StwoRv64CompositionRole local=*job; local.role=0;
  for (uint32_t i=0;i<span.count;++i) {
    const auto &part=span.parts[i]; uint32_t issued=0;
    const int status=stwo::cuda::rv64::composition_dispatch(ctx,lane,&local,&issued,
        &part.kernel,&part.grouping,1,part.groups);
    if(status) return status; *launches+=issued;
  }
  return 0;
}
''')
    return sources + [dispatcher]


def bounded_compile_source(source, obj, build, max_bytes=32768, raw_directory=None):
    """Lower cold single-group units without mutating admitted source manifests.

    Existing object candidates still undergo compile_native's full dependency
    validation. Keep the selected lowered path stable on subsequent builds.
    """
    text = source.read_text()
    if len(text.encode()) <= max_bytes or text.count("__device__ __noinline__ void ") != 1:
        return source, None
    prebounded = "volatile OM31 *ext_bank" in text
    if prebounded and (raw_directory is None or len(text.encode()) < 512 << 10):
        return source, None
    name = source.stem + "-" + hashlib.sha256((str(source) + N.sha(source)).encode()).hexdigest()[:16]
    lowered = build / "bounded-aot" / (name + ".cu")
    if obj.is_file() and not lowered.is_file():
        return source, None
    lowered.parent.mkdir(parents=True, exist_ok=True)
    raw_sha = None
    if prebounded:
        match = re.fullmatch(r"rv64_truth_domain_(\d+)_shard_(\d+)\.cu", source.name)
        if not match:
            return source, None
        raw = raw_directory / f"case-{match[1]}-domain.cu"
        raw_text = raw.read_text()
        parts = list(re.finditer(r"__device__ __noinline__ void ([A-Za-z0-9_]+)_part_(\d+)\(", raw_text))
        kernel = raw_text.index('extern "C" __global__ void')
        selected = list(re.finditer(r"__device__ __noinline__ void ([A-Za-z0-9_]+)_part_(\d+)\(", text))
        group = int(selected[0][2])
        if group >= len(parts) or int(parts[group][2]) != group or parts[group][1] != selected[0][1]:
            raise ValueError("bounded recovery raw group does not match admitted source")
        end = parts[group + 1].start() if group + 1 < len(parts) else kernel
        # Recover the exact original SSA function; never transform an already
        # lowered register-bank program a second time.
        text = raw_text[:parts[0].start()] + raw_text[parts[group].start():end] + text[text.index('extern "C" __global__ void'):]
        raw_sha = N.sha(raw)
    lowered.write_text(text)
    metadata = Grouped.bound_ssa_module(lowered, 64 if prebounded else 192)
    if raw_sha:
        metadata["raw_source_sha256"] = raw_sha
        metadata["recovered_original_group"] = group
        # Keep the identical field multiplication behind one compiler call
        # boundary instead of replicating its force-inlined quartic tower in
        # every instruction slice. Qualified full native proofs gate this
        # storage/optimization choice; base-field q::mul remains untouched.
        text, calls = re.subn(r"(?<![:\w])mul\(", "rv64_bounded_mul(", lowered.read_text())
        helper = "static __device__ __noinline__ OM31 rv64_bounded_mul(OM31 a,OM31 b){return stwo::cuda::rv64::mul(a,b); }\n"
        prefix = "using namespace stwo::cuda::rv64;\n"
        if calls:
            if prefix not in text:
                raise ValueError("bounded multiply namespace missing")
            text = text.replace(prefix, prefix + helper, 1)
            lowered.write_text(text)
        metadata["bounded_multiply_calls"] = calls
    return lowered, {"source_sha256": N.sha(source), "lowered_source": str(lowered), "lowered_sha256": N.sha(lowered), **metadata}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-root", "core-domain", "core-projection", "truth-domain", "truth-partitions", "truth-rational", "build"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--outer-circuit-dir", type=Path, help="Include the exact twelve-group OM31 outer circuit catalogue")
    parser.add_argument("--nvcc", default="/usr/local/cuda/bin/nvcc")
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("--compile-timeout", type=float, default=180)
    parser.add_argument("--split-core-role", type=int, action="append", default=[], help="Split a grouped core optimizer unit into single-group kernels")
    parser.add_argument("--core-module-max-bytes", type=int, default=128 << 10, help="Bound single-group core SSA optimizer units above this size")
    args = parser.parse_args()
    if not 1 <= args.jobs <= 16 or not 0 < args.compile_timeout < float("inf") or args.core_module_max_bytes < 1:
        parser.error("bounded jobs and finite positive compiler deadline required")
    root, build = args.source_root.resolve(), args.build.resolve()
    build.mkdir(parents=True, exist_ok=True)
    logs = build / "aot-logs"
    logs.mkdir(exist_ok=True)
    core, header = core_catalog(args.core_domain.resolve())
    (build / "real_composition_launches.h").write_text(header)
    if args.split_core_role:
        core = split_core(args.core_domain.resolve(), build, args.split_core_role, args.core_module_max_bytes)
    (build / "truth_composition_launches.h").write_bytes((args.truth_partitions / "truth_composition_launches.h").read_bytes())
    (build / "projection_fixture.h").write_bytes((root / "tests/cuda/rv64/projection_fixture.h").read_bytes())
    sources = core + truth_sources(args.truth_domain.resolve(), args.truth_partitions.resolve())
    # The source projection catalogue is distinct from the 49 composition
    # layouts. Keep its exact exported IDs, including the fixture ABI header.
    projections = sorted(args.core_projection.resolve().glob("case-*.cu"))
    ids = {int(re.fullmatch(r"case-(\d+)\.cu", p.name)[1]) for p in projections}
    if ids != set(range(47)):
        raise ValueError("complete image requires all 47 source projections")
    sources.extend(projections)
    if args.outer_circuit_dir:
        sources.extend(outer_sources(args.outer_circuit_dir.resolve()))
    for role in range(15):
        source = args.truth_rational / f"stwo_rv64_truth_projection_{role}.cu"
        result = Rational.partition(source.resolve(), build / "rational" / str(role), 16)
        sources.extend(map(Path, result))
    if not args.split_core_role:
        sources.append(root / "tests/cuda/rv64/real_composition_native.cu")
    sources.append(root / "tests/cuda/rv64/truth_composition_native.cu")
    flags = ["-O3", "-std=c++17", "-lineinfo", "-gencode", "arch=compute_120,code=sm_120", "-Xcompiler=-fPIC,-pthread", f"-I{root}/src/backends/cuda/native", f"-I{build}"]
    version = subprocess.check_output([args.nvcc, "--version"], text=True)
    objects = build / "aot-objects"
    objects.mkdir(exist_ok=True)

    lowering = {}
    device_link = []
    compiler_slots = threading.BoundedSemaphore(args.jobs)

    def compile_one(source):
        # Full path distinguishes role-local dispatch.cpp names; source/dependency
        # and compiler pins are validated by the shared atomic cache publisher.
        name = source.stem + "-" + hashlib.sha256(str(source).encode()).hexdigest()[:12]
        obj = objects / (name + ".o")
        actual, lowered = bounded_compile_source(source, obj, build, raw_directory=args.truth_domain.resolve())
        if lowered:
            lowering[str(source)] = lowered
        if lowered and lowered.get("raw_source_sha256"):
            modules = Instructions.partition(actual, build / "rdc-aot" / name)
            device_link.append(str(source))
            lowered["device_modules"] = [{"source": str(p), "sha256": N.sha(p)} for p in modules["sources"]]
            def compile_slice(path):
                output = objects / (path.stem + ".o")
                with compiler_slots:
                    N.compile_native(args.nvcc, version, flags + ["-rdc=true"], path, output, logs / (path.stem + ".log"), args.compile_timeout)
                return output
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as slices:
                outputs = list(slices.map(compile_slice, modules["sources"]))
            print(json.dumps({"aot": str(source), "device_modules": len(outputs)}), flush=True)
            return outputs
        with compiler_slots:
            cached = N.compile_native(args.nvcc, version, flags, actual, obj, logs / (name + ".log"), args.compile_timeout)
        print(json.dumps({"aot": str(source), "cached": cached}), flush=True)
        return [obj]

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        compiled = [obj for group in pool.map(compile_one, sources) for obj in group]

    command = [sys.executable, str(root / "scripts/rv64_cuda_native_library_build.py"), "--source-root", str(root), "--build", str(build / "native"), "--nvcc", args.nvcc, "--jobs", str(args.jobs), "--compile-timeout", str(args.compile_timeout), "--extra-native-source", "rv64/curve_witness.cu"]
    if device_link:
        command += ["--device-link"]
    if args.outer_circuit_dir:
        command += ["--extra-native-source", "circuit/base_witness.cu", "--extra-native-source", "rv64/circuit_interaction.cu"]
    for obj in compiled:
        command += ["--extra-object", str(obj)]
    subprocess.run(command, check=True)
    library = build / "native/libstwo-rv64-native.so"
    image = ctypes.CDLL(str(library))
    required = ["stwo_rv64_composition_role_on", "stwo_rv64_truth_composition_role_on", "stwo_rv64_curve_witness_on", "stwo_rv64_secp_witness_on"] + [f"stwo_rv64_truth_projection_{i}" for i in range(15)] + [f"launch_{i}" for i in range(47)]
    if args.outer_circuit_dir:
        required += ["stwo_circuit_base_witness_on", "stwo_circuit_om31_fractions_on", "stwo_circuit_om31_cumulative_on", "stwo_circuit_om31_composition_identity", "stwo_circuit_om31_composition_role_on"]
    missing = [name for name in required if not hasattr(image, name)]
    if missing:
        raise RuntimeError("complete resident image missing AOT exports: " + repr(missing))
    receipt = {"schema": "rv64-resident-image-build/v1", "cpu_roles": 49, "core_split_roles": args.split_core_role, "core_module_max_bytes": args.core_module_max_bytes, "truth_roles": 15, "bounded_aot_sources": lowering, "separable_device_sources": device_link, "outer_manifest_sha256": N.sha(args.outer_circuit_dir / "outer-manifest.json") if args.outer_circuit_dir else None, "library_sha256": N.sha(library), "source_sha256": {str(source): N.sha(source) for source in sources}, "gpu_qualified": False}
    (build / "image-build.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(library)


if __name__ == "__main__":
    main()
