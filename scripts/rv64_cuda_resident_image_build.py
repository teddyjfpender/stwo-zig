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
import sys

import rv64_cuda_native_library_build as N
import rv64_cuda_partition_rational as Rational
import rv64_cuda_partition_grouped as Grouped


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


def split_core(directory, build, roles):
    """Keep global RLC indices while bounding individual optimizer units."""
    original, _ = core_catalog(directory)
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
            modules = Grouped.partition(source, destination, 1, 128 << 10)["modules"]
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-root", "core-domain", "core-projection", "truth-domain", "truth-partitions", "truth-rational", "build"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--nvcc", default="/usr/local/cuda/bin/nvcc")
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("--compile-timeout", type=float, default=180)
    parser.add_argument("--split-core-role", type=int, action="append", default=[], help="Split a grouped core optimizer unit into single-group kernels")
    args = parser.parse_args()
    if not 1 <= args.jobs <= 16 or not 0 < args.compile_timeout < float("inf"):
        parser.error("bounded jobs and finite positive compiler deadline required")
    root, build = args.source_root.resolve(), args.build.resolve()
    build.mkdir(parents=True, exist_ok=True)
    logs = build / "aot-logs"
    logs.mkdir(exist_ok=True)
    core, header = core_catalog(args.core_domain.resolve())
    (build / "real_composition_launches.h").write_text(header)
    if args.split_core_role:
        core = split_core(args.core_domain.resolve(), build, args.split_core_role)
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

    def compile_one(source):
        # Full path distinguishes role-local dispatch.cpp names; source/dependency
        # and compiler pins are validated by the shared atomic cache publisher.
        name = source.stem + "-" + hashlib.sha256(str(source).encode()).hexdigest()[:12]
        obj = objects / (name + ".o")
        cached = N.compile_native(args.nvcc, version, flags, source, obj, logs / (name + ".log"), args.compile_timeout)
        print(json.dumps({"aot": str(source), "cached": cached}), flush=True)
        return obj

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        compiled = list(pool.map(compile_one, sources))
    command = [sys.executable, str(root / "scripts/rv64_cuda_native_library_build.py"), "--source-root", str(root), "--build", str(build / "native"), "--nvcc", args.nvcc, "--jobs", str(args.jobs), "--compile-timeout", str(args.compile_timeout), "--extra-native-source", "rv64/curve_witness.cu"]
    for obj in compiled:
        command += ["--extra-object", str(obj)]
    subprocess.run(command, check=True)
    library = build / "native/libstwo-rv64-native.so"
    image = ctypes.CDLL(str(library))
    required = ["stwo_rv64_composition_role_on", "stwo_rv64_truth_composition_role_on", "stwo_rv64_curve_witness_on"] + [f"stwo_rv64_truth_projection_{i}" for i in range(15)] + [f"launch_{i}" for i in range(47)]
    missing = [name for name in required if not hasattr(image, name)]
    if missing:
        raise RuntimeError("complete resident image missing AOT exports: " + repr(missing))
    receipt = {"schema": "rv64-resident-image-build/v1", "cpu_roles": 49, "core_split_roles": args.split_core_role, "truth_roles": 15, "library_sha256": N.sha(library), "source_sha256": {str(source): N.sha(source) for source in sources}, "gpu_qualified": False}
    (build / "image-build.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(library)


if __name__ == "__main__":
    main()
