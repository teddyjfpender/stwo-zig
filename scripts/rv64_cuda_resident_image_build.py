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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-root", "core-domain", "truth-domain", "truth-partitions", "truth-rational", "build"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--nvcc", default="/usr/local/cuda/bin/nvcc")
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("--compile-timeout", type=float, default=180)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 16 or not 0 < args.compile_timeout < float("inf"):
        parser.error("bounded jobs and finite positive compiler deadline required")
    root, build = args.source_root.resolve(), args.build.resolve()
    build.mkdir(parents=True, exist_ok=True)
    logs = build / "aot-logs"
    logs.mkdir(exist_ok=True)
    core, header = core_catalog(args.core_domain.resolve())
    (build / "real_composition_launches.h").write_text(header)
    (build / "truth_composition_launches.h").write_bytes((args.truth_partitions / "truth_composition_launches.h").read_bytes())
    sources = core + truth_sources(args.truth_domain.resolve(), args.truth_partitions.resolve())
    for role in range(15):
        source = args.truth_rational / f"stwo_rv64_truth_projection_{role}.cu"
        result = Rational.partition(source.resolve(), build / "rational" / str(role), 16)
        sources.extend(map(Path, result))
    sources += [root / "tests/cuda/rv64/real_composition_native.cu", root / "tests/cuda/rv64/truth_composition_native.cu"]
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
    required = ["stwo_rv64_composition_role_on", "stwo_rv64_truth_composition_role_on"] + [f"stwo_rv64_truth_projection_{i}" for i in range(15)]
    missing = [name for name in required if not hasattr(image, name)]
    if missing:
        raise RuntimeError("complete resident image missing AOT exports: " + repr(missing))
    receipt = {"schema": "rv64-resident-image-build/v1", "cpu_roles": 49, "truth_roles": 15, "library_sha256": N.sha(library), "source_sha256": {str(source): N.sha(source) for source in sources}, "gpu_qualified": False}
    (build / "image-build.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(library)


if __name__ == "__main__":
    main()
