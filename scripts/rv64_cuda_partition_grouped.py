#!/usr/bin/env python3
"""Partition cold grouped AIR modules without changing any root expression.

Each output kernel keeps original root/power indices and field-atomically adds
into the same quotient bucket. Its y-grid is precisely the recorded group count.
The manifest is build metadata, not evidence of GPU qualification.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


def partition(source: Path, destination: Path, groups_per_module: int, max_module_bytes: int = 524288):
    text = source.read_text()
    parts = list(re.finditer(r"__device__ __noinline__ void ([A-Za-z0-9_]+)_part_(\d+)\(", text))
    entry = re.search(r'extern "C" __global__ void ([A-Za-z0-9_]+)\(', text)
    if not parts or entry is None or groups_per_module < 1 or max_module_bytes < 1:
        raise ValueError("expected a grouped native AIR module")
    name = entry.group(1)
    if any(p.group(1) != name or int(p.group(2)) != i for i, p in enumerate(parts)):
        raise ValueError("noncanonical group sequence")
    prefix = text[:parts[0].start()]
    modules = []
    first = 0
    while first < len(parts):
        count = 1
        while count < groups_per_module and first + count < len(parts):
            end = parts[first + count + 1].start() if first + count + 1 < len(parts) else entry.start()
            if end - parts[first].start() > max_module_bytes:
                break
            count += 1
        symbol = f"{name}_shard_{len(modules)}"
        end = parts[first + count].start() if first + count < len(parts) else entry.start()
        body = text[parts[first].start():end]
        kernel = text[entry.start():].replace(name + "(", symbol + "(", 1)
        # The exported dispatcher contains only selected groups; dependencies
        # are already entirely local to each generated noinline part function.
        kernel = kernel[:kernel.index("switch(blockIdx.y)")] + "switch(blockIdx.y){\n"
        for local in range(count):
            group = first + local
            kernel += f" case {local}u:{name}_part_{group}(a,b,c,offsets,p,powers,inv,out,tl,el,first+i);return;\n"
        kernel += "}}\n"
        output = destination / f"{symbol}.cu"
        output.write_text(prefix + body + kernel)
        modules.append({"source": str(output), "symbol": symbol, "first_group": first, "groups": count,
                        "sha256": hashlib.sha256(output.read_bytes()).hexdigest()})
        first += count
    return {"input": str(source), "input_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "groups": len(parts), "modules": modules}


def truth_catalog(source: Path, destination: Path, groups_per_module: int, max_module_bytes: int):
    signature = "const uint32_t*,const uint32_t*,const uint32_t*,const uint64_t*,const uint32_t*,const uint32_t*,const uint32_t*,uint32_t*,uint32_t,uint32_t,uint32_t,uint32_t"
    lines = ["#pragma once", "#include <cuda_runtime.h>", "#include <cstdint>",
             "struct StwoTruthKernelPart { const void *kernel; uint32_t groups; };",
             "struct StwoTruthKernelSpan { const StwoTruthKernelPart *parts; uint32_t count; };"]
    catalogs = []
    for role in range(7):
        original = source / f"case-{role}-domain.cu"
        if role in (0, 5, 6):
            item = partition(original, destination / f"role-{role}", groups_per_module, max_module_bytes)
            modules = item["modules"]
        else:
            text = original.read_text()
            symbol = re.search(r'extern "C" __global__ void ([A-Za-z0-9_]+)\(', text).group(1)
            groups = len(re.findall(r"__device__ __noinline__ void [A-Za-z0-9_]+_part_\d+\(", text))
            modules = [{"source": str(original), "symbol": symbol, "first_group": 0, "groups": groups}]
            item = {"input": str(original), "modules": modules, "groups": groups}
        catalogs.append(item)
        for module in modules:
            lines.append(f'extern "C" __global__ void {module["symbol"]}({signature});')
        entries = ",".join(f'{{(const void*){m["symbol"]},{m["groups"]}u}}' for m in modules)
        lines.append(f"static const StwoTruthKernelPart truth_parts_{role}[]={{" + entries + "};")
    lines.append("static const StwoTruthKernelSpan truth_catalog[]={" + ",".join(f"{{truth_parts_{i},{len(item['modules'])}u}}" for i,item in enumerate(catalogs)) + "};")
    (destination / "truth_composition_launches.h").write_text("\n".join(lines) + "\n")
    return {"roles": catalogs}

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source", type=Path)
    ap.add_argument("destination", type=Path)
    ap.add_argument("--groups-per-module", type=int, default=8)
    ap.add_argument("--truth-catalog", action="store_true")
    ap.add_argument("--max-module-bytes", type=int, default=524288)
    args = ap.parse_args()
    args.destination.mkdir(parents=True, exist_ok=True)
    for role in (0,5,6):
        if args.truth_catalog: (args.destination / f"role-{role}").mkdir(parents=True, exist_ok=True)
    manifest = truth_catalog(args.source, args.destination, args.groups_per_module, args.max_module_bytes) if args.truth_catalog else partition(args.source, args.destination, args.groups_per_module, args.max_module_bytes)
    target = args.destination / "partition.json"
    target.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"manifest": str(target), "roles": len(manifest["roles"])} if args.truth_catalog else {"manifest": str(target), "groups": manifest["groups"], "modules": len(manifest["modules"])}))


if __name__ == "__main__":
    main()
