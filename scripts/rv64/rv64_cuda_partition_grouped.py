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
import heapq


def bound_ssa_module(source: Path, operations_per_slice: int = 192):
    """Cairo-style private register banks and bounded noinline instruction slices.

    Only storage/compilation changes: every original operation and reverse-RLC
    root stays in emission order. No new committed or device-global matrix.
    """
    text = source.read_text()
    parts = list(re.finditer(r"__device__ __noinline__ void ", text))
    entry = text.index('extern "C" __global__ void')
    entry_name = re.search(r'extern "C" __global__ void ([A-Za-z0-9_]+)\(', text).group(1)
    if len(parts) != 1:
        raise ValueError("oversized module must contain exactly one root group")
    start = parts[0].start()
    lines = text[start:entry].splitlines(keepends=True)
    last, kinds = {}, {}
    for time, line in enumerate(lines):
        declaration = re.match(r"\s*const (uint32_t|OM31) (v\d+)=", line)
        if declaration:
            kinds[declaration[2]] = declaration[1]
        for value in re.findall(r"\bv\d+\b", line):
            if value not in kinds:
                raise ValueError("use before original SSA definition")
            last[value] = time
    slots, free = {}, {"uint32_t": [], "OM31": []}
    capacity = {"uint32_t": 0, "OM31": 0}
    active, lowered = [], []
    def reference(match):
        value = match[0]
        return f"base_bank[{slots[value]}]" if kinds[value] == "uint32_t" else f"bank_load(ext_bank[{slots[value]}])"
    for time, line in enumerate(lines):
        while active and active[0][0] < time:
            _, value = heapq.heappop(active)
            heapq.heappush(free[kinds[value]], slots[value])
        declaration = re.match(r"(\s*)const (uint32_t|OM31) (v\d+)=(.*);\n", line)
        if declaration:
            indent, kind, value, expression = declaration.groups()
            slot = heapq.heappop(free[kind]) if free[kind] else capacity[kind]
            if slot == capacity[kind]:
                capacity[kind] += 1
            slots[value] = slot
            heapq.heappush(active, (last[value], value))
            expression = re.sub(r"\bv\d+\b", reference, expression)
            line = f"{indent}base_bank[{slot}]={expression};\n" if kind == "uint32_t" else f"{indent}bank_store(ext_bank[{slot}],{expression});\n"
        elif "folded=add(" in line:
            line = re.sub(r"\bv\d+\b", reference, line)
        lowered.append(line)
    first = next(i for i, line in enumerate(lowered) if "OM31 folded=zero()" in line) + 1
    tail = next(i for i, line in enumerate(lowered) if "const OM31 result=" in line)
    operations, chunks = lowered[first:tail], []
    at = 0
    while at < len(operations):
        end = min(len(operations), at + operations_per_slice)
        if end < len(operations) and re.match(r"\s*const uint32_t c\d+\[", operations[end-1]):
            end -= 1
        chunks.append(operations[at:end])
        at = end
    arguments = "volatile uint32_t *base_bank,volatile OM31 *ext_bank,const uint32_t *tree0,const uint32_t *tree1,const uint32_t *tree2,const uint64_t *column_offsets,const uint32_t *parameters,const uint32_t *powers,uint32_t trace_log,uint32_t eval_log,uint32_t row"
    values = "base_bank,ext_bank,tree0,tree1,tree2,column_offsets,parameters,powers,trace_log,eval_log,row"
    helpers, calls = [], []
    for i, chunk in enumerate(chunks):
        code = "".join(chunk)
        constants = {match[1] for match in re.finditer(r"const uint32_t (c\d+)\[", code)}
        if not set(re.findall(r"\bc\d+\b", code)) <= constants:
            raise ValueError("constant array crossed a bounded slice")
        name = f"{entry_name}_bounded_step_{i}"
        helpers.append(f"__device__ __noinline__ OM31 {name}({arguments}) {{OM31 folded=zero();\n" + code + " return folded;\n}\n")
        calls.append(f" folded=add(folded,{name}({values}));\n")
    bank_helpers = """__device__ __forceinline__ OM31 bank_load(const volatile OM31 &v) {return {{{v.c0.a.a,v.c0.a.b},{v.c0.b.a,v.c0.b.b}},{{v.c1.a.a,v.c1.a.b},{v.c1.b.a,v.c1.b.b}}};}
__device__ __forceinline__ void bank_store(volatile OM31 &d,OM31 v) {d.c0.a.a=v.c0.a.a;d.c0.a.b=v.c0.a.b;d.c0.b.a=v.c0.b.a;d.c0.b.b=v.c0.b.b;d.c1.a.a=v.c1.a.a;d.c1.a.b=v.c1.a.b;d.c1.b.a=v.c1.b.a;d.c1.b.b=v.c1.b.b;}
"""
    private = f" volatile uint32_t base_bank[{max(1,capacity['uint32_t'])}]; volatile OM31 ext_bank[{max(1,capacity['OM31'])}];\n"
    body = lowered[:first]
    body.insert(1, private)
    source.write_text(text[:start] + bank_helpers + "".join(helpers) + "".join(body) + "".join(calls) + "".join(lowered[tail:]) + text[entry:])
    return {"base_register_slots": capacity["uint32_t"], "secure_register_slots": capacity["OM31"], "private_frame_bytes": 4*capacity["uint32_t"]+32*capacity["OM31"], "instruction_slices": len(chunks), "operations_per_slice": operations_per_slice}

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
        bounded = bound_ssa_module(output) if output.stat().st_size > max_module_bytes else None
        modules.append({"source": str(output), "symbol": symbol, "first_group": first, "groups": count,
                        "sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "bounded": bounded})
        first += count
    return {"input": str(source), "input_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "groups": len(parts), "modules": modules}


def truth_catalog(source: Path, destination: Path, groups_per_module: int, max_module_bytes: int, tail_first_group: int | None = None):
    signature = "const uint32_t*,const uint32_t*,const uint32_t*,const uint64_t*,const uint32_t*,const uint32_t*,const uint32_t*,uint32_t*,uint32_t,uint32_t,uint32_t,uint32_t"
    lines = ["#pragma once", "#include <cuda_runtime.h>", "#include <cstdint>",
             "struct StwoTruthKernelPart { const void *kernel; uint32_t groups; };",
             "struct StwoTruthKernelSpan { const StwoTruthKernelPart *parts; uint32_t count; };"]
    catalogs = []
    roles = sorted(int(match[1]) for path in source.glob("case-*-domain.cu")
                   if (match := re.fullmatch(r"case-(\d+)-domain\.cu", path.name)))
    if roles not in [list(range(7)), list(range(10)), list(range(15))]:
        raise ValueError("truth catalogue must contain the admitted seven, ten or fifteen contiguous cases")
    for role in roles:
        original = source / f"case-{role}-domain.cu"
        if role in (0, 5, 6, 7) or role >= 10:
            (destination / f"role-{role}").mkdir(parents=True, exist_ok=True)
            item = partition(original, destination / f"role-{role}", groups_per_module, max_module_bytes)
            modules = item["modules"]
            if role == 7 and tail_first_group is not None:
                # Keep an already compiled prefix while bounding cold inverse/
                # prefix roots independently. Global RLC indices never move.
                single_dir = destination / "role-7-single"
                single_dir.mkdir(parents=True, exist_ok=True)
                single = partition(original, single_dir, 1, min(max_module_bytes, 131072))
                prefix = [m for m in modules if m["first_group"] + m["groups"] <= tail_first_group]
                if not prefix or prefix[-1]["first_group"] + prefix[-1]["groups"] != tail_first_group or tail_first_group >= item["groups"]:
                    raise ValueError("truth tail must begin at an existing partition boundary")
                modules = prefix + single["modules"][tail_first_group:]
                item["modules"] = modules
                item["tail_first_group"] = tail_first_group
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

def extend_catalog(base: str, generated: str, first_new_role: int = 10):
    """Append new roles without relabelling any qualified existing partition.

    Reusing an old object with a newly partitioned same-named symbol is unsafe:
    its y-grid may cover different original groups. Keep base declarations and
    exact entries byte-for-byte and copy only the extension's new definitions.
    """
    pattern = r"static const StwoTruthKernelSpan truth_catalog\[\]=\{(.*?)\};"
    old = re.search(pattern, base)
    new = re.search(pattern, generated)
    if not old or not new or base[old.end():].strip():
        raise ValueError("expected terminal truth catalogue")
    entries = lambda match: re.findall(r"\{truth_parts_(\d+),\d+u\}", match[1])
    old_ids, new_ids = list(map(int, entries(old))), list(map(int, entries(new)))
    if old_ids != list(range(first_new_role)) or new_ids != list(range(15)):
        raise ValueError("catalogue extension requires exact original ten and new fifteen roles")
    additions = []
    for line in generated[:new.start()].splitlines():
        role = re.search(r"(?:rv64_truth_domain_|truth_parts_)(\d+)", line)
        if role and int(role[1]) >= first_new_role:
            additions.append(line)
    if not additions:
        raise ValueError("missing new role declarations")
    suffix = re.findall(r"\{truth_parts_\d+,\d+u\}", new[1])[first_new_role:]
    return (base[:old.start()] + "\n".join(additions) + "\n" +
            "static const StwoTruthKernelSpan truth_catalog[]={" + old[1] +
            "," + ",".join(suffix) + "};\n")

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source", type=Path)
    ap.add_argument("destination", type=Path)
    ap.add_argument("--groups-per-module", type=int, default=8)
    ap.add_argument("--truth-catalog", action="store_true")
    ap.add_argument("--max-module-bytes", type=int, default=524288)
    ap.add_argument("--truth-tail-first-group", type=int, help="Keep role7 prefix partitions and split its cold suffix into individual constraint groups")
    ap.add_argument("--truth-base-catalog", type=Path, help="Append curves while preserving qualified0..9 declarations and partition entries")
    args = ap.parse_args()
    if args.truth_base_catalog and not args.truth_catalog:
        ap.error("--truth-base-catalog requires --truth-catalog")
    args.destination.mkdir(parents=True, exist_ok=True)
    for role in (0,5,6,7):
        if args.truth_catalog: (args.destination / f"role-{role}").mkdir(parents=True, exist_ok=True)
    manifest = truth_catalog(args.source, args.destination, args.groups_per_module, args.max_module_bytes, args.truth_tail_first_group) if args.truth_catalog else partition(args.source, args.destination, args.groups_per_module, args.max_module_bytes)
    if args.truth_base_catalog:
        header = args.destination / "truth_composition_launches.h"
        base = args.truth_base_catalog.read_text()
        header.write_text(extend_catalog(base, header.read_text()))
        manifest["preserved_base_catalog_sha256"] = hashlib.sha256(base.encode()).hexdigest()
    target = args.destination / "partition.json"
    target.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"manifest": str(target), "roles": len(manifest["roles"])} if args.truth_catalog else {"manifest": str(target), "groups": manifest["groups"], "modules": len(manifest["modules"])}))


if __name__ == "__main__":
    main()
