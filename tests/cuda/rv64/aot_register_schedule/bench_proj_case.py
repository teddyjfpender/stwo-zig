#!/usr/bin/env python3
"""Emit bench_proj_case.h for bench_projection.cu from a projection case source."""
import re, sys
src, before, after, name = sys.argv[1:5]
t = open(src).read()
masks = {}
for tree, k in re.findall(r"tree(\d)\[column_offsets\[(\d+)\]", t):
    if masks.setdefault(int(k), int(tree)) != int(tree): raise SystemExit("mask in two trees")
count = max(masks) + 1 if masks else 0
params = max([int(x) for x in re.findall(r"parameters\+(\d+)u", t)] + [0]) // 8 + 1
public = max([int(x) for x in re.findall(r"public_values\[(\d+)u?\]", t)] + [0]) + 1
lanes = int(re.search(r"stride=\(uint64_t\(1\)<<trace_log\)\*(\d+)u;", t)[1])
print(f'#pragma once\n#define BENCH_BEFORE {before}\n#define BENCH_AFTER {after}\n#define BENCH_CASE_NAME "{name}"')
print(f"static const uint32_t mask_count={count}, parameter_count={params}, public_count={public}, lanes={lanes};")
print("static const uint8_t mask_tree[]={" + ",".join(str(masks.get(k, 255)) for k in range(max(count, 1))) + "};")
