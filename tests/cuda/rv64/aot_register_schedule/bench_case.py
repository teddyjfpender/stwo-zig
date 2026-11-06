#!/usr/bin/env python3
"""Emit bench_case.h for bench_truth.cu from a single-group AOT shard source."""
import re, sys
src, before, after, name = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
t = open(src).read()
masks = {}
for tree, k in re.findall(r"tree(\d)\[column_offsets\[(\d+)\]", t):
    if masks.setdefault(int(k), int(tree)) != int(tree): raise SystemExit("mask in two trees")
count = max(masks) + 1
params = max([int(x) for x in re.findall(r"parameters\+(\d+)u", t)] + [0]) // 8 + 1
powers = max(int(x) for x in re.findall(r"powers\+(\d+)u", t)) // 8 + 1
groups = max(1, len(re.findall(r"\bcase \d+u:", t[t.index('extern "C" __global__'):])))
print(f'#pragma once\n#define BENCH_BEFORE {before}\n#define BENCH_AFTER {after}\n#define BENCH_CASE_NAME "{name}"')
print(f"static const uint32_t mask_count={count}, parameter_count={params}, power_count={powers}, groups={groups};")
print("static const uint8_t mask_tree[]={" + ",".join(str(masks.get(k, 255)) for k in range(count)) + "};")
