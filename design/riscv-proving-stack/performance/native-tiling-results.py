#!/usr/bin/env python3
"""Check completed same-execution 1/3/9 native proof comparisons, retaining stages."""
import argparse
import hashlib
import json
from pathlib import Path
import re


def fields(line, marker):
    values = dict(re.findall(r"(\w+)=([^\s]+)", line.split(marker + " ", 1)[1]))
    return {k: int(v) if v.isdecimal() else v for k, v in values.items()}


def parse(path):
    raw = path.read_bytes()
    text = raw.decode()
    if not re.search(r"All \d+ tests passed\.", text) or "FAIL (" in text:
        raise ValueError("Incomplete or failed test run")
    runs, current, equivalence = [], None, {}
    for line in text.splitlines():
        if "BLOCK_V6_SCALE_SOURCE " in line:
            if current is not None:
                raise ValueError("Unfinished native arm")
            current = {"source": fields(line, "BLOCK_V6_SCALE_SOURCE"), "proof_stages": []}
        for marker in ("BLOCK_V6_DIRECT_NATIVE", "BLOCK_V6_BATCH_UPPER"):
            if marker + " " in line:
                if current is None:
                    raise ValueError("Proof outside native arm")
                current["proof_stages"].append(fields(line, marker))
        if "BLOCK_V6_TILE " in line:
            if current is None:
                raise ValueError("Result without native arm")
            current["result"] = fields(line, "BLOCK_V6_TILE")
            runs.append(current)
            current = None
        if "BLOCK_V6_TILE_EQUIVALENCE " in line:
            row = fields(line, "BLOCK_V6_TILE_EQUIVALENCE")
            if row["profile"] in equivalence:
                raise ValueError("Repeated profile; give each repetition its own log")
            equivalence[row["profile"]] = row
    if current is not None or not runs:
        raise ValueError("Incomplete arms")
    for run in runs:
        source, result, stages = run["source"], run["result"], run["proof_stages"]
        for key in ("profile", "segments", "cycles", "native_ns"):
            if source[key] != result[key]:
                raise ValueError("Source/result mismatch")
        count = result["segments"]
        if count not in (1, 3, 9) or source["workers"] != 8 or source["cycles"] != 13 * source["base_steps"]:
            raise ValueError("Unexpected execution geometry")
        if [s.get("children") for s in stages] != ([8, 1, None] if count == 9 else [count]):
            raise ValueError("Incorrect proof tree")
        if count == 9 and (stages[-1]["segments"] != 9 or stages[-1]["child_batches"] != 2):
            raise ValueError("Incorrect upper proof")
        for stage in stages:
            if stage["profile"] != result["profile"] or stage["verified"] != "true" or stage["globals_open"] != "true":
                raise ValueError("Proof verification/scope mismatch")
            if stage["recursive_ns"] != sum(stage[k] for k in ("prepare_ns", "setup_ns", "prove_ns", "encode_verify_ns")):
                raise ValueError("Proof timing partition mismatch")
        for key in ("recursive_ns", "air_cells", "g_rows"):
            if result[key] != sum(s[key] for s in stages):
                raise ValueError("Tree work/timing mismatch")
        if (result["verified"] != "true" or result["globals_open"] != "true" or
                result["phase_sum_ns"] != result["native_ns"] + result["recursive_ns"] or
                result["root_bytes"] != stages[-1]["proof_bytes"] or result["charged_peak_bytes"] <= 0):
            raise ValueError("Invalid final measurement")
    comparisons = {}
    for profile in {r["result"]["profile"] for r in runs}:
        rows = [r["result"] for r in runs if r["result"]["profile"] == profile]
        eq = equivalence[profile]
        if (sorted(r["segments"] for r in rows) != [1, 3, 9] or
                len({r["execution_digest"] for r in rows}) != 1 or
                {r["cycles"] for r in rows} != {eq["cycles"]} or
                eq["endpoints_match"] != "true" or eq["partitions"] != "1,3,9" or eq["globals_open"] != "true"):
            raise ValueError("Missing matched execution comparison")
        baseline = next(r for r in rows if r["segments"] == 9)
        comparisons[profile] = {str(r["segments"]): {key: baseline[key] / r[key] for key in
            ("phase_sum_ns", "recursive_ns", "air_cells", "g_rows", "charged_peak_bytes")} for r in rows}
    return {"log": path.name, "sha256": hashlib.sha256(raw).hexdigest(), "runs": runs, "nine_over_candidate": comparisons}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", nargs="+", type=Path)
    args = parser.parse_args()
    print(json.dumps({"schema": "stwo-zig/native-tiling/v1",
        "scope": "Fixed ADDI/JAL execution, 1/3/9 native STARKs each reduced to one recursive proof; global obligations open",
        "timing": "Phase sums; charged allocator peak includes retained native inputs and test probes, excludes thread stacks and untracked allocations",
        "samples": [parse(path) for path in args.logs]}, indent=2))


if __name__ == "__main__":
    main()
