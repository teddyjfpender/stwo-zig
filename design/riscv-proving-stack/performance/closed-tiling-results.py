#!/usr/bin/env python3
"""Parse complete closed-bundle tiling runs; do not extrapolate block times."""
import argparse
import csv
import hashlib
import json
import re
from pathlib import Path


def fields(text):
    pairs = [piece.split("=", 1) for piece in text.split()]
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate field")
    return result


def parse(path):
    raw = path.read_bytes()
    text = raw.decode()
    if "All 12 tests passed." not in text or re.search(r"\bFAIL\b|error:|memory address .* leaked", text):
        raise ValueError(f"incomplete or failed qualification: {path}")
    begin, rows, matched = {}, [], []
    for line in text.splitlines():
        if "BLOCK_V6_CLOSED_TILE_BEGIN " in line:
            row = fields(line.split("BLOCK_V6_CLOSED_TILE_BEGIN ", 1)[1])
            key = int(row["segments"])
            if key in begin:
                raise ValueError("duplicate start")
            begin[key] = row
        elif "BLOCK_V6_CLOSED_TILE_MATCHED " in line:
            matched.append(fields(line.split("BLOCK_V6_CLOSED_TILE_MATCHED ", 1)[1]))
        elif "BLOCK_V6_CLOSED_TILE verified=" in line:
            row = fields(line.split("BLOCK_V6_CLOSED_TILE ", 1)[1])
            for name, expected in (("verified", "true"), ("complete_bundle", "true"),
                                   ("standalone_root", "false"), ("negative_identity", "rejected"),
                                   ("negative_missing_proof", "rejected")):
                if row.pop(name) != expected:
                    raise ValueError(f"unqualified claim: {name}")
            strings = {"profile", "elf_sha256", "initial_rw", "final_rw"}
            row = {key: value if key in strings else int(value) for key, value in row.items()}
            for key in ("elf_sha256", "initial_rw", "final_rw"):
                if not re.fullmatch("[0-9a-f]{64}", row[key]):
                    raise ValueError("invalid source/endpoint digest")
            for key in row.keys() - strings:
                if row[key] <= 0:
                    raise ValueError(f"missing/nonpositive metric: {key}")
            phases = sum(row[name] for name in ("collection_ns", "base_ns", "recursive_ns", "verification_ns"))
            recursive = sum(row[name] for name in ("prepare_ns", "setup_ns", "prove_ns", "encode_ns"))
            if phases > row["wall_ns"] or recursive > row["recursive_ns"]:
                raise ValueError("timing partition exceeds enclosing measurement")
            row["boundary_fetches"] = row["segments"] - 1
            if row["program_fetches"] != row["cycles"] + row["boundary_fetches"]:
                raise ValueError("instruction/boundary fetch census differs")
            rows.append(row)
    if len(matched) != 1:
        raise ValueError("missing/duplicate complete comparison")
    match = matched[0]
    if match["same_elf_input_output_endpoints"] != "true" or match["fresh_global_closure"] != "true" or match["standalone_root"] != "false":
        raise ValueError("invalid equivalence scope")
    partitions = {2: {1, 4}, 3: {1, 4, 8}}.get(int(match["partitions"]))
    if partitions is None or len(rows) != len(partitions) or {r["segments"] for r in rows} != partitions or set(begin) != partitions:
        raise ValueError("missing/duplicate partition arm")
    for row in rows:
        started = begin[row["segments"]]
        for key in ("profile", "iterations", "cycles", "segments", "preflight_ns", "source_ns"):
            if str(row[key]) != started[key]:
                raise ValueError("changed workload/start record")
        if row["charged_peak_bytes"] > int(started["budget_bytes"]):
            raise ValueError("charged memory exceeds budget")
        if row["profile"] != match["profile"] or row["cycles"] != int(match["cycles"]):
            raise ValueError("changed equivalence record")
    common = ("profile", "iterations", "cycles", "elf_sha256", "initial_rw", "final_rw", "memory_events", "byte_requests")
    if len({tuple(row[key] for key in common) for row in rows}) != 1:
        raise ValueError("unmatched execution or global events")
    return {"log_sha256": hashlib.sha256(raw).hexdigest(), "rows": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", type=Path, nargs="+")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        parser.error("full source SHA required")
    runs = [parse(path) for path in args.logs]
    if len({run["log_sha256"] for run in runs}) != len(runs):
        parser.error("duplicate log")
    payload = {"source_commit": args.source_commit, "host": "Apple M5 Max, 64 GiB, 8 workers, ReleaseFast",
               "scope": "full driver publication and fresh global/native-batch verification; not standalone root",
               "memory_scope": "shared driver allocator peak, not process RSS",
               "family_times_overlap": True, "canonical_pow_timing_is_random": True, "runs": runs}
    args.output.with_suffix(".json").write_text(json.dumps(payload, indent=2) + "\n")
    rows = [row for run in runs for row in run["rows"]]
    with args.output.with_suffix(".csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
