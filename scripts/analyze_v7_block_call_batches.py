#!/usr/bin/env python3
"""Diagnostic call census of retained contiguous execution geometry.

This reads host replay evidence, not proof authority. Padding below counts call
slots only; it is neither actual AIR geometry nor a proving-time prediction.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path


FAMILIES = ("keccak_calls", "recovery_calls", "sha_calls")


def natural(value, label, positive=False):
    if type(value) is not int or value < int(positive):
        raise ValueError(f"invalid {label}: {value!r}")
    return value


def load(path):
    raw = path.read_bytes()
    records = [json.loads(line) for line in raw.splitlines() if line.strip()]
    summaries = [r for r in records if r.get("kind") == "summary"]
    rows = [r for r in records if "target" in r]
    if len(summaries) != 1 or len(rows) + 1 != len(records) or not rows:
        raise ValueError("expected only execution windows and one summary")
    summary = summaries[0]
    if summary["segments_checked"] != len(rows):
        raise ValueError("incomplete geometry census")
    next_cycle = 1
    for index, row in enumerate(rows):
        if row["target"] != index or row["segments"] != len(rows):
            raise ValueError("noncanonical window order or count")
        if row["global_first_cycle"] != next_cycle:
            raise ValueError("overlapping, missing or reordered cycle interval")
        cycles = natural(row["cycles"], "cycles", positive=True)
        calls = sum(natural(row[k], k) for k in FAMILIES)
        if calls > cycles:
            raise ValueError("more retired precompile calls than cycles")
        next_cycle += cycles
    if summary["cycles"] != next_cycle - 1:
        raise ValueError("summary cycle count disagrees with contiguous windows")
    return rows, {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "windows": len(rows),
        "cycles": next_cycle - 1,
        "evidence": "host replay geometry; not a verified block proof",
    }


def padded_calls(calls):
    return 0 if calls == 0 else 1 << (calls - 1).bit_length()


def analyze(path, rows, evidence):
    families = {}
    for family in FAMILIES:
        counts = [row[family] for row in rows]
        total = sum(counts)
        variants = []
        for width in sorted({1, 2, 4, 8, 16, 32, 64, len(rows)}):
            if width > len(rows):
                continue
            groups = [sum(counts[i:i + width]) for i in range(0, len(rows), width)]
            active = sum(x > 0 for x in groups)
            variants.append({
                "consecutive_windows_per_batch": width,
                "active_arithmetic_inventories": active,
                "inventory_reduction_factor": sum(x > 0 for x in counts) / active if active else None,
                "maximum_calls_in_batch": max(groups),
                "padded_call_slots_proxy": sum(map(padded_calls, groups)),
                "padding_ratio_proxy": sum(map(padded_calls, groups)) / total if total else None,
            })
        families[family] = {
            "calls": total,
            "active_windows": sum(x > 0 for x in counts),
            "maximum_calls_in_window": max(counts),
            "variants": variants,
        }
    return {"source": evidence, "families": families}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("geometry", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--windows-tsv", required=True, type=Path)
    args = parser.parse_args()
    result, table = [], []
    invariant = None
    for path in args.geometry:
        rows, evidence = load(path)
        signature = (evidence["cycles"], *(sum(r[k] for r in rows) for k in FAMILIES))
        if invariant is not None and signature != invariant:
            raise ValueError("schedules disagree on total execution or calls")
        invariant = signature
        result.append(analyze(path, rows, evidence))
        for row in rows:
            table.append({"schedule": path.parent.name, **{k: row[k] for k in
                         ("target", "global_first_cycle", "cycles", *FAMILIES)}})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.windows_tsv.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        "schema": 1,
        "scope": "retained workload census and consecutive family-batching model",
        "limitations": [
            "Host replay does not establish proof correctness.",
            "Different historical schedules do not imply current v7 segment boundaries.",
            "Call-slot padding excludes AIR rows per operation, minimum domains and shared tables.",
            "Inventory reduction is not an end-to-end speedup; window custody projections remain.",
        ],
        "schedules": result,
    }, indent=2) + "\n")
    with args.windows_tsv.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(table[0]), delimiter="\t")
        writer.writeheader()
        writer.writerows(table)


if __name__ == "__main__":
    main()
