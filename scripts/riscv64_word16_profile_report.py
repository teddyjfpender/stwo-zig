#!/usr/bin/env python3
"""Summarize physical Word16 profiles without double-counting nested stages.

Observations only: this script does not verify proofs or establish authority.
"""
import argparse
import json
import math
from collections import defaultdict
from pathlib import Path


def collect(directory: Path) -> dict:
    cost = json.loads((directory / "cost.json").read_text())
    report_path = directory / "report.json"
    report = json.loads(report_path.read_text()) if report_path.exists() else {}
    schedule = report.get("coordinator_schedule", {"lanes": 1})
    concurrent = schedule.get("lanes", 1) > 1
    cpu_count = len(cost["cpu"])
    count = cpu_count + len(cost["truth"])
    paths = sorted(directory.glob("physical-*.stages.json"))
    expected = [f"physical-{i:04}.stages.json" for i in range(count)]
    if [p.name for p in paths] != expected:
        raise ValueError("Missing or unexpected physical profiles; full set required")
    totals = defaultdict(lambda: {"cpu_seconds": 0.0, "truth_seconds": 0.0,
                                   "user_seconds": 0.0, "system_seconds": 0.0})
    rows = []
    for i, path in enumerate(paths):
        profile = json.loads(path.read_text())
        kind = "cpu" if i < cpu_count else "truth"
        shape = cost[kind][i if kind == "cpu" else i - cpu_count]
        stages = {}
        peak = 0
        # Only root nodes: descendants overlap their parents and must not be added.
        for stage in profile["stages"]:
            seconds = stage["seconds"]
            if not isinstance(seconds, (int, float)) or not math.isfinite(seconds) or seconds < 0:
                raise ValueError(f"Invalid stage duration in {path}")
            name = stage["id"]
            usage = stage.get("process_usage") or {}
            entry = {"seconds": seconds, "user_seconds": usage.get("user_seconds"),
                     "system_seconds": usage.get("system_seconds"),
                     "minor_faults": usage.get("minor_faults"),
                     "major_faults": usage.get("major_faults")}
            if name in stages:
                raise ValueError(f"Duplicate root stage {name} in {path}")
            stages[name] = entry
            totals[name][f"{kind}_seconds"] += seconds
            for field in ("user_seconds", "system_seconds"):
                if not concurrent and usage.get(field) is not None:
                    totals[name][field] += usage[field]
            peak = max(peak, usage.get("process_peak_resident_bytes_at_end", 0))
        rows.append({"ordinal": i, "kind": kind, "columns": shape["columns"],
                     "native_cells": shape["native_cells"],
                     "lifted_leaf_exposure_excluding_blowup": shape["lifted_leaf_cells"],
                     "process_lifetime_peak_resident_bytes_at_proof_end": peak or None,
                     "stages": stages})
    native = {k: [sum(x["native_cells"][j] for x in cost[k]) for j in range(3)]
              for k in ("cpu", "truth")}
    if concurrent:
        for total in totals.values():
            total["user_seconds"] = None
            total["system_seconds"] = None
    return {"schema": 2, "scope": "observations only; no proof verification",
            "coordinator_schedule": schedule,
            "stage_duration_scope": "sum of worker elapsed intervals; concurrent intervals overlap and are not block wall time",
            "counter_scope": "whole process/all threads; root stages only; not valid to add overlapping intervals",
            "memory_scope": "process-lifetime peak at interval end, not a per-proof isolated peak",
            "lifting_scope": "exposure is not compression count; native-height incremental hashing reuses prefixes",
            "native_cells": native, "active": cost["active"],
            "physical": rows, "stage_totals": dict(totals)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = collect(args.directory)
    text = json.dumps(result, indent=2, allow_nan=False) + "\n"
    if args.output:
        with args.output.open("x") as output:
            output.write(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
