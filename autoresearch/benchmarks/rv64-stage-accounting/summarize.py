#!/usr/bin/env python3
"""Compare retained RV64 stage receipts without summing overlapping intervals.

Example and exact invocation live with the stage-accounting qualification report.
Source cells are geometry, not observed memory traffic or hardware operations.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path


def load(path):
    return json.loads(Path(path).read_text())


def receipt(path):
    p = Path(path)
    return {"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}


def nodes(document, names):
    # Deliberately select roots only. Adopted CPU coset nodes overlap composition.
    return [n for n in document["stages"] if n["id"] in names]


def interval(document, names):
    chosen = nodes(document, names)
    if not chosen:
        return None
    usage = [n.get("process_usage") for n in chosen]
    result = {"wall_seconds": sum(n["seconds"] for n in chosen), "intervals": len(chosen)}
    for key in ("user_seconds", "system_seconds", "minor_faults", "major_faults"):
        result[key] = sum(u[key] for u in usage) if all(u is not None for u in usage) else None
    result["process_scope"] = "whole process, all threads; not additive with children or overlapping adopted intervals"
    return result


def timed(path):
    if path is None:
        return None
    raw = Path(path).read_text()
    match = re.search(r"([\d.]+)\s+real\s+([\d.]+)\s+user\s+([\d.]+)\s+sys", raw)
    if not match:
        raise ValueError(f"expected macOS /usr/bin/time -l output: {path}")
    result = dict(zip(("wall_seconds", "user_seconds", "system_seconds"), map(float, match.groups())))
    for label, key in (("maximum resident set size", "peak_rss_bytes"), ("page reclaims", "minor_faults"), ("page faults", "major_faults")):
        found = re.search(rf"^\s*(\d+)\s+{label}\s*$", raw, re.M)
        result[key] = int(found[1]) if found else None
    return result


def children(document, stage_names, wanted):
    def descend(n):
        return int(n["id"] == wanted) + sum(descend(c) for c in n.get("children") or [])
    return sum(descend(n) for n in nodes(document, stage_names))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--word16", required=True, type=Path)
    parser.add_argument("--legacy-report", required=True, type=Path)
    parser.add_argument("--legacy-stages", required=True, type=Path)
    parser.add_argument("--chip-accounting", required=True, type=Path)
    parser.add_argument("--word16-time", type=Path)
    parser.add_argument("--legacy-time", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    report = load(args.word16 / "report.json")
    modern = load(args.word16 / "stages.json")
    legacy = load(args.legacy_stages)
    old = load(args.legacy_report)["metrics"]
    chips = load(args.chip_accounting)
    source_new, source_old = report["source_cells"], old["source_cells"]
    rows = []
    definitions = [
        ("native advice", ("native_advice_preparation",), (), None, None, "narrow metadata and facts; source traffic not inferred"),
        ("provider witnesses", ("provider_source_construction",), (), source_new["main"], source_old["main"], "MAIN output cells; CPU MAIN is already constructed in native advice; not a traffic count"),
        ("immutable setup", ("immutable_setup",), ("fixed_commit",), source_new["fixed"], source_old["fixed"], "fixed source cells; scopes differ: Word16 setup vs legacy fixed commit only"),
        ("MAIN commit", ("main_commit",), ("main_commit",), source_new["main"], source_old["main"], "native source cells; LDE outputs separately modeled below"),
        ("interaction generation", ("interaction_generation",), ("authenticated_interaction",), source_new["interaction"], source_old["interaction"], "interaction output cells, excluding scratch/inversion work"),
        ("INTER commit", ("interaction_commit",), ("interaction_commit",), source_new["interaction"], source_old["interaction"], "native source cells; LDE outputs separately modeled below"),
        ("composition", ("composition_evaluation", "composition_interpolate_and_split", "composition_commit"), ("composition_evaluation", "composition_interpolate_and_split", "composition_commit"), None, None, "mixed native domains and weighted quotient extension; no source-cell traffic approximation"),
        ("sampled values", ("sampled_value_evaluation", "sampled_value_channel_mix"), ("sampled_value_evaluation", "sampled_value_channel_mix"), None, None, "polynomial evaluation and openings; source cells do not measure work"),
        ("FRI", ("fri_quotient_build_and_commit",), ("fri_quotient_build_and_commit",), None, None, "FRI geometry and coefficient reuse matter; not source cells"),
        ("decommit", ("fri_decommit", "trace_decommit"), ("fri_decommit", "trace_decommit"), None, None, "query count, openings and authentication paths; not source cells"),
        ("proof of work", ("proof_of_work",), ("proof_of_work",), None, None, "transcript-dependent variance; report separately"),
    ]
    for name, new_ids, old_ids, new_cells, old_cells, scope in definitions:
        rows.append({"stage": name, "word16": interval(modern, new_ids), "legacy": interval(legacy, old_ids), "word16_source_cells": new_cells, "legacy_source_cells": old_cells, "cell_scope": scope})
    new_time, old_time = timed(args.word16_time), timed(args.legacy_time)
    new_cells = source_new["main"] + source_new["interaction"]
    old_cells = source_old["main"] + source_old["interaction"]
    ratios = {"main_interaction_source_reduction": old_cells / new_cells, "main_source_reduction": source_old["main"] / source_new["main"], "interaction_source_reduction": source_old["interaction"] / source_new["interaction"]}
    if new_time and old_time:
        for key in ("wall_seconds", "user_seconds", "system_seconds"):
            ratios[f"{key}_old_over_new"] = old_time[key] / new_time[key]
        ratios["total_cpu_old_over_new"] = (old_time["user_seconds"] + old_time["system_seconds"]) / (new_time["user_seconds"] + new_time["system_seconds"])
        ratios["system_cpu_per_source_cell_new_over_old"] = (new_time["system_seconds"] / new_cells) / (old_time["system_seconds"] / old_cells)
    files = [args.word16 / "report.json", args.word16 / "stages.json", args.legacy_report, args.legacy_stages, args.chip_accounting]
    files.extend(p for p in (args.word16_time, args.legacy_time) if p is not None)
    result = {"schema_version": 1, "scope": "one real plain batch, qualified routes with different physical layouts; no whole-block projection", "basis": [receipt(p) for p in files], "word16_whole_process": new_time, "legacy_whole_process": old_time, "ratios": ratios, "stages": rows, "legacy_witness_outside_stages_seconds": {"ram": old["ram_witness_ns"] / 1e9, "cpu": old["cpu_witness_ns"] / 1e9}, "word16_per_chip": chips["new_per_chip"], "hash_trees_model": chips["hash_trees"], "hash_implementation": chips["hash_implementation"], "composition_model": chips["composition"], "word16_interaction_children": next((n.get("children") or [] for n in modern["stages"] if n["id"] == "interaction_generation"), []), "streaming_batches": {"word16_main": children(modern, ("main_commit",), "streaming_commit_prepare"), "legacy_main": children(legacy, ("main_commit",), "streaming_commit_prepare"), "word16_inter": children(modern, ("interaction_commit",), "streaming_commit_prepare"), "legacy_inter": children(legacy, ("interaction_commit",), "streaming_commit_prepare")}, "limitations": ["Whole-process counters include all threads active during each interval, not thread-local CPU attribution.", "Nested/adopted/overlapping intervals are not summed. Legacy CPU coset roots overlap composition.", "Source cells and native LDE words are logical geometry, not observed memory traffic or hardware operations.", "Exact source roles and hash model are applicable only to the supplied paired chip accounting layout.", "A single run is diagnostic, not a distribution or a throughput claim."]}
    if report["source_cells"] != chips["aggregate"]["new_v6_source_cells"]:
        raise ValueError("chip accounting layout does not match Word16 report source cells")
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print("| Stage | Legacy wall / user / sys s | Word16 wall / user / sys s |")
    print("|---|---:|---:|")
    def cell(value):
        if value is None:
            return "unrecorded"
        return " / ".join("?" if value[k] is None else f"{value[k]:.3f}" for k in ("wall_seconds", "user_seconds", "system_seconds"))
    for row in rows:
        print(f"| {row['stage']} | {cell(row['legacy'])} | {cell(row['word16'])} |")


if __name__ == "__main__":
    main()
