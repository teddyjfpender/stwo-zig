#!/usr/bin/env python3
"""Account native encoding work from a complete execution census, not timings.

Metadata comes from src/riscv_frontend_encoding_census.zig. V7's physical
projection/access interactions are intentionally excluded from the native main
cell total: the compatibility interaction width is a separate comparison only.
No result is a proof, complete proof geometry, or a latency prediction.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path


def integer(value, label):
    if type(value) is not int or value < 0:
        raise ValueError(f"invalid nonnegative integer: {label}")
    return value


def shard_geometry(count, cap):
    """The exact current min-log1/power-of-two/full-shards-first convention."""
    integer(count, "family population")
    if type(cap) is not int or cap < 2 or cap & (cap - 1):
        raise ValueError("shard cap must be a power of two >=2")
    full, tail = divmod(count, cap)
    return full + bool(tail), full * cap + (max(2, 1 << (tail - 1).bit_length()) if tail else 0)


def validate(summary, segments, metadata):
    if summary.get("schema") != "stwo-retained-ethereum-bounded-execution-census-v1" or summary.get("scope") != "full_guest_execution_census_without_proving" or summary.get("proof_verified") is not False:
        raise ValueError("expected explicitly unproved full-guest execution census")
    if metadata.get("schema") != "stwo.riscv.typed-encoding-work-metadata.v1" or metadata.get("proof_authority") is not False:
        raise ValueError("invalid typed metadata scope")
    families = metadata["families"]
    if not families:
        raise ValueError("empty typed family roster")
    integer(summary["expected_cycles"], "expected cycles")
    integer(summary["segment_cycles"], "segment cycles")
    names = [item["name"] for item in families]
    if len(set(names)) != len(names) or names != summary["family_names"]:
        raise ValueError("typed family names/order differ from execution census")
    for family in families:
        for field in ("main_columns", "direct_constraints", "lookup_events", "compatibility_interaction_columns"):
            integer(family[field], field)
        if len(bytes.fromhex(family["authority_digest"])) != 32:
            raise ValueError("invalid typed authority digest")
        candidate_width = integer(family.get("candidate_main_columns", family["main_columns"]), "candidate width")
        if candidate_width > family["main_columns"]:
            raise ValueError("alias candidate widens main columns")
    if len(segments) != summary["segments"] or not segments:
        raise ValueError("missing execution segment")
    next_cycle = 1
    totals = [0] * len(names)
    for index, segment in enumerate(segments):
        if segment["index"] != index or segment["first_cycle"] != next_cycle:
            raise ValueError("gap, duplicate, or reordered execution span")
        counts = segment["counts"]
        cycles = integer(counts["cycles"], "cycles")
        if cycles == 0 or cycles > summary["segment_cycles"] or (index + 1 < len(segments) and cycles != summary["segment_cycles"]):
            raise ValueError("invalid execution segment length")
        if len(counts["families"]) != len(names):
            raise ValueError("family population width differs")
        for i, value in enumerate(counts["families"]):
            totals[i] += integer(value, "family rows")
        if sum(counts["families"]) != counts["core_rows"] or counts["core_rows"] > cycles:
            raise ValueError("native row accounting differs")
        next_cycle += cycles
        if index and segment["entry_pc"] != segments[index - 1]["exit_pc"]:
            raise ValueError("execution PC continuity differs")
        if (segment["terminal"] is not None) != (index == len(segments) - 1):
            raise ValueError("missing terminal or premature completion")
    if segments[-1]["terminal"] != "halt_flag":
        raise ValueError("execution did not complete at the expected halt flag")
    if totals != summary["counts"]["families"] or next_cycle - 1 != summary["counts"]["cycles"] or next_cycle - 1 != summary["expected_cycles"]:
        raise ValueError("segment totals differ from complete census")
    return families


def account(segments, families, group, cap):
    if type(group) is not int or group < 1:
        raise ValueError("positive execution coalescing factor required")
    rows = []
    for i, family in enumerate(families):
        population = shards = padded = 0
        for start in range(0, len(segments), group):
            count = sum(segment["counts"]["families"][i] for segment in segments[start:start + group])
            n, cells = shard_geometry(count, cap)
            population += count
            shards += n
            padded += cells
        width = family["main_columns"]
        candidate = family.get("candidate_main_columns", width)
        rows.append(dict(family=family["name"], rows=population, shards=shards,
                         padded_rows=padded, main_columns=width,
                         main_cells=width * padded, minimum_main_cells=width * population,
                         isolated_alias_candidate_cells=candidate * padded,
                         compatibility_interaction_cells=family["compatibility_interaction_columns"] * padded,
                         lookup_requests=family["lookup_events"] * population,
                         direct_constraint_row_evaluations=family["direct_constraints"] * padded))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--census", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    summary_path = options.census / "summary.json"
    segments_path = options.census / "segments.jsonl"
    summary = json.loads(summary_path.read_text())
    segments = [json.loads(line) for line in segments_path.read_text().splitlines() if line.strip()]
    metadata = json.loads(options.metadata.read_text())
    families = validate(summary, segments, metadata)
    if options.output.exists():
        raise ValueError("output must be a new directory")
    options.output.mkdir(parents=True)
    # Preserve the actual compiled metadata, not a dependency on a temp path.
    (options.output / "encoding-metadata.json").write_bytes(options.metadata.read_bytes())
    baseline = account(segments, families, 1, 65536)
    with (options.output / "native-families.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(baseline[0]))
        writer.writeheader()
        writer.writerows(sorted(baseline, key=lambda row: row["main_cells"], reverse=True))
    grid = []
    for group in (1, 4, 16, len(segments)):
        for cap in (65536, 131072, 524288, 2097152):
            result = account(segments, families, group, cap)
            largest = max(sum(shard_geometry(sum(segment["counts"]["families"][i]
                              for segment in segments[start:start + group]), cap)[0]
                              for i in range(len(families))) for start in range(0, len(segments), group))
            grid.append(dict(execution_coalescing=group, shard_rows=cap,
                             shard_cap_matches_current_rule=cap == 65536,
                             maximum_native_shards_per_partition=largest,
                             native_component_limit_satisfied=largest <= metadata["maximum_native_components"],
                             admission_qualified=False,
                             canonical_partition=group == 1 and cap == 65536,
                             native_shards=sum(row["shards"] for row in result),
                             main_cells=sum(row["main_cells"] for row in result),
                             padded_rows=sum(row["padded_rows"] for row in result)))
    report = dict(schema="stwo.riscv.frontend-work-ledger.v1", proof_verified=False,
                  timing_prediction=False,
                  scope="native main encoding only; excludes V7 access witnesses/interactions, providers, PCS expansion and recursion",
                  inputs={name: hashlib.sha256(path.read_bytes()).hexdigest()
                          for name, path in (("summary.json", summary_path), ("segments.jsonl", segments_path),
                                             ("encoding-metadata.json", options.metadata))},
                  cycles=summary["expected_cycles"], execution_segments=len(segments),
                  baseline=dict(native_shards=sum(row["shards"] for row in baseline),
                                main_cells=sum(row["main_cells"] for row in baseline),
                                minimum_main_cells=sum(row["minimum_main_cells"] for row in baseline),
                                isolated_alias_candidate_cells=sum(row["isolated_alias_candidate_cells"] for row in baseline)),
                  counterfactuals=grid)
    (options.output / "ledger.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["baseline"], sort_keys=True))


if __name__ == "__main__":
    main()
