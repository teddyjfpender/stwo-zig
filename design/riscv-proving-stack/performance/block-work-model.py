#!/usr/bin/env python3
"""Reproduce the block memory geometry comparison from recorded source counts.

This is a cell-count model, not a prover timing or peak-memory benchmark.
The counts are from block-v5-performance-roadmap-v1.md, and the column widths
are pinned below to the protocol versions cited in the design note.
"""

import argparse
import json


TOTAL_EVENTS = 356_303_914
REGISTER_EVENTS = 298_427_187
RW_EVENTS = 57_876_727
assert REGISTER_EVENTS + RW_EVENTS == TOTAL_EVENTS


def scenario(name: str, events: int, lanes: int, columns: int, row_log: int) -> dict:
    rows = 1 << row_log
    capacity = lanes * rows
    instances = (events + capacity - 1) // capacity
    committed_cells = instances * rows * columns
    active_rows = (events + lanes - 1) // lanes
    return {
        "name": name,
        "events": events,
        "lanes": lanes,
        "columns_per_row": columns,
        "row_log": row_log,
        "instances": instances,
        "committed_m31_cells": committed_cells,
        "raw_trace_gib": round(committed_cells * 4 / (1 << 30), 3),
        "padding_ratio": round(committed_cells / (active_rows * columns), 6),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--row-log", type=int, default=22)
    args = parser.parse_args()
    if not 1 <= args.row_log <= 24:
        parser.error("row log must be in [1, 24]")

    cases = [
        scenario("measured-census legacy all-memory", TOTAL_EVENTS, 1, 142, args.row_log),
        scenario("counterfactual mode1 word-v4", RW_EVENTS, 1, 107, args.row_log),
        scenario("counterfactual mode1 RAM2", RW_EVENTS, 2, 170, args.row_log),
    ]
    baseline = cases[0]["committed_m31_cells"]
    for case in cases:
        case["baseline_cell_ratio"] = round(baseline / case["committed_m31_cells"], 4)
    print(json.dumps({
        "scope": "geometry only; no speed, peak memory, or proof qualification claim",
        "recorded_block": "24,628,607",
        "source": "autoresearch/notes/2026-09-24-ethereum-block-delivery/block-v5-performance-roadmap-v1.md",
        "cases": cases,
    }, indent=2))


if __name__ == "__main__":
    main()
