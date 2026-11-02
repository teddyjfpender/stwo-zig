#!/usr/bin/env python3
"""Model native-height streaming hasher-state visits, not measured hash time.

Input: JSON object mapping a tree name to {native_log: column_count}.
The source+LDE preparation budget and max-column limit follow commit_ops.
No witness, commitment, or transcript is constructed by this diagnostic.
"""
import argparse
import json


def account(histogram, cap, budget, blowup):
    columns = sorted(log for log, count in histogram.items() for _ in range(count))
    batches = []
    cursor = 0
    visits = 0
    while cursor < len(columns):
        end, used = cursor, 0
        while end < len(columns) and end - cursor < cap:
            charge = (4 << columns[end]) * (1 + (1 << blowup))
            if end != cursor and (charge > budget or used > budget - charge):
                break
            used += charge
            end += 1
        groups = {}
        for log in columns[cursor:end]:
            groups[log] = groups.get(log, 0) + 1
        # addColumns invokes one updateHashers per equal-height group.
        wave_visits = sum(1 << (log + blowup) for log in groups)
        visits += wave_visits
        batches.append({"columns": end - cursor, "preparation_bytes": used,
                        "native_height_groups": groups, "hasher_state_visits": wave_visits})
        cursor = end
    return {"cap_columns": cap, "byte_budget": budget,
            "batch_count": len(batches), "hasher_state_visits": visits,
            "source_cells": sum(1 << log for log in columns),
            "lde_cells": sum(1 << (log + blowup) for log in columns),
            "batches": batches}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("histogram")
    parser.add_argument("--budget-mib", type=int, default=256)
    parser.add_argument("--blowup", type=int, default=1)
    args = parser.parse_args()
    if args.budget_mib <= 0 or not 0 <= args.blowup <= 20:
        parser.error("invalid budget or blowup")
    raw = json.load(open(args.histogram))
    result = {}
    for name, histogram in raw.items():
        h = {int(log): int(count) for log, count in histogram.items()}
        if any(not 1 <= log <= 30 or count < 0 for log, count in h.items()):
            parser.error("invalid native log or column count")
        result[name] = [account(h, cap, args.budget_mib << 20, args.blowup) for cap in (8, 64)]
    print(json.dumps({"scope": "modeled updateHashers state visits; excludes expansion, finalization, parents, actual compression counts, compiler cache traffic and timing", "trees": result}, indent=2))


if __name__ == "__main__":
    main()
