#!/usr/bin/env python3
"""Retain raw cache/tape counters and summarize producer-only cache costs."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import statistics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    data = args.log.read_bytes()
    prefixes = ("GPU_OUTER_PP_PACK ", "GPU_OUTER_PLAN_PACK ", "LEAF_SEED_TAPE ",
                "GPU_OUTER_PP_CLASS pipelined check_ok", "GPU_OUTER_PLAN_CLASS check_ok")
    rows = []
    for line in data.decode(errors="replace").splitlines():
        if not line.startswith(prefixes):
            continue
        fields = {}
        for key, value in re.findall(r"(\w+)=([^\s]+)", line):
            fields[key] = int(value) if key != "class" and value.isdigit() else value
        rows.append({"event": line.split(" class=", 1)[0].split(" seeds=", 1)[0], "fields": fields, "raw": line})
    summary = {}
    for prefix in ("GPU_OUTER_PP_PACK", "GPU_OUTER_PLAN_PACK", "LEAF_SEED_TAPE"):
        selected = [r for r in rows if r["raw"].startswith(prefix)]
        adopts = [r for r in selected if " adopt " in r["raw"]]
        unpacks = [r for r in selected if " unpack " in r["raw"]]
        summary[prefix] = {
            "adopts": len(adopts), "unpacks": len(unpacks),
            "refusals": sum("refused=" in r["raw"] for r in selected),
            "cached_leaf_uses": sum(" used " in r["raw"] for r in selected),
            "last_held_bytes": adopts[-1]["fields"].get("held_bytes") if adopts else None,
            "adopted_logical_bytes": sum(r["fields"].get("logical_bytes", r["fields"].get("logical_task_bytes", 0)) for r in adopts),
            "adopted_physical_bytes": sum(r["fields"].get("physical_bytes", r["fields"].get("physical_task_bytes", 0)) for r in adopts),
        }
        for field in ("ns", "record_ns", "authority_ns", "prep_ns"):
            values = [r["fields"][field] for r in selected if field in r["fields"] and " adopt " not in r["raw"]]
            if values:
                summary[prefix][field] = {"count": len(values), "median": statistics.median(values), "min": min(values), "max": max(values)}
    result = {"schema": "rv64-m7-cache-metrics/v1", "label": "M", "source_log": str(args.log),
              "source_log_sha256": hashlib.sha256(data).hexdigest(), "summary": summary, "events": rows,
              "scope": "Whole resident producer lifetime; host-cache storage/decoding only, not proof size or device traffic."}
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
