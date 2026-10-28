#!/usr/bin/env python3
"""Parse completed, matched three-arm joint-proof experiments (never block time)."""
import argparse
import csv
import hashlib
import json
import re
from pathlib import Path


def parse(path):
    raw = path.read_bytes()
    text = raw.decode()
    if "All 16 tests passed." not in text or re.search(r"\bFAIL\b|error:|memory address .* leaked", text):
        raise ValueError(f"incomplete/failed qualification: {path}")
    rows = []
    for line in text.splitlines():
        match = re.search(r"BLOCK_V6_(JOINT|PRUNED) (.*)$", line)
        if not match:
            continue
        fields = dict(item.split("=", 1) for item in match[2].split())
        if fields.pop("globals_open") != "true":
            raise ValueError("unsupported closed/global authority claim")
        pruned = match[1] == "PRUNED" or fields.pop("reuse", "false") == "true"
        joint = fields.pop("joint", "true")
        if joint not in ("true", "false") or fields["ram"] not in ("true", "false"):
            raise ValueError("invalid Boolean")
        row = {"arm": "pruned" if pruned else "joint" if joint == "true" else "separate",
               "profile": fields.pop("profile"), "ram": fields.pop("ram") == "true"}
        row.update({key: int(value) for key, value in fields.items()})
        required = {"mode", "cycles", "seed", "prove_ns", "verify_ns", "stark_bytes", "starks"}
        if not required <= row.keys() or set(fields) - required - {"aliases", "projections", "alias_cells"}:
            raise ValueError("unknown or missing metric")
        for key in required - {"mode"}:
            if row[key] <= 0:
                raise ValueError("nonpositive measurement")
        if row["starks"] != (2 if row["arm"] == "separate" else 1):
            raise ValueError("incorrect STARK count")
        if pruned and not (0 < row.get("aliases", 0) < row.get("projections", 0) and row.get("alias_cells", 0) > 0):
            raise ValueError("missing elimination census")
        rows.append(row)
    expected = {(profile, mode, ram, arm)
                for profile in ("diagnostic_q8_pow0", "csp_q70_pow26")
                for mode, ram in ((0, True), (1, True), (1, False))
                for arm in ("separate", "joint", "pruned")}
    keys = [(r["profile"], r["mode"], r["ram"], r["arm"]) for r in rows]
    if len(keys) != len(expected) or set(keys) != expected:
        raise ValueError("missing, duplicate or foreign comparison arm")
    if len({(r["seed"], r["cycles"]) for r in rows}) != 1:
        raise ValueError("unmatched workload or transcript seed")
    return {"log_sha256": hashlib.sha256(raw).hexdigest(), "rows": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", type=Path, nargs="+")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        parser.error("source commit must be a full SHA")
    runs = [parse(path) for path in args.logs]
    if len({run["rows"][0]["seed"] for run in runs}) != len(runs):
        parser.error("duplicate transcript seed")
    if len({row["cycles"] for run in runs for row in run["rows"]}) != 1:
        parser.error("unmatched workload across runs")
    data = {"source_commit": args.source_commit, "host": "Apple M5 Max, 64 GiB, 8 workers, ReleaseFast",
            "scope": "native/companion proof phase, open globals; not full block or command latency",
            "memory_measured": False, "canonical_pow_timing_is_random": True, "runs": runs}
    args.output.with_suffix(".json").write_text(json.dumps(data, indent=2) + "\n")
    rows = [row for run in runs for row in run["rows"]]
    columns = list(dict.fromkeys(key for row in rows for key in row))
    with args.output.with_suffix(".csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, columns)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
