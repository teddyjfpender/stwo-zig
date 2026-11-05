#!/usr/bin/env python3
"""RV64 M4-M7 progress ledger (stream measure owns the schema: vectors/reports/progress/SCHEMA.md).

  python3 scripts/rv64_progress.py append RECEIPT --stream S --milestone M4 [--label M] [--notes TEXT]
          [--commit SHA] [--byte-identical-to NAME] [--date YYYY-MM-DD] [--dry-run]
      Derive one row from a harness receipt (rv64-m3-receipt/v1, rv64-m4-receipt/v2 or a scale
      receipt) and append it to vectors/reports/progress/<stream>.jsonl. Validates the row.
  python3 scripts/rv64_progress.py render [--out vectors/reports/progress/PROGRESS.md]
      Read every progress/*.jsonl and write PROGRESS.md: one table per block over time, all columns.
  python3 scripts/rv64_progress.py check
      Validate every row of every ledger (CI-able, no third-party deps).
  python3 scripts/rv64_progress.py seed-m3
      (Re)write progress/m3-baseline.jsonl from rv64-m3-20261104/summary.json + scale receipts
      and the accepted-v7 1-GPU basket, so history starts at the M3 baseline.

One file per stream means no merge conflicts; rows are append-only (never edit history: append
a corrected row with a note instead).
"""
import argparse
import datetime
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
PROGRESS = ROOT / "vectors/reports/progress"
M3 = ROOT / "vectors/reports/rv64-m3-20261104"
V7 = ROOT / "vectors/reports/rv64-om31-recursion-20261103/recursive-basket-fifteen-accepted-v7.json"

REQUIRED = ["date", "commit", "stream", "milestone", "block", "gpus", "label"]
NUMERIC = ["request_s", "capture_s", "setup_s", "native_s", "recursion_s", "verifier_s", "rss_peak_gib", "device_peak_gb", "proof_bytes"]
OPTIONAL_NUMERIC = ["native_verify_s", "fold_tail_s", "rss_request_private_gib", "syncs", "launches", "pool_mallocs", "library_loads",
                    "pageable_copies", "loadavg_1m", "instructions_m", "nodes"]
OPTIONAL_TEXT = ["byte_identical_to", "receiver_accepted", "notes", "receipt", "config", "run"]
LABELS = {"M", "D", "E"}
QUIET_LOAD = 8.0  # protocol: quote timings only from runs with 1-min load average < 8
ALL = REQUIRED + NUMERIC + OPTIONAL_NUMERIC + OPTIONAL_TEXT


def load(path):
    with open(path) as handle:
        return json.load(handle)


def validate(row, where=""):
    errors = []
    for key in REQUIRED:
        if row.get(key) in (None, ""):
            errors.append(f"missing {key}")
    if row.get("label") not in LABELS:
        errors.append(f"label must be one of {sorted(LABELS)}")
    for key in NUMERIC + OPTIONAL_NUMERIC:
        if key in row and row[key] is not None and not isinstance(row[key], (int, float)):
            errors.append(f"{key} must be a number or null")
    if "receiver_accepted" in row and row["receiver_accepted"] not in (True, False, None):
        errors.append("receiver_accepted must be true/false/null")
    unknown = sorted(set(row) - set(ALL))
    if unknown:
        errors.append(f"unknown keys {unknown} (extend SCHEMA.md + rv64_progress.py first)")
    try:
        datetime.date.fromisoformat(str(row.get("date")))
    except ValueError:
        errors.append("date must be YYYY-MM-DD")
    if errors:
        raise SystemExit(f"invalid progress row {where}: " + "; ".join(errors) + "\n" + json.dumps(row))
    return row


def r3(x):
    return None if x is None else round(float(x), 3)


def row_from_receipt(receipt):
    """Map v1 / v2 receipts onto ledger columns."""
    if receipt.get("schema") == "rv64-m4-receipt/v2":
        st = receipt["stages"]
        ram = receipt.get("ram", {})
        dev = (receipt.get("device_memory") or {}).get("device_peak_gb") or {}
        corr = receipt.get("correctness", {})
        rec = corr.get("receiver") or {}
        counters = receipt.get("counters") or {}
        row = {"block": receipt["block"], "gpus": receipt["gpus"], "request_s": r3(st.get("request_s")), "capture_s": r3(st.get("capture_s")),
               "setup_s": r3(st.get("setup_s")), "native_s": r3(st.get("native_s")), "recursion_s": r3(st.get("recursion_s")),
               "verifier_s": r3((receipt.get("verifier") or {}).get("verify_per_block_s")), "rss_peak_gib": r3(ram.get("rss_peak_daemon_gib")),
               "rss_request_private_gib": r3(ram.get("rss_peak_request_private_gib")),
               "device_peak_gb": r3(max(dev.values())) if dev else None, "proof_bytes": (receipt.get("proof_size") or {}).get("proof_bytes_final"),
               "native_verify_s": r3(st.get("native_verify_on_critical_path_s")), "fold_tail_s": r3(st.get("fold_tail_after_last_leaf_s")),
               "receiver_accepted": rec.get("accepted") if rec.get("status") not in (None, "not_run") else None,
               "nodes": (receipt.get("recursion") or {}).get("nodes"), "run": receipt.get("run")}
        if counters.get("hook_active"):
            row.update(syncs=counters["sync_total"], launches=counters["kernel_launches"], pool_mallocs=counters["pool_mallocs"],
                       library_loads=counters["library_loads"], pageable_copies=counters["pageable_copies"])
        load1 = ((receipt.get("loadavg") or {}).get("start") or {}).get("1m")
        if load1 is not None:
            row["loadavg_1m"] = load1
        fp = corr.get("fingerprint_vs_reference")
        if fp and fp.get("identical"):
            row["byte_identical_to"] = "/".join(Path(fp["reference"]).with_suffix("").parts[-4:])
        return row
    st = receipt.get("stages", {})
    proc = receipt.get("producer_process", {})
    dev = (receipt.get("physical_gpu_memory_peak") or {}).get("peak_used_bytes") or {}
    rec = receipt.get("receiver") or {}
    rr = ((receipt.get("recursion") or {}).get("counters") or {}).get("recursive_report") or {}
    load1 = ((receipt.get("loadavg") or {}).get("start") or {}).get("1m")
    row = {"block": receipt["block"], "gpus": receipt["gpus"], "request_s": r3(st.get("request_wall_s")), "capture_s": r3(st.get("capture_s")),
           "setup_s": r3(st.get("setup_s")), "native_s": r3(st.get("native_prove_s")), "recursion_s": r3(st.get("recursion_s")),
           "verifier_s": r3((rec.get("process") or {}).get("wall_ns", 0) / 1e9) if rec.get("process") else None,
           "rss_peak_gib": r3(proc.get("peak_rss_bytes", 0) / 2**30) if proc.get("peak_rss_bytes") else None,
           "device_peak_gb": r3(max(dev.values()) / 1e9) if dev else None, "proof_bytes": rr.get("root_proof_bytes"),
           "receiver_accepted": rec.get("accepted") if rec.get("status") not in (None, "not_run") else None,
           "nodes": (rr.get("leaf_proofs") or 0) + (rr.get("fold_proofs") or 0) or None, "run": receipt.get("run")}
    if load1 is not None:
        row["loadavg_1m"] = load1
    return row


def git_head():
    try:
        return subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short=9", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def append(args):
    receipt = load(args.receipt)
    row = {"date": args.date or datetime.date.today().isoformat(), "commit": args.commit or receipt.get("source_commit") or git_head(),
           "stream": args.stream, "milestone": args.milestone, "label": args.label}
    row.update({k: v for k, v in row_from_receipt(receipt).items() if v is not None})
    if args.byte_identical_to:
        row["byte_identical_to"] = args.byte_identical_to
    if args.notes:
        row["notes"] = args.notes
    if args.config:
        row["config"] = args.config
    try:
        row["receipt"] = str(Path(args.receipt).resolve().relative_to(ROOT))
    except ValueError:
        row["receipt"] = str(args.receipt)
    ordered = {k: row[k] for k in ALL if k in row}
    validate(ordered, args.receipt)
    line = json.dumps(ordered, separators=(",", ":"))
    if args.dry_run:
        print(line)
        return
    PROGRESS.mkdir(parents=True, exist_ok=True)
    with open(PROGRESS / f"{args.stream}.jsonl", "a") as handle:
        handle.write(line + "\n")
    print(line)


ALIASES = {"load1": "loadavg_1m", "load_avg_1m": "loadavg_1m", "loadavg": "loadavg_1m"}
LEGACY = []  # (where, moved keys) for rows normalised at read time


def normalise(row, where=""):
    """Read-time normalisation of rows written by hand before the schema settled (integrate, M4).

    History is append-only, so legacy rows are never rewritten on disk. Here: known aliases map onto
    schema keys, a per-GPU device_peak_gb dict becomes its max, other unknown keys move into
    row["extra"] (not rendered). Required keys, labels and numeric types are still enforced."""
    row = dict(row)
    moved = []
    for old, new in ALIASES.items():
        if old in row and new not in row and isinstance(row[old], (int, float)):
            row[new] = row.pop(old)
            moved.append(old)
    dev = row.get("device_peak_gb")
    if isinstance(dev, dict):
        values = [v for v in dev.values() if isinstance(v, (int, float))]
        row["device_peak_gb"] = max(values) if values else None
        moved.append("device_peak_gb{}")
    extra = {k: row.pop(k) for k in sorted(set(row) - set(ALL))}
    rss = row.get("rss_peak_gib")
    if isinstance(rss, (int, float)) and rss < 1.0:
        # nsys-wrapped runs recorded the wrapper's RSS (~0.04 GiB), not the producer's
        extra["rss_peak_gib_wrapper"] = row.pop("rss_peak_gib")
    if extra:
        moved.extend(extra)
    for key in NUMERIC + OPTIONAL_NUMERIC:
        if key in row and row[key] is not None and not isinstance(row[key], (int, float)):
            extra[key] = row.pop(key)
            moved.append(key)
    if moved:
        LEGACY.append((where, moved))
    validate(row, where)
    if extra:
        row["extra"] = extra
    return row


def rows():
    out = []
    for path in sorted(PROGRESS.glob("*.jsonl")):
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if line.strip():
                out.append((path.name, normalise(json.loads(line), f"{path.name}:{n}")))
    return out


def fmt(value, digits=1):
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


COLUMNS = [("date", "date", None), ("milestone", "ms", None), ("stream", "stream", None), ("gpus", "GPUs", None), ("label", "lbl", None),
           ("request_s", "request s", 2), ("capture_s", "capture", 2), ("setup_s", "setup", 2), ("native_s", "native", 2),
           ("recursion_s", "recursion", 2), ("verifier_s", "verifier", 1), ("rss_peak_gib", "RSS GiB", 1), ("device_peak_gb", "dev GB", 1),
           ("proof_bytes", "proof KB", None), ("syncs", "syncs", None), ("launches", "launches", None), ("pool_mallocs", "pool mallocs", None),
           ("library_loads", "lib loads", None), ("pageable_copies", "pageable", None), ("byte_identical_to", "byte-identical to", None),
           ("receiver_accepted", "receiver", None), ("commit", "commit", None), ("notes", "notes", None)]


def render(args):
    data = rows()
    blocks = sorted({r["block"] for _, r in data}, key=lambda b: (b not in (26235156, 24628607), b))
    lines = ["# RV64 progress ledger", "",
             "Generated by `scripts/rv64_progress.py render` from `vectors/reports/progress/*.jsonl` (schema: `SCHEMA.md`). Do not edit by hand.", "",
             "Labels: **M** measured (receipt exists), **D** derived from measured numbers, **E** estimate. `—` = not measured in that row.",
             "Seconds unless noted; proof KB = final proof bytes / 1000. Rows are in date then file order (append-only history).", ""]
    best = {}
    for _, r in data:
        if r["label"] != "M" or r["block"] not in (26235156, 24628607) or r.get("gpus") != 2:
            continue
        if (r.get("loadavg_1m") or 0) >= QUIET_LOAD:  # timing hygiene: only quiet runs compete
            continue
        b = best.setdefault(r["block"], {})
        for key in ("request_s", "capture_s", "setup_s", "native_s", "recursion_s", "verifier_s", "rss_peak_gib", "proof_bytes"):
            if r.get(key) is not None and (b.get(key) is None or r[key] < b[key][0]):
                b[key] = (r[key], r["date"], r["stream"])
    if best:
        lines += ["## Best measured so far (2 GPUs, dev blocks) vs M3 baseline", "",
                  f"Only label-M rows from quiet runs (`loadavg_1m` < {QUIET_LOAD:g} or not recorded) compete; loaded-pod rows stay in the history below.", "",
                  "| block | column | M3 baseline | best | factor | by |", "|---|---|---:|---:|---:|---|"]
        base = {r["block"]: r for _, r in data if r["stream"] == "m3-baseline" and r["milestone"] == "M3" and r.get("gpus") == 2}
        for block in (24628607, 26235156):
            for key, (value, date, stream) in sorted(best.get(block, {}).items()):
                b0 = (base.get(block) or {}).get(key)
                factor = f"{b0 / value:.2f}x" if b0 and value else "—"
                lines.append(f"| {block} | {key} | {fmt(b0, 2)} | {fmt(value, 2)} | {factor} | {stream} {date} |")
        lines.append("")
    for block in blocks:
        rs = [(f, r) for f, r in data if r["block"] == block]
        rs.sort(key=lambda fr: (fr[1]["date"], fr[0]))
        lines += [f"## {block}", "", "| " + " | ".join(c[1] for c in COLUMNS) + " |", "|" + "|".join("---:" if c[2] is not None or c[0] in ("proof_bytes", "syncs", "launches", "pool_mallocs", "library_loads", "pageable_copies", "gpus") else "---" for c in COLUMNS) + "|"]
        for _, r in rs:
            cells = []
            for key, _, digits in COLUMNS:
                v = r.get(key)
                if key == "proof_bytes" and v is not None:
                    v = f"{v / 1000:.0f}"
                cells.append(fmt(v, digits if digits is not None else 1).replace("|", "/"))
            lines.append("| " + " | ".join(cells) + " |")
        lines.append("")
    out = Path(args.out) if getattr(args, "out", None) else PROGRESS / "PROGRESS.md"
    out.write_text("\n".join(lines))
    print(f"{out}: {len(data)} rows, {len(blocks)} blocks")


def seed_m3(args):
    summary = load(M3 / "summary.json")
    out = []
    for row in summary["rows"]:
        block = row["block"]
        scale = M3 / "integrate/scale" / f"{block}.json"
        receipt = load(scale) if scale.is_file() else {}
        derived = row_from_receipt(receipt) if receipt else {}
        r = {"date": "2026-11-04", "commit": row.get("source_commit") or "e61851f9e", "stream": "m3-baseline", "milestone": "M3", "block": block,
             "gpus": 2, "label": "M", "request_s": row["request_s"], "capture_s": row["capture_s"], "setup_s": row["setup_s"],
             "native_s": row["native_prove_s"], "recursion_s": row["recursion_s"], "verifier_s": r3(row.get("receiver_wall_s")) if row.get("receiver_wall_s") else derived.get("verifier_s"),
             "rss_peak_gib": row.get("producer_peak_rss_gib") or derived.get("rss_peak_gib"), "device_peak_gb": derived.get("device_peak_gb"),
             "proof_bytes": derived.get("proof_bytes"), "native_verify_s": row.get("native_verify_on_critical_path_s"),
             "nodes": derived.get("nodes"), "instructions_m": round(row["instructions"] / 1e6, 2),
             "receiver_accepted": row.get("receiver_accepted"),
             "config": "cold; " + ",".join(f"{k.replace('STWO_RV64_', '')}={v}" for k, v in sorted((row.get("environment_overrides") or {}).items())),
             "receipt": f"vectors/reports/rv64-m3-20261104/integrate/scale/{block}.json",
             "notes": "M3 baseline (summary.json); native+bundle byte-identical to v7, folds/root differ by design (fold v2)"}
        out.append({k: r[k] for k in ALL if k in r and r[k] is not None})
    v7 = load(V7)
    for row in v7["rows"]:
        r = {"date": "2026-11-03", "commit": "923e63b45", "stream": "m3-baseline", "milestone": "v7", "block": row["block"], "gpus": 1, "label": "M",
             "request_s": r3(row["request_wall_ns"] / 1e9), "capture_s": r3(row["capture_ns"] / 1e9), "setup_s": r3(row["native_setup_ns"] / 1e9),
             "native_s": r3(row["native_prove_ns"] / 1e9), "recursion_s": r3(row["recursion_ns"] / 1e9),
             "verifier_s": r3(row["receiver_process"]["wall_ns"] / 1e9) if row.get("receiver_process") else None, "proof_bytes": row.get("root_bytes"),
             "native_verify_s": r3(row["native_verify_ns"] / 1e9), "instructions_m": round(row["instructions"] / 1e6, 2),
             "receiver_accepted": bool(row.get("fresh_recursive_accepted")),
             "receipt": "vectors/reports/rv64-om31-recursion-20261103/recursive-basket-fifteen-accepted-v7.json",
             "notes": "accepted v7, 1x RTX 5090 (verifier = strict shared-authority receiver wall; native verify on path)"}
        out.append({k: r[k] for k in ALL if k in r and r[k] is not None})
    for r in out:
        validate(r, "seed")
    PROGRESS.mkdir(parents=True, exist_ok=True)
    (PROGRESS / "m3-baseline.jsonl").write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in out))
    print(f"seeded {len(out)} rows")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("append")
    a.add_argument("receipt")
    a.add_argument("--stream", required=True)
    a.add_argument("--milestone", required=True)
    a.add_argument("--label", default="M", choices=sorted(LABELS))
    a.add_argument("--notes")
    a.add_argument("--config")
    a.add_argument("--commit")
    a.add_argument("--date")
    a.add_argument("--byte-identical-to")
    a.add_argument("--dry-run", action="store_true")
    r = sub.add_parser("render")
    r.add_argument("--out")
    sub.add_parser("check")
    sub.add_parser("seed-m3")
    args = parser.parse_args()
    if args.command == "append":
        append(args)
    elif args.command == "render":
        render(args)
    elif args.command == "check":
        n = len(rows())
        print(f"{n} rows valid ({len(LEGACY)} legacy rows normalised at read time; new rows must use schema keys)")
        for where, moved in LEGACY:
            print(f"  legacy {where}: {', '.join(moved)}")
    else:
        seed_m3(args)


if __name__ == "__main__":
    sys.exit(main())
