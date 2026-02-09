#!/usr/bin/env python3
"""Derive deterministic long-workload A/B decisions for pool reuse and proof codec."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "vectors" / "reports" / "benchmark_contrast_long_ab_decision.json"


def load(path: Path) -> Dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"invalid report payload: {path}")
    return payload


def ratio_delta_pct(current: float, baseline: float) -> float:
    if baseline <= 0:
        return 0.0
    return ((current / baseline) - 1.0) * 100.0


def rows_for_comparison(
    baseline_workloads: Dict[str, Dict[str, Any]],
    candidate_workloads: Dict[str, Dict[str, Any]],
    *,
    prove_key: str,
    rss_key: str,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for name in sorted(baseline_workloads):
        if name not in candidate_workloads:
            raise RuntimeError(f"candidate report missing workload: {name}")

        baseline_ratios = baseline_workloads[name]["ratios"]
        candidate_ratios = candidate_workloads[name]["ratios"]

        baseline_prove = float(baseline_ratios[prove_key])
        baseline_rss = float(baseline_ratios[rss_key])
        candidate_prove = float(candidate_ratios[prove_key])
        candidate_rss = float(candidate_ratios[rss_key])

        rows.append(
            {
                "name": name,
                "delta_prove_pct": round(ratio_delta_pct(candidate_prove, baseline_prove), 6),
                "delta_rss_pct": round(ratio_delta_pct(candidate_rss, baseline_rss), 6),
                "better_both": candidate_prove <= baseline_prove and candidate_rss <= baseline_rss,
            }
        )
    return rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--no-reuse-report",
        type=Path,
        default=ROOT / "vectors" / "reports" / "benchmark_contrast_long_no_reuse_ab.json",
    )
    parser.add_argument(
        "--reuse-report",
        type=Path,
        default=ROOT / "vectors" / "reports" / "benchmark_contrast_long_reuse_ab.json",
    )
    parser.add_argument(
        "--json-codec-report",
        type=Path,
        default=ROOT / "vectors" / "reports" / "benchmark_contrast_long_json_codec_ab.json",
    )
    parser.add_argument(
        "--binary-codec-report",
        type=Path,
        default=ROOT / "vectors" / "reports" / "benchmark_contrast_long_binary_codec_ab.json",
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    return parser.parse_args()


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def main() -> int:
    args = parse_args()

    no_reuse = load(args.no_reuse_report)
    reuse = load(args.reuse_report)
    json_codec = load(args.json_codec_report)
    binary_codec = load(args.binary_codec_report)

    no_reuse_workloads = {w["name"]: w for w in no_reuse["workloads"]}
    reuse_workloads = {w["name"]: w for w in reuse["workloads"]}
    json_workloads = {w["name"]: w for w in json_codec["workloads"]}
    binary_workloads = {w["name"]: w for w in binary_codec["workloads"]}

    if sorted(no_reuse_workloads) != sorted(reuse_workloads):
        raise RuntimeError("reuse and no-reuse reports use different workload sets")
    if sorted(json_workloads) != sorted(binary_workloads):
        raise RuntimeError("json and binary codec reports use different workload sets")

    reuse_rows = rows_for_comparison(
        no_reuse_workloads,
        reuse_workloads,
        prove_key="zig_over_rust_prove",
        rss_key="zig_over_rust_peak_rss_kb",
    )
    codec_rows = rows_for_comparison(
        json_workloads,
        binary_workloads,
        prove_key="zig_over_rust_prove",
        rss_key="zig_over_rust_peak_rss_kb",
    )

    deep_long = {
        "blake_deep",
        "poseidon_deep",
        "wide_fibonacci_fib2000",
        "wide_fibonacci_fib5000",
    }
    selected_reuse_workloads = [
        row["name"]
        for row in reuse_rows
        if row["better_both"] and row["name"] in deep_long
    ]

    promote_binary_codec = all(row["better_both"] for row in codec_rows)

    decision = {
        "schema_version": 1,
        "generated_at_unix": int(time.time()),
        "reuse_ab": {
            "report_no_reuse": rel(args.no_reuse_report),
            "report_reuse": rel(args.reuse_report),
            "selected_reuse_workloads": selected_reuse_workloads,
            "rows": reuse_rows,
        },
        "codec_ab": {
            "report_json_codec": rel(args.json_codec_report),
            "report_binary_codec": rel(args.binary_codec_report),
            "promote_binary_codec": promote_binary_codec,
            "selected_codec": "binary" if promote_binary_codec else "json",
            "rows": codec_rows,
        },
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(decision, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "status": "ok",
                "selected_reuse_workloads": selected_reuse_workloads,
                "selected_codec": decision["codec_ab"]["selected_codec"],
                "out": rel(args.out),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
