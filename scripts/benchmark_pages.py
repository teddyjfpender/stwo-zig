#!/usr/bin/env python3
"""Render static benchmark chart assets from benchmark reports.

This page publishes:
- Full upstream family benchmark metrics (benchmark_full_report.json).
- Example-workload benchmark metrics with large/long runs (benchmark_contrast_long_report.json).

The generated data includes prove/verify/proof-size ratios and peak-RSS RAM ratios.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
SOURCE_REPORT_DEFAULT = ROOT / "vectors" / "reports" / "benchmark_full_report.json"
EXAMPLES_REPORT_DEFAULT = ROOT / "vectors" / "reports" / "benchmark_contrast_long_report.json"
OUT_DIR_DEFAULT = ROOT / "bench" / "dev" / "bench"
FIB5000_WORKLOAD = "wide_fibonacci_fib5000"
FLOW_TOP_LEVEL_STAGE_IDS = [
    "channel_and_scheme_init",
    "preprocessed_commit",
    "trace_generation",
    "main_trace_commit",
    "statement_mix",
    "core_prove",
    "proof_wire_encode",
    "artifact_write",
]
FLOW_MAIN_TRACE_STAGE_IDS = [
    "interpolate_columns",
    "evaluate_extended_domain",
    "merkle_commit",
]
FLOW_CORE_PROVE_STAGE_IDS = [
    "draw_random_coeff",
    "composition_trace_extract",
    "composition_evaluation",
    "composition_interpolate_and_split",
    "composition_commit",
    "oods_point_and_mask_points",
    "sampled_value_evaluation",
    "sampled_value_channel_mix",
    "fri_quotient_build",
    "fri_commit",
    "proof_of_work",
    "fri_decommit",
    "trace_decommit",
    "constraint_check_and_assembly",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate static benchmark chart assets")
    parser.add_argument(
        "--source-report",
        type=Path,
        default=SOURCE_REPORT_DEFAULT,
        help="Path to benchmark_full_report.json",
    )
    parser.add_argument(
        "--examples-report",
        type=Path,
        default=EXAMPLES_REPORT_DEFAULT,
        help="Path to benchmark_contrast_long_report.json",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=OUT_DIR_DEFAULT,
        help="Output directory for static page assets",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate existing assets match generated content without writing.",
    )
    return parser.parse_args()


def ratio(numerator: float, denominator: float) -> float:
    if denominator == 0.0:
        return 0.0
    return numerator / denominator


def build_family_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for family in report.get("families", []):
        name = str(family.get("family", "unknown"))
        mapped = family.get("mapped_workload", {})
        ratios = family.get("ratios", {})
        rust = family.get("rust", {})
        zig = family.get("zig", {})

        rust_peak_rss = float(rust.get("peak_rss_kb") or 0.0)
        zig_peak_rss = float(zig.get("peak_rss_kb") or 0.0)
        zig_over_rust_peak_rss = float(
            ratios.get("zig_over_rust_peak_rss_kb")
            if ratios.get("zig_over_rust_peak_rss_kb") is not None
            else ratio(zig_peak_rss, rust_peak_rss)
        )

        rows.append(
            {
                "family": name,
                "example": str(mapped.get("example", "")),
                "zig_over_rust_prove": float(ratios.get("zig_over_rust_prove", 0.0)),
                "zig_over_rust_verify": float(ratios.get("zig_over_rust_verify", 0.0)),
                "zig_over_rust_proof_wire_bytes": float(ratios.get("zig_over_rust_proof_wire_bytes", 0.0)),
                "zig_over_rust_peak_rss_kb": zig_over_rust_peak_rss,
                "rust_prove_avg_seconds": float(rust.get("prove", {}).get("avg_seconds", 0.0)),
                "rust_verify_avg_seconds": float(rust.get("verify", {}).get("avg_seconds", 0.0)),
                "zig_prove_avg_seconds": float(zig.get("prove", {}).get("avg_seconds", 0.0)),
                "zig_verify_avg_seconds": float(zig.get("verify", {}).get("avg_seconds", 0.0)),
                "rust_peak_rss_kb": rust_peak_rss,
                "zig_peak_rss_kb": zig_peak_rss,
            }
        )
    return rows


def build_example_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for workload in report.get("workloads", []):
        ratios = workload.get("ratios", {})
        rust = workload.get("rust", {})
        zig = workload.get("zig", {})

        rust_prove_rss_peak_kb = float(rust.get("prove", {}).get("rss_peak_kb") or 0.0)
        zig_prove_rss_peak_kb = float(zig.get("prove", {}).get("rss_peak_kb") or 0.0)
        rust_verify_rss_peak_kb = float(rust.get("verify", {}).get("rss_peak_kb") or 0.0)
        zig_verify_rss_peak_kb = float(zig.get("verify", {}).get("rss_peak_kb") or 0.0)

        rows.append(
            {
                "name": str(workload.get("name", "unknown")),
                "example": str(workload.get("example", "")),
                "zig_over_rust_prove": float(ratios.get("zig_over_rust_prove", 0.0)),
                "zig_over_rust_verify": float(ratios.get("zig_over_rust_verify", 0.0)),
                "zig_over_rust_proof_wire_bytes": float(ratios.get("zig_over_rust_proof_wire_bytes", 0.0)),
                "zig_over_rust_peak_rss_kb": ratio(zig_prove_rss_peak_kb, rust_prove_rss_peak_kb),
                "rust_prove_avg_seconds": float(rust.get("prove", {}).get("avg_seconds", 0.0)),
                "rust_verify_avg_seconds": float(rust.get("verify", {}).get("avg_seconds", 0.0)),
                "zig_prove_avg_seconds": float(zig.get("prove", {}).get("avg_seconds", 0.0)),
                "zig_verify_avg_seconds": float(zig.get("verify", {}).get("avg_seconds", 0.0)),
                "rust_prove_rss_peak_kb": rust_prove_rss_peak_kb,
                "zig_prove_rss_peak_kb": zig_prove_rss_peak_kb,
                "rust_verify_rss_peak_kb": rust_verify_rss_peak_kb,
                "zig_verify_rss_peak_kb": zig_verify_rss_peak_kb,
            }
        )
    return rows


def ratio_or_zero(numerator: float, denominator: float) -> float:
    return ratio(numerator, denominator)


def find_stage(stages: list[dict[str, Any]], stage_id: str) -> dict[str, Any]:
    for stage in stages:
        if str(stage.get("id", "")) == stage_id:
            return stage
    raise RuntimeError(f"missing stage '{stage_id}' in fib5000 flow payload")


def validate_stage_order(stages: list[dict[str, Any]], expected_ids: list[str], label: str) -> None:
    actual_ids = [str(stage.get("id", "")) for stage in stages]
    if actual_ids != expected_ids:
        raise RuntimeError(f"{label} stage order mismatch: expected {expected_ids}, got {actual_ids}")


def build_stage_rows(
    rust_stages: list[dict[str, Any]],
    zig_stages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    rust_total = sum(float(stage.get("seconds", 0.0)) for stage in rust_stages)
    zig_total = sum(float(stage.get("seconds", 0.0)) for stage in zig_stages)
    for idx, rust_stage in enumerate(rust_stages):
        zig_stage = zig_stages[idx]
        if rust_stage.get("id") != zig_stage.get("id"):
            raise RuntimeError("Rust/Zig fib5000 top-level stage mismatch")
        rust_seconds = float(rust_stage.get("seconds", 0.0))
        zig_seconds = float(zig_stage.get("seconds", 0.0))
        rows.append(
            {
                "id": str(rust_stage.get("id", "")),
                "label": str(rust_stage.get("label", "")),
                "color_index": idx,
                "rust_seconds": rust_seconds,
                "rust_share": ratio_or_zero(rust_seconds, rust_total),
                "zig_seconds": zig_seconds,
                "zig_share": ratio_or_zero(zig_seconds, zig_total),
                "zig_over_rust": ratio_or_zero(zig_seconds, rust_seconds),
            }
        )
    return rows


def build_nested_stage_rows(
    stages: list[dict[str, Any]],
    expected_ids: list[str],
) -> list[dict[str, Any]]:
    validate_stage_order(stages, expected_ids, "zig nested")
    total = sum(float(stage.get("seconds", 0.0)) for stage in stages)
    return [
        {
            "id": str(stage.get("id", "")),
            "label": str(stage.get("label", "")),
            "seconds": float(stage.get("seconds", 0.0)),
            "share": ratio_or_zero(float(stage.get("seconds", 0.0)), total),
        }
        for stage in stages
    ]


def build_fib5000_flow(report: dict[str, Any]) -> dict[str, Any]:
    workload = next(
        (workload for workload in report.get("workloads", []) if workload.get("name") == FIB5000_WORKLOAD),
        None,
    )
    if workload is None:
        raise RuntimeError(f"missing workload '{FIB5000_WORKLOAD}' in examples report")

    rust_flow = workload.get("rust", {}).get("prove", {}).get("stage_flow")
    zig_flow = workload.get("zig", {}).get("prove", {}).get("stage_flow")
    if not rust_flow or not zig_flow:
        raise RuntimeError("fib5000 stage flow is missing from examples report")

    rust_stages = rust_flow.get("stages", [])
    zig_stages = zig_flow.get("stages", [])
    validate_stage_order(rust_stages, FLOW_TOP_LEVEL_STAGE_IDS, "rust top-level")
    validate_stage_order(zig_stages, FLOW_TOP_LEVEL_STAGE_IDS, "zig top-level")

    zig_main_trace = find_stage(zig_stages, "main_trace_commit").get("children") or []
    zig_core_prove = find_stage(zig_stages, "core_prove").get("children") or []
    validate_stage_order(zig_main_trace, FLOW_MAIN_TRACE_STAGE_IDS, "zig main_trace_commit")
    validate_stage_order(zig_core_prove, FLOW_CORE_PROVE_STAGE_IDS, "zig core_prove")

    top_level_rows = build_stage_rows(rust_stages, zig_stages)
    return {
        "workload": FIB5000_WORKLOAD,
        "rust_total_seconds": round(sum(row["rust_seconds"] for row in top_level_rows), 6),
        "zig_total_seconds": round(sum(row["zig_seconds"] for row in top_level_rows), 6),
        "top_level_rows": top_level_rows,
        "zig_main_trace_commit": build_nested_stage_rows(zig_main_trace, FLOW_MAIN_TRACE_STAGE_IDS),
        "zig_core_prove": build_nested_stage_rows(zig_core_prove, FLOW_CORE_PROVE_STAGE_IDS),
    }


def build_payload(
    family_report: dict[str, Any],
    family_report_path: Path,
    examples_report: dict[str, Any],
    examples_report_path: Path,
) -> dict[str, Any]:
    return {
        "schema_version": 3,
        "sources": {
            "families_report": str(family_report_path.relative_to(ROOT)),
            "examples_report": str(examples_report_path.relative_to(ROOT)),
        },
        "summaries": {
            "families": family_report.get("summary", {}),
            "examples": examples_report.get("summary", {}),
        },
        "fib5000_flow": build_fib5000_flow(examples_report),
        "family_rows": build_family_rows(family_report),
        "example_rows": build_example_rows(examples_report),
    }


def render_data_js(payload: dict[str, Any]) -> str:
    return "window.BENCHMARK_PAGE_DATA = " + json.dumps(payload, indent=2, sort_keys=True) + ";\n"


def render_index_html() -> str:
    return """<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>stwo-zig benchmark parity</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 24px; color: #222; background: #f6f8fa; }
    h1 { margin: 0 0 8px; }
    h2 { margin: 0 0 10px; }
    h3 { margin: 0 0 10px; }
    p { margin: 0 0 16px; }
    .card { background: #fff; border: 1px solid #d0d7de; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
    .chart { display: grid; grid-template-columns: 220px 1fr 90px; row-gap: 6px; column-gap: 8px; align-items: center; }
    .label { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .chart-axis-label { color: #57606a; font-size: 11px; text-transform: uppercase; letter-spacing: 0.02em; }
    .bar-wrap { position: relative; height: 14px; background: #eaeef2; border-radius: 3px; overflow: hidden; }
    .bar { position: relative; z-index: 1; height: 100%; }
    .bar.prove { background: #1f6feb; }
    .bar.verify { background: #fb8500; }
    .bar.size { background: #2a9d8f; }
    .bar.rss { background: #0e9f6e; }
    .bar.detail { background: #0969da; }
    .one-marker { position: absolute; top: 0; bottom: 0; width: 2px; background: rgba(17, 24, 39, 0.45); z-index: 2; pointer-events: none; }
    .axis-wrap { height: 18px; overflow: visible; background: #f0f3f6; }
    .axis-tick { position: absolute; top: -2px; transform: translateX(-50%); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; color: #57606a; white-space: nowrap; }
    .axis-tick.left { left: 0; transform: none; }
    .axis-tick.right { right: 0; left: auto; transform: none; }
    .value { text-align: right; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; border-bottom: 1px solid #d8dee4; padding: 6px 8px; }
    th { background: #f0f3f6; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    .flow-legend { display: flex; flex-wrap: wrap; gap: 8px 12px; margin-bottom: 12px; }
    .flow-legend-item { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; }
    .flow-swatch { width: 12px; height: 12px; border-radius: 3px; display: inline-block; }
    .flow-chart { display: grid; grid-template-columns: 220px 1fr 90px; row-gap: 10px; column-gap: 8px; align-items: center; margin-bottom: 16px; }
    .flow-stack { display: flex; width: 100%; height: 22px; border-radius: 6px; overflow: hidden; background: #eaeef2; border: 1px solid #d8dee4; }
    .flow-segment { height: 100%; min-width: 1px; }
    .flow-detail-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-top: 16px; }
  </style>
</head>
<body>
  <h1>stwo-zig Benchmark Parity</h1>
  <p>Generated from committed benchmark data and includes peak-RSS RAM metrics plus a fib5000 proof-flow explainer built from averaged benchmark samples.</p>

  <div class=\"card\">
    <h2>Family Benchmarks</h2>
    <h3>Prove Ratio (Zig over Rust)</h3>
    <div id=\"familyProveChart\" class=\"chart\"></div>
    <h3>Verify Ratio (Zig over Rust)</h3>
    <div id=\"familyVerifyChart\" class=\"chart\"></div>
    <h3>Proof-Size Ratio (Zig over Rust)</h3>
    <div id=\"familySizeChart\" class=\"chart\"></div>
    <h3>Peak-RSS Ratio (Zig over Rust)</h3>
    <div id=\"familyRssChart\" class=\"chart\"></div>
  </div>

  <div class=\"card\">
    <h2>Family Raw Metrics</h2>
    <table id=\"familyTable\">
      <thead>
        <tr>
          <th>Family</th>
          <th>Example</th>
          <th>Zig/Rust Prove</th>
          <th>Zig/Rust Verify</th>
          <th>Zig/Rust Proof Size</th>
          <th>Zig/Rust Peak RSS</th>
          <th>Rust Peak RSS (KB)</th>
          <th>Zig Peak RSS (KB)</th>
          <th>Rust Prove (s)</th>
          <th>Zig Prove (s)</th>
          <th>Rust Verify (s)</th>
          <th>Zig Verify (s)</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
  </div>

  <div class=\"card\">
    <h2>Example Workload Benchmarks</h2>
    <h3>Prove Ratio (Zig over Rust)</h3>
    <div id=\"exampleProveChart\" class=\"chart\"></div>
    <h3>Verify Ratio (Zig over Rust)</h3>
    <div id=\"exampleVerifyChart\" class=\"chart\"></div>
    <h3>Proof-Size Ratio (Zig over Rust)</h3>
    <div id=\"exampleSizeChart\" class=\"chart\"></div>
    <h3>Peak-RSS Ratio (Zig over Rust)</h3>
    <div id=\"exampleRssChart\" class=\"chart\"></div>
  </div>

  <div class=\"card\">
    <h2>Fib5000 Proof Flow</h2>
    <p>Shared top-level prove stages are shown side-by-side for Rust and Zig. Zig also breaks out the two main internal regions we are actively optimizing: <span class=\"mono\">main_trace_commit</span> and <span class=\"mono\">core_prove</span>.</p>
    <div id=\"fib5000FlowLegend\" class=\"flow-legend\"></div>
    <div id=\"fib5000FlowBars\" class=\"flow-chart\"></div>
    <table id=\"fib5000FlowTable\">
      <thead>
        <tr>
          <th>Stage</th>
          <th>Rust (s)</th>
          <th>Rust Share</th>
          <th>Zig (s)</th>
          <th>Zig Share</th>
          <th>Zig/Rust</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
    <div class=\"flow-detail-grid\">
      <div>
        <h3>Zig main_trace_commit</h3>
        <div id=\"fib5000MainTraceDetail\" class=\"chart\"></div>
      </div>
      <div>
        <h3>Zig core_prove</h3>
        <div id=\"fib5000CoreProveDetail\" class=\"chart\"></div>
      </div>
    </div>
  </div>

  <div class=\"card\">
    <h2>Example Raw Metrics</h2>
    <table id=\"exampleTable\">
      <thead>
        <tr>
          <th>Workload</th>
          <th>Example</th>
          <th>Zig/Rust Prove</th>
          <th>Zig/Rust Verify</th>
          <th>Zig/Rust Proof Size</th>
          <th>Zig/Rust Peak RSS</th>
          <th>Rust Prove Peak RSS (KB)</th>
          <th>Zig Prove Peak RSS (KB)</th>
          <th>Rust Verify Peak RSS (KB)</th>
          <th>Zig Verify Peak RSS (KB)</th>
          <th>Rust Prove (s)</th>
          <th>Zig Prove (s)</th>
          <th>Rust Verify (s)</th>
          <th>Zig Verify (s)</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
    <p class=\"mono\" id=\"meta\"></p>
  </div>

  <script src=\"data.js\"></script>
  <script>
    const data = window.BENCHMARK_PAGE_DATA;
    const familyRows = data.family_rows || [];
    const exampleRows = data.example_rows || [];
    const fib5000Flow = data.fib5000_flow || null;

    const ratioKeys = [
      'zig_over_rust_prove',
      'zig_over_rust_verify',
      'zig_over_rust_proof_wire_bytes',
      'zig_over_rust_peak_rss_kb',
    ];

    function computeSharedAxisMax(family, examples) {
      const values = [];
      [family, examples].forEach((rows) => {
        rows.forEach((row) => {
          ratioKeys.forEach((key) => {
            const value = Number(row[key]);
            if (Number.isFinite(value) && value >= 0) {
              values.push(value);
            }
          });
        });
      });
      const observedMax = values.length > 0 ? Math.max(...values) : 1.0;
      return Math.max(1.0, Math.ceil(observedMax * 10.0) / 10.0);
    }

    function computeSecondsAxisMax(rows) {
      const values = rows.map((row) => Number(row.seconds));
      const observedMax = values.length > 0 ? Math.max(...values) : 1.0;
      return Math.max(0.001, Math.ceil(observedMax * 1000.0) / 1000.0);
    }

    function flowColor(index) {
      const palette = ['#1f6feb', '#2a9d8f', '#fb8500', '#8b5cf6', '#e63946', '#0e9f6e', '#f4a261', '#577590', '#4361ee', '#9c6644', '#3a86ff', '#bc4749', '#6a4c93', '#2d6a4f'];
      return palette[index % palette.length];
    }

    function renderAxisRow(target, axisMax, oneMarkerPct) {
      const label = document.createElement('div');
      label.className = 'label chart-axis-label';
      label.textContent = 'shared scale';

      const wrap = document.createElement('div');
      wrap.className = 'bar-wrap axis-wrap';

      const tickLeft = document.createElement('div');
      tickLeft.className = 'axis-tick left';
      tickLeft.textContent = '0.0x';
      wrap.appendChild(tickLeft);

      const tickOne = document.createElement('div');
      tickOne.className = 'axis-tick';
      tickOne.style.left = `${oneMarkerPct.toFixed(4)}%`;
      tickOne.textContent = '1.0x';
      wrap.appendChild(tickOne);

      const tickRight = document.createElement('div');
      tickRight.className = 'axis-tick right';
      tickRight.textContent = `${axisMax.toFixed(1)}x`;
      wrap.appendChild(tickRight);

      const value = document.createElement('div');
      value.className = 'value';
      value.textContent = 'ratio';

      target.appendChild(label);
      target.appendChild(wrap);
      target.appendChild(value);
    }

    function renderSecondsAxisRow(target, axisMax) {
      const label = document.createElement('div');
      label.className = 'label chart-axis-label';
      label.textContent = 'seconds';

      const wrap = document.createElement('div');
      wrap.className = 'bar-wrap axis-wrap';

      const tickLeft = document.createElement('div');
      tickLeft.className = 'axis-tick left';
      tickLeft.textContent = '0.000s';
      wrap.appendChild(tickLeft);

      const tickRight = document.createElement('div');
      tickRight.className = 'axis-tick right';
      tickRight.textContent = `${axisMax.toFixed(3)}s`;
      wrap.appendChild(tickRight);

      const value = document.createElement('div');
      value.className = 'value';
      value.textContent = 'sec';

      target.appendChild(label);
      target.appendChild(wrap);
      target.appendChild(value);
    }

    function renderBars(rows, targetId, key, barClass, labelKey, axisMax, oneMarkerPct) {
      const target = document.getElementById(targetId);
      renderAxisRow(target, axisMax, oneMarkerPct);
      rows.forEach((r) => {
        const label = document.createElement('div');
        label.className = 'label';
        label.textContent = r[labelKey];

        const wrap = document.createElement('div');
        wrap.className = 'bar-wrap';

        const marker = document.createElement('div');
        marker.className = 'one-marker';
        marker.style.left = `${oneMarkerPct.toFixed(4)}%`;
        wrap.appendChild(marker);

        const bar = document.createElement('div');
        bar.className = `bar ${barClass}`;
        const pct = Math.min((Number(r[key]) / axisMax) * 100, 100);
        bar.style.width = `${pct.toFixed(2)}%`;
        wrap.appendChild(bar);

        const value = document.createElement('div');
        value.className = 'value';
        value.textContent = Number(r[key]).toFixed(6);

        target.appendChild(label);
        target.appendChild(wrap);
        target.appendChild(value);
      });
    }

    function renderSecondsBars(rows, targetId) {
      const target = document.getElementById(targetId);
      const axisMax = computeSecondsAxisMax(rows);
      renderSecondsAxisRow(target, axisMax);
      rows.forEach((row) => {
        const label = document.createElement('div');
        label.className = 'label';
        label.textContent = row.id;

        const wrap = document.createElement('div');
        wrap.className = 'bar-wrap';

        const bar = document.createElement('div');
        bar.className = 'bar detail';
        bar.style.width = `${Math.min((Number(row.seconds) / axisMax) * 100, 100).toFixed(2)}%`;
        wrap.appendChild(bar);

        const value = document.createElement('div');
        value.className = 'value';
        value.textContent = `${Number(row.seconds).toFixed(6)}s`;

        target.appendChild(label);
        target.appendChild(wrap);
        target.appendChild(value);
      });
    }

    function renderFlowLegend(flow) {
      const target = document.getElementById('fib5000FlowLegend');
      flow.top_level_rows.forEach((row) => {
        const item = document.createElement('div');
        item.className = 'flow-legend-item';
        const swatch = document.createElement('span');
        swatch.className = 'flow-swatch';
        swatch.style.background = flowColor(row.color_index);
        item.appendChild(swatch);
        const label = document.createElement('span');
        label.textContent = row.id;
        item.appendChild(label);
        target.appendChild(item);
      });
    }

    function renderFlowBars(flow) {
      const target = document.getElementById('fib5000FlowBars');
      const runtimes = [
        { key: 'rust', label: `Rust (${Number(flow.rust_total_seconds).toFixed(3)}s)` },
        { key: 'zig', label: `Zig (${Number(flow.zig_total_seconds).toFixed(3)}s)` },
      ];
      runtimes.forEach((runtime) => {
        const label = document.createElement('div');
        label.className = 'label';
        label.textContent = runtime.label;

        const stack = document.createElement('div');
        stack.className = 'flow-stack';
        flow.top_level_rows.forEach((row) => {
          const segment = document.createElement('div');
          segment.className = 'flow-segment';
          segment.style.background = flowColor(row.color_index);
          const share = Number(row[`${runtime.key}_share`]);
          segment.style.width = `${Math.max(share * 100.0, 0.4).toFixed(3)}%`;
          segment.title = `${row.id}: ${Number(row[`${runtime.key}_seconds`]).toFixed(6)}s (${(share * 100.0).toFixed(2)}%)`;
          stack.appendChild(segment);
        });

        const value = document.createElement('div');
        value.className = 'value';
        value.textContent = `${Number(flow[`${runtime.key}_total_seconds`]).toFixed(6)}s`;

        target.appendChild(label);
        target.appendChild(stack);
        target.appendChild(value);
      });
    }

    function renderFlowTable(flow) {
      const body = document.querySelector('#fib5000FlowTable tbody');
      flow.top_level_rows.forEach((row) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><span class=\"flow-swatch\" style=\"background:${flowColor(row.color_index)}\"></span> ${row.id}</td>
          <td>${Number(row.rust_seconds).toFixed(6)}</td>
          <td>${(Number(row.rust_share) * 100.0).toFixed(2)}%</td>
          <td>${Number(row.zig_seconds).toFixed(6)}</td>
          <td>${(Number(row.zig_share) * 100.0).toFixed(2)}%</td>
          <td>${Number(row.zig_over_rust).toFixed(6)}</td>
        `;
        body.appendChild(tr);
      });
    }

    const sharedAxisMax = computeSharedAxisMax(familyRows, exampleRows);
    const oneMarkerPct = Math.min((1.0 / sharedAxisMax) * 100.0, 100.0);

    renderBars(familyRows, 'familyProveChart', 'zig_over_rust_prove', 'prove', 'family', sharedAxisMax, oneMarkerPct);
    renderBars(familyRows, 'familyVerifyChart', 'zig_over_rust_verify', 'verify', 'family', sharedAxisMax, oneMarkerPct);
    renderBars(familyRows, 'familySizeChart', 'zig_over_rust_proof_wire_bytes', 'size', 'family', sharedAxisMax, oneMarkerPct);
    renderBars(familyRows, 'familyRssChart', 'zig_over_rust_peak_rss_kb', 'rss', 'family', sharedAxisMax, oneMarkerPct);

    renderBars(exampleRows, 'exampleProveChart', 'zig_over_rust_prove', 'prove', 'name', sharedAxisMax, oneMarkerPct);
    renderBars(exampleRows, 'exampleVerifyChart', 'zig_over_rust_verify', 'verify', 'name', sharedAxisMax, oneMarkerPct);
    renderBars(exampleRows, 'exampleSizeChart', 'zig_over_rust_proof_wire_bytes', 'size', 'name', sharedAxisMax, oneMarkerPct);
    renderBars(exampleRows, 'exampleRssChart', 'zig_over_rust_peak_rss_kb', 'rss', 'name', sharedAxisMax, oneMarkerPct);

    const familyBody = document.querySelector('#familyTable tbody');
    familyRows.forEach((r) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${r.family}</td>
        <td>${r.example}</td>
        <td>${Number(r.zig_over_rust_prove).toFixed(6)}</td>
        <td>${Number(r.zig_over_rust_verify).toFixed(6)}</td>
        <td>${Number(r.zig_over_rust_proof_wire_bytes).toFixed(6)}</td>
        <td>${Number(r.zig_over_rust_peak_rss_kb).toFixed(6)}</td>
        <td>${Number(r.rust_peak_rss_kb).toFixed(2)}</td>
        <td>${Number(r.zig_peak_rss_kb).toFixed(2)}</td>
        <td>${Number(r.rust_prove_avg_seconds).toFixed(6)}</td>
        <td>${Number(r.zig_prove_avg_seconds).toFixed(6)}</td>
        <td>${Number(r.rust_verify_avg_seconds).toFixed(6)}</td>
        <td>${Number(r.zig_verify_avg_seconds).toFixed(6)}</td>
      `;
      familyBody.appendChild(tr);
    });

    const exampleBody = document.querySelector('#exampleTable tbody');
    exampleRows.forEach((r) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${r.name}</td>
        <td>${r.example}</td>
        <td>${Number(r.zig_over_rust_prove).toFixed(6)}</td>
        <td>${Number(r.zig_over_rust_verify).toFixed(6)}</td>
        <td>${Number(r.zig_over_rust_proof_wire_bytes).toFixed(6)}</td>
        <td>${Number(r.zig_over_rust_peak_rss_kb).toFixed(6)}</td>
        <td>${Number(r.rust_prove_rss_peak_kb).toFixed(2)}</td>
        <td>${Number(r.zig_prove_rss_peak_kb).toFixed(2)}</td>
        <td>${Number(r.rust_verify_rss_peak_kb).toFixed(2)}</td>
        <td>${Number(r.zig_verify_rss_peak_kb).toFixed(2)}</td>
        <td>${Number(r.rust_prove_avg_seconds).toFixed(6)}</td>
        <td>${Number(r.zig_prove_avg_seconds).toFixed(6)}</td>
        <td>${Number(r.rust_verify_avg_seconds).toFixed(6)}</td>
        <td>${Number(r.zig_verify_avg_seconds).toFixed(6)}</td>
      `;
      exampleBody.appendChild(tr);
    });

    if (fib5000Flow) {
      renderFlowLegend(fib5000Flow);
      renderFlowBars(fib5000Flow);
      renderFlowTable(fib5000Flow);
      renderSecondsBars(fib5000Flow.zig_main_trace_commit || [], 'fib5000MainTraceDetail');
      renderSecondsBars(fib5000Flow.zig_core_prove || [], 'fib5000CoreProveDetail');
    }

    document.getElementById('meta').textContent = `schema=${data.schema_version} | families_source=${data.sources.families_report} | examples_source=${data.sources.examples_report} | shared_ratio_axis_max=${sharedAxisMax.toFixed(1)}x`;
  </script>
</body>
</html>
"""


def load_ok_report(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"missing {label}: {path}")
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("status") != "ok":
        raise RuntimeError(f"{label} status is not ok: {path}")
    return report


def main() -> int:
    args = parse_args()
    family_report = load_ok_report(args.source_report, "family benchmark report")
    examples_report = load_ok_report(args.examples_report, "examples benchmark report")

    payload = build_payload(
        family_report,
        args.source_report,
        examples_report,
        args.examples_report,
    )
    rendered_js = render_data_js(payload)
    rendered_html = render_index_html()

    out_dir = args.out_dir
    out_data = out_dir / "data.js"
    out_index = out_dir / "index.html"

    if args.validate:
        if not out_data.exists() or not out_index.exists():
            raise RuntimeError("benchmark page assets missing; run without --validate")
        if out_data.read_text(encoding="utf-8") != rendered_js:
            raise RuntimeError("benchmark data.js is stale; regenerate assets")
        if out_index.read_text(encoding="utf-8") != rendered_html:
            raise RuntimeError("benchmark index.html is stale; regenerate assets")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    out_data.write_text(rendered_js, encoding="utf-8")
    out_index.write_text(rendered_html, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
