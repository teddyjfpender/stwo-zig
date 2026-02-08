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


def build_payload(
    family_report: dict[str, Any],
    family_report_path: Path,
    examples_report: dict[str, Any],
    examples_report_path: Path,
) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "sources": {
            "families_report": str(family_report_path.relative_to(ROOT)),
            "examples_report": str(examples_report_path.relative_to(ROOT)),
        },
        "summaries": {
            "families": family_report.get("summary", {}),
            "examples": examples_report.get("summary", {}),
        },
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
    .bar-wrap { height: 14px; background: #eaeef2; border-radius: 3px; overflow: hidden; }
    .bar { height: 100%; }
    .bar.prove { background: #1f6feb; }
    .bar.verify { background: #fb8500; }
    .bar.size { background: #2a9d8f; }
    .bar.rss { background: #0e9f6e; }
    .value { text-align: right; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; border-bottom: 1px solid #d8dee4; padding: 6px 8px; }
    th { background: #f0f3f6; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  </style>
</head>
<body>
  <h1>stwo-zig Benchmark Parity</h1>
  <p>Generated from committed benchmark data and includes peak-RSS RAM metrics.</p>

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

    function renderBars(rows, targetId, key, barClass, labelKey) {
      const target = document.getElementById(targetId);
      const max = Math.max(...rows.map(r => r[key]), 0.000001);
      rows.forEach((r) => {
        const label = document.createElement('div');
        label.className = 'label';
        label.textContent = r[labelKey];

        const wrap = document.createElement('div');
        wrap.className = 'bar-wrap';
        const bar = document.createElement('div');
        bar.className = `bar ${barClass}`;
        const pct = Math.min((r[key] / max) * 100, 100);
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

    renderBars(familyRows, 'familyProveChart', 'zig_over_rust_prove', 'prove', 'family');
    renderBars(familyRows, 'familyVerifyChart', 'zig_over_rust_verify', 'verify', 'family');
    renderBars(familyRows, 'familySizeChart', 'zig_over_rust_proof_wire_bytes', 'size', 'family');
    renderBars(familyRows, 'familyRssChart', 'zig_over_rust_peak_rss_kb', 'rss', 'family');

    renderBars(exampleRows, 'exampleProveChart', 'zig_over_rust_prove', 'prove', 'name');
    renderBars(exampleRows, 'exampleVerifyChart', 'zig_over_rust_verify', 'verify', 'name');
    renderBars(exampleRows, 'exampleSizeChart', 'zig_over_rust_proof_wire_bytes', 'size', 'name');
    renderBars(exampleRows, 'exampleRssChart', 'zig_over_rust_peak_rss_kb', 'rss', 'name');

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

    document.getElementById('meta').textContent = `families_source=${data.sources.families_report} | examples_source=${data.sources.examples_report}`;
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
