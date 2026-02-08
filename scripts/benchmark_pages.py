#!/usr/bin/env python3
"""Render static benchmark chart assets from benchmark_full report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
SOURCE_REPORT_DEFAULT = ROOT / "vectors" / "reports" / "benchmark_full_report.json"
OUT_DIR_DEFAULT = ROOT / "bench" / "dev" / "bench"
OUT_DATA_DEFAULT = OUT_DIR_DEFAULT / "data.js"
OUT_INDEX_DEFAULT = OUT_DIR_DEFAULT / "index.html"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate static benchmark chart assets")
    parser.add_argument(
        "--source-report",
        type=Path,
        default=SOURCE_REPORT_DEFAULT,
        help="Path to benchmark_full_report.json",
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


def build_payload(report: dict[str, Any], report_path: Path) -> dict[str, Any]:
    families = report.get("families", [])
    rows: list[dict[str, Any]] = []
    for family in families:
        name = str(family.get("family", "unknown"))
        ratios = family.get("ratios", {})
        rust = family.get("rust", {})
        zig = family.get("zig", {})
        rows.append(
            {
                "family": name,
                "zig_over_rust_prove": float(ratios.get("zig_over_rust_prove", 0.0)),
                "zig_over_rust_verify": float(ratios.get("zig_over_rust_verify", 0.0)),
                "zig_over_rust_proof_wire_bytes": float(ratios.get("zig_over_rust_proof_wire_bytes", 0.0)),
                "rust_prove_avg_seconds": float(rust.get("prove", {}).get("avg_seconds", 0.0)),
                "rust_verify_avg_seconds": float(rust.get("verify", {}).get("avg_seconds", 0.0)),
                "zig_prove_avg_seconds": float(zig.get("prove", {}).get("avg_seconds", 0.0)),
                "zig_verify_avg_seconds": float(zig.get("verify", {}).get("avg_seconds", 0.0)),
            }
        )

    return {
        "schema_version": 1,
        "source_report": str(report_path.relative_to(ROOT)),
        "summary": report.get("summary", {}),
        "rows": rows,
    }


def render_data_js(payload: dict[str, Any]) -> str:
    return "window.BENCHMARK_FULL_DATA = " + json.dumps(payload, indent=2, sort_keys=True) + ";\n"


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
    p { margin: 0 0 16px; }
    .card { background: #fff; border: 1px solid #d0d7de; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
    .chart { display: grid; grid-template-columns: 220px 1fr 80px; row-gap: 6px; column-gap: 8px; align-items: center; }
    .label { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .bar-wrap { height: 14px; background: #eaeef2; border-radius: 3px; overflow: hidden; }
    .bar { height: 100%; }
    .bar.prove { background: #1f6feb; }
    .bar.verify { background: #fb8500; }
    .bar.size { background: #2a9d8f; }
    .value { text-align: right; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { text-align: left; border-bottom: 1px solid #d8dee4; padding: 6px 8px; }
    th { background: #f0f3f6; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  </style>
</head>
<body>
  <h1>stwo-zig Benchmark Parity</h1>
  <p>Generated from committed benchmark data.</p>

  <div class=\"card\">
    <h2>Prove Ratio (Zig over Rust)</h2>
    <div id=\"proveChart\" class=\"chart\"></div>
  </div>

  <div class=\"card\">
    <h2>Verify Ratio (Zig over Rust)</h2>
    <div id=\"verifyChart\" class=\"chart\"></div>
  </div>

  <div class=\"card\">
    <h2>Proof-Size Ratio (Zig over Rust)</h2>
    <div id=\"sizeChart\" class=\"chart\"></div>
  </div>

  <div class=\"card\">
    <h2>Raw Averages (seconds)</h2>
    <table id=\"dataTable\">
      <thead>
        <tr>
          <th>Family</th>
          <th>Zig/Rust Prove</th>
          <th>Zig/Rust Verify</th>
          <th>Zig/Rust Proof Size</th>
          <th>Rust Prove</th>
          <th>Zig Prove</th>
          <th>Rust Verify</th>
          <th>Zig Verify</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
    <p class=\"mono\" id=\"meta\"></p>
  </div>

  <script src=\"data.js\"></script>
  <script>
    const data = window.BENCHMARK_FULL_DATA;
    const rows = data.rows || [];

    function renderBars(targetId, key, barClass) {
      const target = document.getElementById(targetId);
      const max = Math.max(...rows.map(r => r[key]), 0.000001);
      rows.forEach((r) => {
        const label = document.createElement('div');
        label.className = 'label';
        label.textContent = r.family;

        const wrap = document.createElement('div');
        wrap.className = 'bar-wrap';
        const bar = document.createElement('div');
        bar.className = `bar ${barClass}`;
        const pct = Math.min((r[key] / max) * 100, 100);
        bar.style.width = `${pct.toFixed(2)}%`;
        wrap.appendChild(bar);

        const value = document.createElement('div');
        value.className = 'value';
        value.textContent = r[key].toFixed(6);

        target.appendChild(label);
        target.appendChild(wrap);
        target.appendChild(value);
      });
    }

    renderBars('proveChart', 'zig_over_rust_prove', 'prove');
    renderBars('verifyChart', 'zig_over_rust_verify', 'verify');
    renderBars('sizeChart', 'zig_over_rust_proof_wire_bytes', 'size');

    const tbody = document.querySelector('#dataTable tbody');
    rows.forEach((r) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${r.family}</td>
        <td>${r.zig_over_rust_prove.toFixed(6)}</td>
        <td>${r.zig_over_rust_verify.toFixed(6)}</td>
        <td>${r.zig_over_rust_proof_wire_bytes.toFixed(6)}</td>
        <td>${r.rust_prove_avg_seconds.toFixed(6)}</td>
        <td>${r.zig_prove_avg_seconds.toFixed(6)}</td>
        <td>${r.rust_verify_avg_seconds.toFixed(6)}</td>
        <td>${r.zig_verify_avg_seconds.toFixed(6)}</td>
      `;
      tbody.appendChild(tr);
    });

    document.getElementById('meta').textContent = `source=${data.source_report}`;
  </script>
</body>
</html>
"""


def main() -> int:
    args = parse_args()
    if not args.source_report.exists():
        raise RuntimeError(f"missing benchmark report: {args.source_report}")
    report = json.loads(args.source_report.read_text(encoding="utf-8"))
    if report.get("status") != "ok":
        raise RuntimeError("benchmark_full report status is not ok")

    payload = build_payload(report, args.source_report)
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
