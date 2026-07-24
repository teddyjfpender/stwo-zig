from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from .identity import (
    DEFAULT_REPORT,
    CoverageError,
    decoder_identity,
    load_json,
    named_paths,
)
from .report import build_report, verify_record, write_report
from .shape import capture_shape_reports


def capture(args: argparse.Namespace) -> dict[str, Any]:
    pies = named_paths(args.pie, "--pie")
    source_root = args.source_root.resolve()
    work_dir = args.work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    decoder = decoder_identity(
        args.decoder_cairo_root.resolve(),
        args.decoder_stwo_root.resolve(),
        args.gpu_bench,
        args.kernel_emit,
        gate_captured=True,
    )
    census_path = work_dir / "witness_census.txt"
    census = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "--manifest-path",
            str(source_root / "tools/witness_genericize/Cargo.toml"),
            "--",
            "--census",
            str(source_root / "crates/prover/src/witness/components"),
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    census_path.write_text(census.stdout, encoding="utf-8")
    adapted, shapes = capture_shape_reports(
        pies,
        work_dir,
        args.gpu_bench,
        args.kernel_emit,
        reuse_sealed_adapted=args.reuse_sealed_adapted,
    )
    return build_report(
        pies,
        adapted,
        shapes,
        source_root,
        census_path,
        decoder,
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Capture and verify source-owned Cairo component coverage for four SN PIEs."
        )
    )
    subparsers = result.add_subparsers(dest="command", required=True)

    capture_parser = subparsers.add_parser("capture")
    capture_parser.add_argument("--pie", action="append", required=True)
    capture_parser.add_argument("--source-root", type=Path, required=True)
    capture_parser.add_argument("--decoder-cairo-root", type=Path, required=True)
    capture_parser.add_argument("--decoder-stwo-root", type=Path, required=True)
    capture_parser.add_argument("--gpu-bench", type=Path, required=True)
    capture_parser.add_argument("--kernel-emit", type=Path, required=True)
    capture_parser.add_argument("--work-dir", type=Path, required=True)
    capture_parser.add_argument("--reuse-sealed-adapted", action="store_true")
    capture_parser.add_argument("--output", type=Path, default=DEFAULT_REPORT)
    capture_parser.add_argument("--record-blockers", action="store_true")

    report_parser = subparsers.add_parser("report")
    report_parser.add_argument("--pie", action="append", required=True)
    report_parser.add_argument("--adapted", action="append", required=True)
    report_parser.add_argument("--shape-report", action="append", required=True)
    report_parser.add_argument("--source-root", type=Path, required=True)
    report_parser.add_argument("--census", type=Path, required=True)
    report_parser.add_argument("--decoder-cairo-root", type=Path, required=True)
    report_parser.add_argument("--decoder-stwo-root", type=Path, required=True)
    report_parser.add_argument("--gpu-bench", type=Path, required=True)
    report_parser.add_argument("--kernel-emit", type=Path, required=True)
    report_parser.add_argument("--output", type=Path, default=DEFAULT_REPORT)
    report_parser.add_argument("--record-blockers", action="store_true")

    check_parser = subparsers.add_parser("check-record")
    check_parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    check_parser.add_argument("--require-coverage-ready", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "check-record":
            report_path = args.report.resolve()
            report = load_json(report_path)
            verify_record(report, report_path)
            if args.require_coverage_ready and not report["source_coverage_admissible"]:
                raise CoverageError(
                    "source coverage is not admissible: "
                    + json.dumps(report["blockers"], sort_keys=True)
                )
            print(
                json.dumps(
                    {
                        "report": str(report_path),
                        "source_coverage_admissible": report[
                            "source_coverage_admissible"
                        ],
                        "component_count": len(report["component_union"]),
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "capture":
            report = capture(args)
        else:
            report = build_report(
                named_paths(args.pie, "--pie"),
                named_paths(args.adapted, "--adapted"),
                named_paths(args.shape_report, "--shape-report"),
                args.source_root.resolve(),
                args.census.resolve(),
                decoder_identity(
                    args.decoder_cairo_root.resolve(),
                    args.decoder_stwo_root.resolve(),
                    args.gpu_bench,
                    args.kernel_emit,
                    gate_captured=False,
                ),
            )
        write_report(report, args.output.resolve())
        if not report["source_coverage_admissible"] and not args.record_blockers:
            raise CoverageError(
                "coverage report recorded but source coverage admission failed: "
                + json.dumps(report["blockers"], sort_keys=True)
            )
        return 0
    except (CoverageError, OSError, subprocess.CalledProcessError) as error:
        print(f"cairo-four-pie-coverage: {error}", file=sys.stderr)
        return 1
