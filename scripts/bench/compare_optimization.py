#!/usr/bin/env python3
"""Capture and compare optimization baseline/evidence for stwo-zig."""

from __future__ import annotations

import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from optimization_compare_lib.controller import (  # noqa: E402
    BASELINE_DEFAULT,
    BENCHMARK_FULL_REPORT_DEFAULT,
    BENCHMARK_REPORT_DEFAULT,
    COMPARE_REPORT_DEFAULT,
    KERNEL_REPORT_DEFAULT,
    LATEST_COMPARE_REPORT,
    PROFILE_REPORT_DEFAULT,
    REPORTS_DIR,
    ROOT,
    TARGET_FAMILY_DEFAULTS,
    CompareError,
    capture_baseline,
    evaluate_comparison,
    load_json,
    main,
    maybe_load_json,
    parse_args,
    parse_target_families,
    rel,
    run_capture,
    run_self_test,
)

__all__ = [
    "BASELINE_DEFAULT",
    "BENCHMARK_FULL_REPORT_DEFAULT",
    "BENCHMARK_REPORT_DEFAULT",
    "COMPARE_REPORT_DEFAULT",
    "KERNEL_REPORT_DEFAULT",
    "LATEST_COMPARE_REPORT",
    "PROFILE_REPORT_DEFAULT",
    "REPORTS_DIR",
    "ROOT",
    "TARGET_FAMILY_DEFAULTS",
    "CompareError",
    "capture_baseline",
    "evaluate_comparison",
    "load_json",
    "main",
    "maybe_load_json",
    "parse_args",
    "parse_target_families",
    "rel",
    "run_capture",
    "run_self_test",
]


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CompareError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True))
        raise SystemExit(1)
