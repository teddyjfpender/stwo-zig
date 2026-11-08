#!/usr/bin/env python3
"""Compare compatible benchmark reports and preserve their exact source bytes."""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from benchmark_delta_lib.controller import (  # noqa: E402
    DELTA_PROTOCOL,
    DELTA_SCHEMA_VERSION,
    MAX_REPORT_BYTES,
    NATIVE_PROTOCOL,
    NATIVE_PROTOCOL_V3,
    NATIVE_PROTOCOL_V4,
    NATIVE_PROTOCOL_V5,
    NATIVE_PROTOCOL_V6,
    NATIVE_PROTOCOLS,
    SUPPORTED_PROTOCOLS,
    UPSTREAM_PROTOCOL,
    DeltaError,
    IncompatibleReports,
    build_parser,
    compare_native,
    compare_reports,
    compare_upstream,
    comparison_summary,
    load_report,
    main,
    metric_delta,
    metric_record,
    parse_timestamp,
    validate_native_v4_report,
    validate_native_v6_report,
)

__all__ = [
    "DELTA_PROTOCOL",
    "DELTA_SCHEMA_VERSION",
    "MAX_REPORT_BYTES",
    "NATIVE_PROTOCOL",
    "NATIVE_PROTOCOL_V3",
    "NATIVE_PROTOCOL_V4",
    "NATIVE_PROTOCOL_V5",
    "NATIVE_PROTOCOL_V6",
    "NATIVE_PROTOCOLS",
    "SUPPORTED_PROTOCOLS",
    "UPSTREAM_PROTOCOL",
    "DeltaError",
    "IncompatibleReports",
    "build_parser",
    "compare_native",
    "compare_reports",
    "compare_upstream",
    "comparison_summary",
    "load_report",
    "main",
    "metric_delta",
    "metric_record",
    "parse_timestamp",
    "validate_native_v4_report",
    "validate_native_v6_report",
]


if __name__ == "__main__":
    raise SystemExit(main())
