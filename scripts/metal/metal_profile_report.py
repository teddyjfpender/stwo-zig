#!/usr/bin/env python3
"""Render stwo-zig Metal NDJSON telemetry as a strict hot-path report."""

from __future__ import annotations

import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from metal_profile_report_lib import (  # noqa: E402
    ProfileError,
    build_report,
    format_text,
    load_events,
    main as aggregate_main,
)

__all__ = ["ProfileError", "build_report", "format_text", "load_events", "main"]


def main(argv: list[str] | None = None) -> int:
    return aggregate_main(argv)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ProfileError) as error:
        print(f"metal_profile_report: {error}", file=sys.stderr)
        raise SystemExit(1)
