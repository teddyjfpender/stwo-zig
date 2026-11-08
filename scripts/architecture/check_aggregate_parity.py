#!/usr/bin/env python3
"""Validate focused/aggregate Native behavior and verification parity."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.architecture_host_gate_lib.aggregate_parity import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
