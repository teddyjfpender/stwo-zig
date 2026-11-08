#!/usr/bin/env python3
"""Capture reproducible Metal AOT builds, then admit them on a real device."""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from metal_core_aot_receipt_lib import ReceiptError, main  # noqa: E402


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ReceiptError) as error:
        print(f"metal core AOT receipt failed: {error}", file=sys.stderr)
        raise SystemExit(2)
