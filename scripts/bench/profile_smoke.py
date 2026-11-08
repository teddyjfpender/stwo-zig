#!/usr/bin/env python3
"""Run the bounded Rust/Zig profiling evidence protocol."""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from profile_smoke_lib.controller import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
