#!/usr/bin/env python3
"""Inspect architecture binaries against focused linkage policy."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.architecture_host_gate_lib.link_closure import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
