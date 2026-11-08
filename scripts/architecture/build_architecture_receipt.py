#!/usr/bin/env python3
"""Produce and verify versioned Zig build-architecture receipts."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.build_architecture_receipt_lib import controller  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    return controller.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
