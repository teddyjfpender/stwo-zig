#!/usr/bin/env python3
"""Execute the checked-in architecture phase plan and emit host evidence."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.architecture_host_gate_lib import controller  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    return controller.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
