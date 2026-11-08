#!/usr/bin/env python3
"""Run the fail-closed Native CUDA activation authority gate."""

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.native_cuda_benchmark_lib.activation import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
