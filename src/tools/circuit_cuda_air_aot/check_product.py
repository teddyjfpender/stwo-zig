#!/usr/bin/env python3
"""Admit generated circuit AIR CUDA sources against the pinned AOT product."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from scripts.cuda_build_lib.product_selection import validate_aot_manifest  # noqa: E402


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("expected generated and pinned circuit AOT directories")
    generated, pinned = (Path(value) for value in sys.argv[1:])
    generated_manifest = json.loads((generated / "aot_manifest.json").read_text())
    pinned_manifest = json.loads((pinned / "aot_manifest.json").read_text())
    validate_aot_manifest(generated, generated_manifest)
    validate_aot_manifest(pinned, pinned_manifest)
    if generated_manifest != pinned_manifest or len(pinned_manifest) != 11:
        raise SystemExit("circuit AOT product inventory differs from pinned AIR")
    for entry in pinned_manifest:
        filename = entry["file"]
        if (generated / filename).read_bytes() != (pinned / filename).read_bytes():
            raise SystemExit(f"circuit AOT source differs from pinned AIR: {filename}")
    print("circuit CUDA AOT product: eleven pinned kernels admitted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
