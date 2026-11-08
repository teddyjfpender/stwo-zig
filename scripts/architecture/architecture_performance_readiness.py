#!/usr/bin/env python3
"""Emit BG-14 epoch-two harness readiness without running performance promotion."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

try:
    from architecture_host_gate_lib.performance_readiness import ReadinessError, inspect
except ModuleNotFoundError:
    from scripts.architecture_host_gate_lib.performance_readiness import ReadinessError, inspect


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--protocol", type=Path,
        default=ROOT / "conformance/build-monorepo-performance-baseline-v2-protocol-v2.json",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = inspect(args.root, args.protocol)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=args.output.name + ".", dir=args.output.parent)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, args.output)
    except (OSError, ValueError, ReadinessError) as error:
        print(f"architecture performance readiness: FAIL: {error}")
        return 2
    print("architecture performance state: DEFERRED (architecture checkpoint PASS)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
