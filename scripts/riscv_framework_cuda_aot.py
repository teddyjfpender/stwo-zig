#!/usr/bin/env python3
"""Stage a pinned recursive-framework source catalog for the CUDA AOT builder.

This is an offline native-kernel product, not the unfinished resident RISC-V
backend. No compiler, GPU execution or proof verification is implied by staging.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from cuda_build_lib.framework_identity import stage_framework_product


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export-dir", type=Path, required=True)
    parser.add_argument("--export-sha256", required=True)
    parser.add_argument("--field-header", type=Path, required=True)
    parser.add_argument("--field-sha256", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    path = stage_framework_product(args.export_dir, args.export_sha256, args.field_header,
                                   args.field_sha256, args.destination)
    # The native builder selects only '.', even though the canonical catalog
    # names other, unselected product sets. No frontend availability is changed.
    declaration = Path(__file__).resolve().parents[1] / "src/backends/cuda/aot/native/product_sets.json"
    (path.parent / "product_sets.json").write_bytes(declaration.read_bytes())
    print(json.dumps({"schema": "stwo-cuda-framework-staging-v1",
                      "aot_manifest_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                      "source_catalog_sha256": args.export_sha256,
                      "field_sha256": args.field_sha256,
                      "entries": len(json.loads(path.read_bytes())),
                      "frontend": "native", "aot_sets": ["."],
                      "device_compiled": False, "device_executed": False,
                      "proof_verified": False}, indent=2))


if __name__ == "__main__":
    main()
