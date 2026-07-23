#!/usr/bin/env python3
"""Verify the exact imported CUDA/C++ source closure."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src/backends/cuda/vendor/upstream"
MANIFEST = ROOT / "src/backends/cuda/source_manifest.json"

UPSTREAM = {
    "repository": "https://github.com/teddyjfpender/stwo",
    "branch": "perf-optimizations",
    "commit": "1d1d10c31fdac45c9ecb7aee9d3e8935b5cf8035",
    "tree": "044f995e98ba6f2fdb5a1634a99c14927d7a93c0",
    "path": "crates/backend-cuda-kernels/cuda",
}


def source_files() -> list[Path]:
    files = sorted(path for path in SOURCE_ROOT.rglob("*") if path.is_file())
    if not files:
        raise SystemExit(f"CUDA source closure is empty: {SOURCE_ROOT}")
    symlinks = [path for path in SOURCE_ROOT.rglob("*") if path.is_symlink()]
    if symlinks:
        joined = ", ".join(str(path.relative_to(ROOT)) for path in symlinks)
        raise SystemExit(f"CUDA source closure contains symlinks: {joined}")
    return files


def build_manifest() -> dict[str, object]:
    entries: list[dict[str, object]] = []
    closure = hashlib.sha256()
    byte_count = 0
    for path in source_files():
        relative = path.relative_to(SOURCE_ROOT).as_posix()
        payload = path.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        encoded_path = relative.encode("utf-8")
        closure.update(len(encoded_path).to_bytes(8, "little"))
        closure.update(encoded_path)
        closure.update(len(payload).to_bytes(8, "little"))
        closure.update(payload)
        byte_count += len(payload)
        entries.append({"path": relative, "bytes": len(payload), "sha256": digest})
    return {
        "schema": "stwo-zig-cuda-source-closure-v1",
        "upstream": UPSTREAM,
        "file_count": len(entries),
        "byte_count": byte_count,
        "closure_sha256": closure.hexdigest(),
        "files": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="replace the tracked manifest with the current imported closure",
    )
    args = parser.parse_args()
    actual = build_manifest()
    encoded = json.dumps(actual, indent=2, sort_keys=True) + "\n"
    if args.write:
        MANIFEST.write_text(encoded, encoding="utf-8")
        print(
            f"wrote {MANIFEST.relative_to(ROOT)}: "
            f"{actual['file_count']} files, {actual['closure_sha256']}"
        )
        return 0
    if not MANIFEST.is_file():
        raise SystemExit(f"missing CUDA source manifest: {MANIFEST}")
    expected = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if actual != expected:
        raise SystemExit(
            "imported CUDA source closure differs from its pinned manifest; "
            "run with --write only for a reviewed upstream import"
        )
    print(
        f"CUDA source closure verified: "
        f"{actual['file_count']} files, {actual['closure_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
