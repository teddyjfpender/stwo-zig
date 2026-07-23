#!/usr/bin/env python3
"""Verify the exact imported CUDA and host-orchestration source authorities."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUTHORITIES = (
    {
        "name": "kernels",
        "source_root": ROOT / "src/backends/cuda/vendor/upstream",
        "manifest": ROOT / "src/backends/cuda/source_manifest.json",
        "upstream": {
            "repository": "https://github.com/teddyjfpender/stwo",
            "branch": "perf-optimizations",
            "commit": "1d1d10c31fdac45c9ecb7aee9d3e8935b5cf8035",
            "tree": "044f995e98ba6f2fdb5a1634a99c14927d7a93c0",
            "path": "crates/backend-cuda-kernels/cuda",
        },
    },
    {
        "name": "host",
        "source_root": ROOT / "src/backends/cuda/vendor/host_authority",
        "manifest": ROOT / "src/backends/cuda/host_source_manifest.json",
        "upstream": {
            "repository": "https://github.com/teddyjfpender/stwo",
            "branch": "perf-optimizations",
            "commit": "1d1d10c31fdac45c9ecb7aee9d3e8935b5cf8035",
            "trees": {
                "crates/backend-cuda": "475d8e3ec4b94b3f6901ead8c7376eefa7840893",
                "crates/backend-cuda-kernels": "a54a12de9fa3c7fd406154b501cb5e1d8a988eed",
            },
            "paths": [
                "crates/backend-cuda",
                "crates/backend-cuda-kernels/Cargo.toml",
                "crates/backend-cuda-kernels/build.rs",
                "crates/backend-cuda-kernels/src",
            ],
        },
    },
)


def source_files(source_root: Path) -> list[Path]:
    files = sorted(path for path in source_root.rglob("*") if path.is_file())
    if not files:
        raise SystemExit(f"CUDA source authority is empty: {source_root}")
    symlinks = [path for path in source_root.rglob("*") if path.is_symlink()]
    if symlinks:
        joined = ", ".join(str(path.relative_to(ROOT)) for path in symlinks)
        raise SystemExit(f"CUDA source authority contains symlinks: {joined}")
    return files


def build_manifest(authority: dict[str, object]) -> dict[str, object]:
    source_root = authority["source_root"]
    assert isinstance(source_root, Path)
    entries: list[dict[str, object]] = []
    closure = hashlib.sha256()
    byte_count = 0
    for path in source_files(source_root):
        relative = path.relative_to(source_root).as_posix()
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
        "authority": authority["name"],
        "upstream": authority["upstream"],
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
    for authority in AUTHORITIES:
        actual = build_manifest(authority)
        manifest = authority["manifest"]
        assert isinstance(manifest, Path)
        encoded = json.dumps(actual, indent=2, sort_keys=True) + "\n"
        if args.write:
            manifest.write_text(encoded, encoding="utf-8")
            print(
                f"wrote {manifest.relative_to(ROOT)}: "
                f"{actual['file_count']} files, {actual['closure_sha256']}"
            )
            continue
        if not manifest.is_file():
            raise SystemExit(f"missing CUDA source manifest: {manifest}")
        expected = json.loads(manifest.read_text(encoding="utf-8"))
        if actual != expected:
            raise SystemExit(
                f"imported CUDA {authority['name']} authority differs from its "
                "pinned manifest; run with --write only for a reviewed upstream import"
            )
        print(
            f"CUDA {authority['name']} authority verified: "
            f"{actual['file_count']} files, {actual['closure_sha256']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
