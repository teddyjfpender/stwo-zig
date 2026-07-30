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
        "expected_closure": {
            "file_count": 458,
            "byte_count": 33508731,
            "closure_sha256": "63c7503f83ed467fdcf010be867b0f395ace8a4a0d1d11572112ce7405cbbe2b",
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
            "repository_tree": "55cbec6c408dfc4e81c722deca9f5526d3785536",
            "paths": [
                "Cargo.lock",
                "Cargo.toml",
                "LICENSE",
                "rust-toolchain.toml",
                "rustfmt.toml",
                "crates/*",
            ],
        },
        "expected_closure": {
            "file_count": 1003,
            "byte_count": 44877364,
            "closure_sha256": "8592124d6ad17610e23171fa7160030f8f76e21f4deff35e76699de8ad515341",
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


def validate_expected_closure(
    authority: dict[str, object],
    actual: dict[str, object],
) -> None:
    expected = authority.get("expected_closure")
    if not isinstance(expected, dict):
        raise SystemExit(
            f"CUDA {authority['name']} authority lacks an immutable closure pin"
        )
    observed = {
        key: actual.get(key)
        for key in ("file_count", "byte_count", "closure_sha256")
    }
    if observed != expected:
        raise SystemExit(
            f"imported CUDA {authority['name']} authority differs from the "
            "closure pinned to its declared upstream commit/tree; update the "
            "authority pin only as part of a reviewed whole-import change"
        )


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
        validate_expected_closure(authority, actual)
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
