"""Identity-bound closure for product-owned CUDA and C++ sources."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .errors import BuildError


def load_native_closure(native_root: Path) -> dict[str, object]:
    native_root = native_root.resolve()
    if not native_root.is_dir():
        raise BuildError(f"Zig-owned CUDA runtime source is absent: {native_root}")
    files = sorted(path for path in native_root.rglob("*") if path.is_file())
    if not files or any(path.is_symlink() for path in native_root.rglob("*")):
        raise BuildError("Zig-owned CUDA runtime must be a non-empty regular-file closure")
    if any(path.suffix not in {".cpp", ".h", ".cu", ".cuh"} for path in files):
        raise BuildError("Zig-owned CUDA runtime contains an unsupported source type")

    digest = hashlib.sha256()
    entries: list[dict[str, object]] = []
    for path in files:
        relative = path.relative_to(native_root).as_posix()
        payload = path.read_bytes()
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "little"))
        digest.update(encoded)
        digest.update(len(payload).to_bytes(8, "little"))
        digest.update(payload)
        entries.append(
            {
                "path": relative,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )

    host_sources = [
        native_root / str(entry["path"])
        for entry in entries
        if str(entry["path"]).endswith(".cpp")
    ]
    cuda_sources = [
        native_root / str(entry["path"])
        for entry in entries
        if str(entry["path"]).endswith(".cu")
    ]
    if not host_sources:
        raise BuildError("Zig-owned CUDA runtime contains no C++ implementation")
    return {
        "root": native_root,
        "closure_sha256": digest.hexdigest(),
        "files": entries,
        "sources": [*host_sources, *cuda_sources],
        "host_sources": host_sources,
        "cuda_sources": cuda_sources,
    }
