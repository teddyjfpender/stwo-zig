"""Fingerprint compiler inputs, including shared guest-runtime dependency patches."""

import hashlib

COMPILE_SUFFIXES = {
    ".rs",
    ".toml",
    ".lock",
    ".json",
    ".ld",
    ".md",
    ".zig",
    ".h",
    ".c",
    ".py",
}


def compile_sources(root):
    runtime = root / "autoresearch/benchmarks/guest_runtime"
    rv64 = runtime / "ethereum/rv64"
    roots = [
        root / "opstack/kona",
        runtime / "exact_layout_allocator_v2.rs",
        rv64 / "src",
        rv64 / "mem",
        root / "src",
        root / "opstack/build.py",
        root / "opstack/source_identity.py",
    ]
    roots += [
        rv64 / "vendor" / name
        for name in ["k256", "ecdsa", "revm-interpreter", "revm-bytecode", "sha2-rv64"]
    ]
    files = {}
    for base in roots:
        paths = [base] if base.is_file() else base.rglob("*")
        for path in paths:
            if (
                not path.is_file()
                or "target" in path.parts
                or path.suffix not in COMPILE_SUFFIXES
            ):
                continue
            data = path.read_bytes()
            files[str(path.relative_to(root))] = {
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
    return dict(sorted(files.items()))


def require_unchanged(before, after):
    changed = sorted(
        name for name in set(before) | set(after) if before.get(name) != after.get(name)
    )
    if changed:
        raise ValueError(
            "compiler inputs changed during build: " + ", ".join(changed[:8])
        )
