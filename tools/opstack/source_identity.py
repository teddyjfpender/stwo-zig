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
    ".bin",  # include_bytes! compiler inputs, including the fixed blob domain
}


def compile_sources(root, execution_crate="guests/opstack/kona"):
    guests = root / "guests/opstack"
    # Read-only path dependencies on the Ethereum RV64 guest runtime (exception E-3).
    rv64 = root / "guests/ethereum/rv64"
    roots = [
        root / execution_crate,
        guests / "runtime",
        guests / "vendor",
        rv64 / "src",
        rv64 / "mem",
        rv64 / "service_abi",
        root / "src",
        root / "tools/opstack/build.py",
        root / "tools/opstack/source_identity.py",
    ]
    if execution_crate != "guests/opstack/kona":
        roots += [root / "guests/opstack/kona/guest" / name
                  for name in ("riscv64i-stwo.json", "linker.ld")]
        roots += [root / "guests/opstack/kona/guest/src/keccak_sponge_service.rs"]
    roots += [
        rv64 / "vendor" / name
        for name in ["k256", "ecdsa", "revm-interpreter", "sha2-rv64"]
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
