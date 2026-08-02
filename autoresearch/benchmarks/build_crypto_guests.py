#!/usr/bin/env python3
"""Build and vendor the cryptographic RISC-V guest ELFs used by the perf matrix.

These guests are COMPILED RV32IM programs (SHA-256, Keccak, ECDSA from the
pinned Stark-V guest-lib, plus a repo-owned Poseidon2-M31 guest), not the
byte-reproducible hand-assembled corpus. They cannot be regenerated
byte-identically across toolchain versions, so they are vendored as fixtures
under vectors/riscv_elfs/crypto/ with a provenance record (source commit,
toolchain, per-ELF sha256). Both provers run the SAME committed ELF, so the
comparison is exact.

Usage:
  python3 autoresearch/benchmarks/build_crypto_guests.py --stark-v-source <checkout>

The checkout must be at the pinned Stark-V commit. Requires the guest toolchain
(nightly-2026-01-29 with the riscv32im-unknown-none-elf target).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CRYPTO_DIR = ROOT / "vectors/riscv_elfs/crypto"
PROVENANCE = CRYPTO_DIR / "provenance.json"
PINNED_COMMIT = "d478f783055aa0d73a93768a433a3c6c31c91d1c"
GUEST_TARGET = "riscv32im-unknown-none-elf"
BYTE_INPUT_SIZES = (128, 256, 512, 1024, 2048)
POSEIDON_WIDTHS = (2, 4, 8, 12, 16)
M31_P = 0x7FFF_FFFF
POSEIDON_CRATE = ROOT / "vectors/riscv_guests/poseidon2_m31"

# Guests sourced from the pinned Stark-V guest-lib. `input_sweep` guests read a
# [len u32 LE][data] buffer; `fixed` guests take no input. Eval classes:
#   provable                    - matched prove/verify on both lanes, all sizes
#   provable_single_block_only  - only the single-block (128B) case is matched;
#                                 multi-block touches Stark-V's signed-mulh path
#                                 that the Zig port fails closed on
#   execution_only              - both lanes EXECUTE it, but neither proves it at
#                                 the pinned config (Stark-V's own prover fails)
STARK_V_GUESTS = {
    "sha2_input": {"kind": "input_sweep", "hash": "sha256", "eval": "provable"},
    "keccak_input": {
        "kind": "input_sweep",
        "hash": "keccak",
        "eval": "provable_single_block_only",
        "note": "multi-block (>=256B) touches Stark-V's signed-mulh limitation; "
        "the Zig port fails closed there, so only the 128B single-block case "
        "is a matched provable row",
    },
    "ecdsa": {
        "kind": "fixed",
        "eval": "execution_only",
        "note": "~6M cycles needs trace log_size 23 > the pinned prover's 22 cap; "
        "Stark-V's own prover fails to prove it",
    },
}

# Repo-owned guest (not from Stark-V). Poseidon2's x^5 S-box is multiply-heavy;
# the pinned Stark-V prover panics on the resulting trace (same signature as its
# mul_div limitation vector), so it too is execution-only at the pin.
REPO_GUESTS = {
    "poseidon2_m31": {
        "kind": "field_sweep",
        "eval": "execution_only",
        "source": "repo: vectors/riscv_guests/poseidon2_m31",
        "note": "Poseidon2-over-M31 (stwo's own permutation params); pinned "
        "Stark-V prover panics proving the multiply-heavy trace",
    },
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(cmd: list[str], cwd: Path) -> str:
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(cmd)}\n{result.stderr[-600:]}")
    return result.stdout


def make_byte_input(size: int) -> bytes:
    """Deterministic [len u32 LE][data] buffer; committed so runs are reproducible."""
    data = bytes((i * 7 + 1) & 0xFF for i in range(size))
    return size.to_bytes(4, "little") + data


def make_field_input(n: int) -> bytes:
    """[n u32 LE][n field elements u32 LE], each already reduced mod M31."""
    elements = [((i + 1) * 2654435761) % M31_P for i in range(n)]
    return n.to_bytes(4, "little") + b"".join(e.to_bytes(4, "little") for e in elements)


def validate_source(source: Path) -> None:
    head = run(["git", "rev-parse", "HEAD"], source).strip()
    if head != PINNED_COMMIT:
        raise SystemExit(f"Stark-V checkout is at {head}, not the pinned {PINNED_COMMIT}")


def build_stark_v_guests(source: Path) -> tuple[dict[str, str], str]:
    guest_bin = source / "guest/guest-bin"
    run(["cargo", "build", "--release"], guest_bin)
    out = guest_bin / "target" / GUEST_TARGET / "release"
    toolchain = run(["rustc", "--version"], guest_bin).strip()
    elf_sha: dict[str, str] = {}
    for name in STARK_V_GUESTS:
        built = out / name
        if not built.exists():
            raise SystemExit(f"guest ELF not produced: {built}")
        vendored = CRYPTO_DIR / f"{name}.elf"
        shutil.copyfile(built, vendored)
        elf_sha[name] = sha256_file(vendored)
    return elf_sha, toolchain


def build_repo_guests() -> dict[str, str]:
    run(["cargo", "build", "--release"], POSEIDON_CRATE)
    out = POSEIDON_CRATE / "target" / GUEST_TARGET / "release"
    elf_sha: dict[str, str] = {}
    for name in REPO_GUESTS:
        built = out / name
        if not built.exists():
            raise SystemExit(f"repo guest ELF not produced: {built}")
        vendored = CRYPTO_DIR / f"{name}.elf"
        shutil.copyfile(built, vendored)
        elf_sha[name] = sha256_file(vendored)
    return elf_sha


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stark-v-source", required=True, type=Path)
    args = parser.parse_args(argv)

    source = args.stark_v_source.resolve()
    validate_source(source)
    CRYPTO_DIR.mkdir(parents=True, exist_ok=True)

    input_dir = CRYPTO_DIR / "inputs"
    input_dir.mkdir(exist_ok=True)
    input_sha: dict[str, str] = {}
    for size in BYTE_INPUT_SIZES:
        path = input_dir / f"msg_{size}.bin"
        path.write_bytes(make_byte_input(size))
        input_sha[f"msg_{size}.bin"] = sha256_file(path)
    for width in POSEIDON_WIDTHS:
        path = input_dir / f"field_{width}.bin"
        path.write_bytes(make_field_input(width))
        input_sha[f"field_{width}.bin"] = sha256_file(path)

    elf_sha, toolchain = build_stark_v_guests(source)
    elf_sha.update(build_repo_guests())

    guests = {}
    for name, spec in STARK_V_GUESTS.items():
        entry = dict(spec)
        entry["elf"] = f"vectors/riscv_elfs/crypto/{name}.elf"
        entry["elf_sha256"] = elf_sha[name]
        entry.setdefault("source", "stark-v guest-lib")
        entry["metal_backend"] = "gated_riscv_adapter_is_cpu_only"
        guests[name] = entry
    for name, spec in REPO_GUESTS.items():
        entry = dict(spec)
        entry["elf"] = f"vectors/riscv_elfs/crypto/{name}.elf"
        entry["elf_sha256"] = elf_sha[name]
        entry["metal_backend"] = "gated_riscv_adapter_is_cpu_only"
        guests[name] = entry

    provenance = {
        "schema": "riscv_crypto_guests_v1",
        "stark_v_commit": PINNED_COMMIT,
        "guest_target": GUEST_TARGET,
        "guest_toolchain": toolchain,
        "byte_input_sizes": list(BYTE_INPUT_SIZES),
        "poseidon_field_widths": list(POSEIDON_WIDTHS),
        "input_format": {
            "byte": "[len u32 LE][data bytes]; pattern (i*7+1) mod 256",
            "field": "[n u32 LE][n field elements u32 LE]; ((i+1)*2654435761) mod M31",
        },
        "input_sha256": input_sha,
        "guests": guests,
    }
    PROVENANCE.write_text(json.dumps(provenance, indent=1, sort_keys=True) + "\n")
    print(f"vendored {len(guests)} guests + {len(input_sha)} inputs -> {CRYPTO_DIR}")
    for name, entry in guests.items():
        print(f"  {name:14s} {entry['eval']:28s} {entry['elf_sha256'][:12]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
