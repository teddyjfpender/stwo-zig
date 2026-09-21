#!/usr/bin/env python3
"""Prove the Ethereum narrow Poseidon component on admitted Metal AOT and CPU.

Checks actual GPU composition dispatch, identical serialized proof bytes, and
fresh CPU verification after producer destruction. Uses the shared build lock.
The selected trace log15 reaches the existing Metal mixed-component crossover;
this is a correctness gate, not a full-leaf benchmark.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess

from zig_protocol_lib.command import test_command
from zig_serial_build import DEFAULT_LOCK, build_lock

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    arguments = parser.parse_args()
    if len(arguments.manifest_sha256) != 64 or any(
        value not in "0123456789abcdef" for value in arguments.manifest_sha256
    ):
        parser.error("--manifest-sha256 requires 64 lowercase hexadecimal characters")
    environment = os.environ.copy()
    environment["STWO_ETHEREUM_NARROW_AOT_BUNDLE"] = str(arguments.bundle.resolve())
    environment["STWO_ETHEREUM_NARROW_AOT_MANIFEST_SHA256"] = arguments.manifest_sha256
    command = test_command(
        "src/tests/riscv/ethereum_narrow_metal_proof_test.zig",
        "-O", "ReleaseSafe", "-fstrip",
        "--test-filter", "Ethereum narrow Metal authenticated AOT",
        "-lc", "-framework", "Foundation", "-framework", "Metal", "-lobjc",
    )
    # Zig attaches C sources to the next -M module, so place this before root.
    position = next(i for i, value in enumerate(command) if value.startswith("-Mroot="))
    command[position:position] = [
        "-cflags", "-fobjc-arc", "-fblocks", "--", "src/backends/metal/runtime.m",
    ]
    with build_lock(DEFAULT_LOCK, label="ethereum-narrow-metal-proof"):
        return subprocess.run(command, cwd=ROOT, env=environment, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
