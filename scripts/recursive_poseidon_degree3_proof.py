#!/usr/bin/env python3
"""Check the compact recursive Poseidon AIR with complete proofs.

The default CPU gate includes semantic/negative tests and fresh verification of
serialized universal and retained narrow proofs. --metal additionally requires
an explicitly pinned core-v2 AOT bundle; it compares exact CPU/Metal proof bytes
and freshly verifies the Metal artifact after producer destruction. The compact
provider's composition currently uses the shared host evaluator.
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
    parser.add_argument("--metal", action="store_true")
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--manifest-sha256")
    args = parser.parse_args()
    if args.metal and (args.bundle is None or args.manifest_sha256 is None):
        parser.error("--metal requires --bundle and --manifest-sha256")
    if not args.metal and (args.bundle is not None or args.manifest_sha256 is not None):
        parser.error("AOT arguments require --metal")
    environment = os.environ.copy()
    if args.metal:
        if len(args.manifest_sha256) != 64 or any(c not in "0123456789abcdef" for c in args.manifest_sha256):
            parser.error("--manifest-sha256 requires 64 lowercase hexadecimal characters")
        environment["STWO_RECURSIVE_POSEIDON_AOT_BUNDLE"] = str(args.bundle.resolve())
        environment["STWO_RECURSIVE_POSEIDON_AOT_MANIFEST_SHA256"] = args.manifest_sha256
        command = test_command(
            "src/tests/riscv/recursion_poseidon_degree3_metal_test.zig",
            "-O", "ReleaseSafe", "-fstrip",
            "--test-filter", "recursive universal degree3 Metal",
            "-lc", "-framework", "Foundation", "-framework", "Metal", "-lobjc",
        )
        position = next(i for i, value in enumerate(command) if value.startswith("-Mroot="))
        command[position:position] = ["-cflags", "-fobjc-arc", "-fblocks", "--", "src/backends/metal/runtime.m"]
    else:
        command = test_command(
            "src/tests/riscv/recursion_poseidon_degree3_test_root.zig",
            "-O", "ReleaseSafe", "-fstrip", "--test-filter", "degree3",
        )
    with build_lock(DEFAULT_LOCK, label="recursive-poseidon-degree3-proof"):
        if not args.metal:
            # Zig does not collect tests from a named dependency module. Run
            # the backend-neutral semantic root explicitly before full proofs.
            semantic = test_command(
                "src/frontends/riscv/recursion_poseidon_degree3_test_root.zig",
                "-O", "ReleaseSafe", "-fstrip", "--test-filter", "degree3",
            )
            result = subprocess.run(semantic, cwd=ROOT, env=environment, check=False)
            if result.returncode:
                return result.returncode
        return subprocess.run(command, cwd=ROOT, env=environment, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
