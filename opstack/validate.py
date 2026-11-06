#!/usr/bin/env python3
"""Offline OP checks, with explicit ownership of each vendored source delta."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "opstack/kona/vendor"


def vendors():
    for name in ("op-revm", "ark-bn254"):
        root = VENDOR / name
        pin = json.loads((root / "UPSTREAM.json").read_text())
        original = pin["upstream_files"]
        modified = set(pin["modified_files"])
        allowed = set(original) | set(pin["added_files"])
        if not modified <= set(original):
            raise ValueError(name + ": unknown modified file")
        for path, digest in original.items():
            actual = hashlib.sha256((root / path).read_bytes()).hexdigest()
            if actual != digest and path not in modified:
                raise ValueError(f"{name}: unreviewed upstream drift: {path}")
        actual = {
            str(p.relative_to(root))
            for p in root.rglob("*")
            if p.is_file() and "target" not in p.parts
        }
        if actual != allowed:
            raise ValueError(
                f"{name}: file inventory drift: added={actual - allowed}, missing={allowed - actual}"
            )
    print("vendor source ownership: passed", flush=True)


def run(command):
    print("+ " + " ".join(str(x) for x in command), flush=True)
    subprocess.run([str(x) for x in command], cwd=ROOT, check=True, timeout=1800)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--fast", action="store_true", help="Python and vendor ownership only"
    )
    args = p.parse_args()
    vendors()
    run([sys.executable, "-m", "ruff", "check", "opstack"])
    run([sys.executable, "-m", "ruff", "format", "--check", "opstack"])
    run([sys.executable, "-m", "unittest", "discover", "-s", "opstack/tests", "-v"])
    if not args.fast:
        crate = ROOT / "opstack/kona"
        run(
            [
                "cargo",
                "+stable",
                "fmt",
                "--manifest-path",
                crate / "Cargo.toml",
                "-p",
                "stwo-kona-execution",
                "-p",
                "stwo-kona-rv64-guest",
                "--check",
            ]
        )
        run(
            [
                "cargo",
                "+stable",
                "test",
                "--offline",
                "--locked",
                "--manifest-path",
                crate / "Cargo.toml",
                "--features",
                "host",
                "-j1",
            ]
        )
        run(
            [
                "cargo",
                "+stable",
                "test",
                "--offline",
                "--locked",
                "--manifest-path",
                VENDOR / "op-revm/Cargo.toml",
                "--no-default-features",
                "--features",
                "std",
                "--lib",
                "-j1",
            ]
        )
        run(
            [
                "cargo",
                "+stable",
                "test",
                "--offline",
                "--locked",
                "--release",
                "--manifest-path",
                VENDOR / "ark-bn254/Cargo.toml",
                "--features",
                "stwo-montgomery-service",
                "--lib",
                "-j1",
            ]
        )


if __name__ == "__main__":
    main()
