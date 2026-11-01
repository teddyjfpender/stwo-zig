#!/usr/bin/env python3
"""Run the guest's focused suites without changing vendored workspace membership."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
GUEST = ROOT / "autoresearch/benchmarks/guest_runtime/ethereum/rv64"
TOOLCHAIN = "nightly-2026-08-08"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="external test cache")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    if out.is_relative_to(ROOT):
        parser.error("--out must be outside the repository")
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CARGO_TARGET_DIR=str(out / "target"))
    suites = {}
    # Cargo cannot test a transitive vendored package as a workspace member.
    # These copies use the exact reviewed sources and pinned test-only locks.
    for name in ("revm-bytecode", "revm-interpreter", "zeth-mpt"):
        src = GUEST / "vendor" / name
        dst = out / "crates" / name
        shutil.copytree(src / "src", dst / "src", dirs_exist_ok=True)
        manifest = (src / "Cargo.toml").read_text() + "\n[workspace]\n"
        if name == "revm-interpreter":
            manifest = manifest.replace('[dependencies.bytecode]\n',
                                        '[dependencies.bytecode]\npath = "../revm-bytecode"\n')
        (dst / "Cargo.toml").write_text(manifest)
        shutil.copyfile(HERE / "validation-locks" / (name + ".lock"), dst / "Cargo.lock")
        suites[name] = (["cargo", "+" + TOOLCHAIN, "test", "--locked", "--manifest-path",
                         str(dst / "Cargo.toml"), "--lib"], src)
    for name, directory in (("mem", GUEST / "mem"), ("sha256", GUEST / "vendor/sha2-rv64")):
        suites[name] = (["cargo", "+" + TOOLCHAIN, "test", "--locked", "--release", "--manifest-path",
                         str(directory / "Cargo.toml")], directory)
    result = {"schema": "stwo.rv64.guest-efficiency-unit-validation.v1", "suites": {}}
    for name, (command, source) in suites.items():
        if args.offline:
            command.append("--offline")
        log = out / (name + ".log")
        with log.open("w") as stream:
            proc = subprocess.run(command, cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT)
        # Bind the result to every source file, including integration tests.
        source_files = sorted((source / "src").rglob("*.rs"))
        hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files}
        result["suites"][name] = {"ok": proc.returncode == 0, "returncode": proc.returncode,
                                  "command": command, "source_sha256": hashes,
                                  "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()}
        print(("PASS " if proc.returncode == 0 else "FAIL ") + name, flush=True)
    result["ok"] = all(s["ok"] for s in result["suites"].values())
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    if not result["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
