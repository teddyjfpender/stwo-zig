#!/usr/bin/env python3
"""Build a pinned Kona host and RV64 guest, retaining source/binary identities."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.riscv64_csp_compare import elf_info

TOOLCHAIN = "nightly-2026-08-08"
VARIANTS = {
    "software": None,
    "keccak": "keccak-service",
    "services": "services-v3",
    "sponge": "sponge-service",
}


def identity(path):
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument(
        "--variant",
        choices=(*VARIANTS, "lean", "frontier", "memory"),
        default="software",
    )
    parser.add_argument("--eager", action="store_true")
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 8:
        parser.error("jobs 1..8")
    args.artifacts.mkdir(parents=True, exist_ok=True)
    artifacts = args.artifacts.resolve()
    crate = ROOT / "opstack/kona"
    env = dict(
        os.environ,
        CARGO_TARGET_DIR=str(crate / "target"),
        RUSTFLAGS="-C passes=lower-atomic",
    )
    commands = []
    with (artifacts / "build.log").open("w") as log:

        def run(command, custom_env=env):
            commands.append([str(x) for x in command])
            subprocess.run(
                commands[-1],
                cwd=ROOT,
                env=custom_env,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
                timeout=1200,
            )

        # Same compiler revision, independent native execution backend.
        host_env = dict(
            os.environ, CARGO_TARGET_DIR=str(crate / "target"), RUSTFLAGS=""
        )
        run(
            [
                "cargo",
                "+" + TOOLCHAIN,
                "build",
                "--manifest-path",
                crate / "Cargo.toml",
                "--locked",
                "--release",
                "--features",
                "host",
                "-j",
                args.jobs,
            ],
            host_env,
        )
        lean = args.variant in ("lean", "frontier", "memory")
        manifest = crate / ("lean/Cargo.toml" if lean else "Cargo.toml")
        profile = "frontier" if args.variant in ("frontier", "memory") else "release"
        command = [
            "cargo",
            "+" + TOOLCHAIN,
            "build",
            "--manifest-path",
            manifest,
            "--locked",
            "--profile",
            profile,
            "--target",
            crate / "guest/riscv64i-stwo.json",
            "-Z",
            "json-target-spec",
            "-Z",
            "build-std=core,alloc",
            "-Z",
            "build-std-features=compiler-builtins-mem",
            "-j",
            args.jobs,
        ]
        if not lean:
            command += ["-p", "stwo-kona-rv64-guest"]
        features = (
            []
            if lean or VARIANTS.get(args.variant) is None
            else [VARIANTS[args.variant]]
        )
        if args.variant == "memory":
            features.append("memory-service")
        if args.eager:
            features.append("eager-preimages")
        if features:
            command += ["--features", ",".join(features)]
        run(command)
    executable = "stwo-kona-rv64-lean" if lean else "stwo-kona-rv64-guest"
    guest = artifacts / "guest.elf"
    host = artifacts / "host"
    shutil.copy2(crate / f"target/riscv64i-stwo/{profile}/{executable}", guest)
    shutil.copy2(crate / "target/release/stwo-kona-host", host)
    zig = (
        [shutil.which("zig")]
        if shutil.which("zig")
        else [sys.executable, "-m", "ziglang"]
    )
    runner = artifacts / "rv64-execution"
    zig_version = subprocess.check_output([*zig, "version"], text=True).strip()
    if zig_version != "0.15.2":
        raise ValueError("requires Zig 0.15.2; found " + zig_version)
    subprocess.run(
        [
            *zig,
            "build-exe",
            "src/frontends/riscv/rv64/ethereum_execution.zig",
            "-O",
            "ReleaseFast",
            "-femit-bin=" + str(runner),
        ],
        cwd=ROOT,
        check=True,
        timeout=600,
    )
    _, symbols, _ = elf_info(guest)
    sources = {
        str(p.relative_to(ROOT)): identity(p)
        for p in (ROOT / "opstack").rglob("*")
        if p.is_file() and "target" not in p.parts and "__pycache__" not in p.parts
    }
    report = {
        "schema": "stwo.opstack.build.v1",
        "variant": args.variant,
        "eager": args.eager,
        "commands": commands,
        "source_head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "tracked_diff_sha256": hashlib.sha256(
            subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=ROOT)
        ).hexdigest(),
        "kona_commit": "a271fd6b3feb76e49f3453e5a27be4b33a3c7211",
        "cargo_lock_sha256": identity(manifest.parent / "Cargo.lock")["sha256"],
        "guest_rustflags": env["RUSTFLAGS"],
        "zig_version": zig_version,
        "compiler": subprocess.check_output(
            ["rustc", "+" + TOOLCHAIN, "--version"], text=True
        ).strip(),
        "guest": identity(guest),
        "host": identity(host),
        "runner": identity(runner),
        "sources": sources,
        "symbols": symbols,
        "proof_verified": False,
        "snark_wrap": False,
    }
    (artifacts / "build.json").write_text(json.dumps(report, indent=2) + "\n")
    print(guest)


if __name__ == "__main__":
    main()
