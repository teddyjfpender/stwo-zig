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
from opstack.source_identity import compile_sources, require_unchanged
from scripts.rv64.riscv64_csp_compare import elf_info

TOOLCHAIN = "nightly-2026-08-08"
VARIANTS = {
    "mantle-software": None,
    "mantle-services": "crypto-services",
    "software": None,
    "brotli-probe": "brotli-probe",
    "brotli-lazy": "brotli-probe,lazy-brotli",
    "brotli-lazy-bulk": "brotli-probe,lazy-brotli,memory-service",
    "keccak": "keccak-service",
    "services": "services-v3",
    "sponge": "sponge-service",
    "transition": "transition-program,services-v3",
    "transition-sha": "transition-program,services-v3,sha-service",
    "blob-eval-canonical-fr": "blob-eval-probe,services-v3,montgomery-services,canonical-fr",
    "transition-sha-canonical-fr": "transition-program,services-v3,sha-service,montgomery-services,canonical-fr",
    "blob-eval-probe": "blob-eval-probe",
    "blob-eval-services": "blob-eval-probe,services-v3,montgomery-services",
    "transition-montgomery": "transition-program,services-v3,montgomery-services",
    "transition-sha-montgomery": "transition-program,services-v3,sha-service,montgomery-services",
}

LEAN_VARIANTS = {
    "lean": ("release", []),
    "frontier": ("frontier", []),
    "memory": ("frontier", ["memory-service"]),
    "sha": ("frontier", ["sha-service"]),
    "memory-sha": ("frontier", ["memory-service", "sha-service"]),
    "arithmetic": ("frontier", ["sha-service", "arithmetic-service"]),
    "bn254": (
        "frontier",
        ["memory-service", "sha-service", "arithmetic-service", "bn254-service"],
    ),
    "full": ("frontier", ["memory-service", "sha-service", "arithmetic-service"]),
    "precompiles": (
        "frontier",
        ["memory-service", "sha-service", "arithmetic-service", "precompile-services"],
    ),
    "pairing": (
        "frontier",
        ["memory-service", "sha-service", "arithmetic-service", "pairing-cache"],
    ),
    "pairing-bn254": (
        "frontier",
        [
            "memory-service",
            "sha-service",
            "arithmetic-service",
            "pairing-cache",
            "bn254-service",
        ],
    ),
    "optimized": (
        "frontier",
        [
            "memory-service",
            "sha-service",
            "arithmetic-service",
            "pairing-cache",
            "jumpdest-service",
        ],
    ),
}

LEAN_VARIANTS["canonical"] = (
    "frontier",
    [*LEAN_VARIANTS["optimized"][1], "bn254-canonical"],
)

LEAN_VARIANTS["canonical-glv"] = (
    "frontier",
    [*LEAN_VARIANTS["canonical"][1], "bn254-glv"],
)

LEAN_VARIANTS["canonical-glv-hinted"] = (
    "frontier",
    [*LEAN_VARIANTS["canonical-glv"][1], "pairing-hints"],
)

LEAN_VARIANTS["canonical-glv-hinted-inline"] = (
    "frontier",
    [*LEAN_VARIANTS["canonical-glv-hinted"][1], "extension-inline"],
)

# Prototype only: the VM and proof receiver separately admit the new OP tag.
LEAN_VARIANTS["canonical-glv-hinted-sparse"] = (
    "frontier",
    [*LEAN_VARIANTS["canonical-glv-hinted-inline"][1], "pairing-sparse-service"],
)

LEAN_VARIANTS["canonical-glv-hinted-sparse-dense"] = (
    "frontier",
    [*LEAN_VARIANTS["canonical-glv-hinted-sparse"][1], "pairing-dense-service"],
)
LEAN_VARIANTS["dense-probe-control"] = ("frontier", [*LEAN_VARIANTS["canonical-glv-hinted-sparse"][1], "pairing-dense-probe"])
LEAN_VARIANTS["dense-probe-candidate"] = ("frontier", [*LEAN_VARIANTS["canonical-glv-hinted-sparse"][1], "pairing-dense-probe", "pairing-dense-service"])

def execution_requirements(features):
    """Bind the guest's selected services, including diagnostic build aliases."""
    selected = set(",".join(features).split(","))
    if "crypto-services" in selected:
        return {"required_execution_profile": "ethereum_services_v3",
                "op_service_abi": None, "extra_service_tags": [0x0003_0010, 0x0003_0130]}
    sparse = bool(selected & {"pairing-sparse-service", "pairing-packet-batching", "pairing-dense-service", "pairing-dense-probe"})
    return {
        "required_execution_profile": "ethereum_services_op_v1" if sparse else None,
        "op_service_abi": "bn254-miller-line-640/v1" if sparse else None,
        "extra_service_tags": [0x0004_0001] if sparse else [],
    }


BULK_DEFAULTS = {"COPY": 16, "UCOPY": 16, "SET": 16, "CMP": 8}


def bulk_environment(environment, minimum=None):
    """A reproducible compiler environment; ambient thresholds never leak in."""
    if (
        minimum is not None
        and minimum != "off"
        and (not minimum.isdecimal() or not 8 <= int(minimum) <= 1 << 20)
    ):
        raise ValueError("bulk minimum must be off or 8..1048576 bytes")
    thresholds = {
        name: str(value) if minimum is None else minimum
        for name, value in BULK_DEFAULTS.items()
    }
    clean = {
        key: value
        for key, value in environment.items()
        if not key.startswith("STWO_ADMITTED_")
    }
    clean.update(
        {"STWO_ADMITTED_" + name + "_MIN": value for name, value in thresholds.items()}
    )
    return clean, thresholds


def identity(path):
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument(
        "--variant",
        choices=(*VARIANTS, *LEAN_VARIANTS),
        default="software",
    )
    parser.add_argument("--eager", action="store_true")
    parser.add_argument("--allocator-check", action="store_true")
    parser.add_argument(
        "--guest-opt-level",
        choices=("2", "3", "s", "z"),
        default="3",
        help="explicit guest LLVM optimization policy; native reference stays unchanged",
    )
    parser.add_argument(
        "--bulk-min",
        help="explicit shared copy/set/compare threshold: 8..1048576 or off",
    )
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--native-reference",type=Path,help="explicit trusted native reference binary; reuse/hash instead of rebuilding it")
    parser.add_argument("--runner-reference",type=Path,help="explicit trusted RV64 execution runner; reuse/hash instead of recompiling it")
    args = parser.parse_args()
    if args.variant.startswith("mantle-") and (args.eager or args.allocator_check or args.bulk_min is not None):
        parser.error("Mantle does not select OP guest features or bulk-service thresholds")
    if (args.variant.startswith("transition") or args.variant.startswith("blob-eval")) and args.eager:
        parser.error("the transition program authenticates preimages on demand")
    if not 1 <= args.jobs <= 8:
        parser.error("jobs 1..8")
    try:
        compiler_env, bulk_thresholds = bulk_environment(os.environ, args.bulk_min)
    except ValueError as error:
        parser.error(str(error))
    for reference in(args.native_reference,args.runner_reference):
        if reference is not None and(not reference.is_file()or reference.stat().st_size==0):parser.error("reference binary missing")
    args.artifacts.mkdir(parents=True, exist_ok=False)
    artifacts = args.artifacts.resolve()
    mantle = args.variant.startswith("mantle-")
    crate_name = "opstack/mantle" if mantle else "opstack/kona"
    crate = ROOT / crate_name
    env = dict(
        compiler_env,
        CARGO_TARGET_DIR=str(crate / "target"),
        RUSTFLAGS="-C passes=lower-atomic -C opt-level=" + args.guest_opt_level,
    )
    source_snapshot = compile_sources(ROOT, crate_name)
    source_head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    tracked_diff_sha256 = hashlib.sha256(
        subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=ROOT)
    ).hexdigest()
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

        if args.native_reference is None:
            # Same compiler revision, independent native execution backend.
            host_env = dict(
                compiler_env, CARGO_TARGET_DIR=str(crate / "target"), RUSTFLAGS=""
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
                    "host,pairing-dense-probe"
                    if args.variant.startswith("dense-probe-")
                    else "host,pairing-hints"
                    if args.variant.startswith("canonical-glv-hinted")
                    else "host,brotli-probe"
                    if args.variant.startswith("brotli-")
                    else "host,blob-eval-probe"
                    if args.variant.startswith("blob-eval")
                    else "host,transition-program"
                    if args.variant.startswith("transition")
                    else "host",
                    "-j",
                    args.jobs,
                ],
                host_env,
            )
        lean = args.variant in LEAN_VARIANTS
        manifest = crate / ("lean/Cargo.toml" if lean else "Cargo.toml")
        profile, lean_features = LEAN_VARIANTS.get(args.variant, ("release", []))
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
            ROOT / "opstack/kona/guest/riscv64i-stwo.json",
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
            command += ["-p", "stwo-mantle-rv64-guest" if mantle else "stwo-kona-rv64-guest"]
        if mantle:
            command += ["--no-default-features"]
        features = (
            list(lean_features)
            if lean
            else ([VARIANTS[args.variant]] if VARIANTS.get(args.variant) else [])
        )
        if args.eager:
            features.append("eager-preimages")
        if args.allocator_check:
            features.append("allocator-check")
        if features:
            command += ["--features", ",".join(features)]
        run(command)
    executable = "stwo-mantle-rv64-guest" if mantle else "stwo-kona-rv64-lean" if lean else "stwo-kona-rv64-guest"
    guest = artifacts / "guest.elf"
    host = artifacts / "host"
    shutil.copy2(crate / f"target/riscv64i-stwo/{profile}/{executable}", guest)
    shutil.copy2(args.native_reference.resolve()if args.native_reference else crate / ("target/release/stwo-mantle-native" if mantle else "target/release/stwo-kona-host"), host)
    zig = (
        [shutil.which("zig")]
        if shutil.which("zig")
        else [sys.executable, "-m", "ziglang"]
    )
    runner = artifacts / "rv64-execution"
    zig_version = subprocess.check_output([*zig, "version"], text=True).strip()
    if zig_version != "0.15.2":
        raise ValueError("requires Zig 0.15.2; found " + zig_version)
    runner_cache = crate / "target/stwo-rv64-execution"
    zig_command = [
        *zig,
        "build-exe",
        "src/frontends/riscv/rv64/ethereum_execution.zig",
        "-O",
        "ReleaseFast",
        "-femit-bin=" + str(runner_cache),
    ]
    commands.append(zig_command)
    if args.runner_reference is None:
        subprocess.run(zig_command, cwd=ROOT, check=True, timeout=600)
        shutil.copy2(runner_cache, runner)
    else:
        commands.pop()
        shutil.copy2(args.runner_reference.resolve(),runner)
    require_unchanged(source_snapshot, compile_sources(ROOT, crate_name))
    _, symbols, segments = elf_info(guest)
    sources = {
        str(p.relative_to(ROOT)): identity(p)
        for p in (ROOT / "opstack").rglob("*")
        if p.is_file() and "target" not in p.parts and "__pycache__" not in p.parts
    }
    report = {
        "schema": "stwo.mantle.build.v1" if mantle else "stwo.opstack.build.v1",
        "variant": args.variant,
        **execution_requirements(features),
        "guest_opt_level": args.guest_opt_level,
        "bulk_threshold_bytes": bulk_thresholds,
        "eager": args.eager,
        "allocator_check": args.allocator_check,
        "commands": commands,
        "source_head": source_head,
        "tracked_diff_sha256": tracked_diff_sha256,
        "compile_sources": source_snapshot,
        "compile_sources_unchanged": True,
        "executable_load_bytes": sum(
            len(data) for _, _, data, flags in segments if flags & 1
        ),
        "kona_commit": "305d78b348748e47bd0fe2d4d95bb29ddb10f9ba" if mantle else "a271fd6b3feb76e49f3453e5a27be4b33a3c7211",
        "external_native_reference": identity(args.native_reference.resolve()) if args.native_reference else None,
        "external_runner_reference": identity(args.runner_reference.resolve()) if args.runner_reference else None,
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
