"""Check full-message framing and compile the exact RV32 compression ABI."""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from zig_serial_build import build_lock

crate = ROOT / "autoresearch/benchmarks/guest_runtime/sha256_precompile_tests"
target = ROOT / "autoresearch/benchmarks/guest_runtime/ethereum/riscv32i-stwo.json"
with build_lock(label="sha256-guest-qualification"):
    subprocess.run(["cargo", "test", "--offline", "--release", "-j", "2"], cwd=crate, check=True)
    env = os.environ.copy()
    env["RUSTFLAGS"] = "--cfg stwo_sha256_precompile_v1"
    subprocess.run([
        "cargo", "+nightly-2026-08-08", "rustc", "--locked", "--offline", "--release", "-j", "2",
        "--target", str(target), "-Z", "json-target-spec", "-Z", "build-std=core",
        "-Z", "build-std-features=compiler-builtins-mem", "--", "--emit=asm",
    ], cwd=crate, env=env, check=True)
    emitted = list((crate / "target/riscv32i-stwo/release").rglob("stwo_sha256_precompile_guest_tests-*.s"))
    if len(emitted) != 1:
        raise RuntimeError(f"Expected one current assembly artifact, got {len(emitted)}")
    assembly = emitted[0].read_text()
    words = [int(match, 0) for match in re.findall(r"\.word\s+(0x[0-9a-fA-F]+|[0-9]+)", assembly)]
    instruction = 0x0C00000B | (5 << 15) | (6 << 20)
    if instruction not in words or "stwo_sha256_guest_hash:" not in assembly:
        raise RuntimeError("Native SHA ABI was not emitted")
    (HERE / "sha-guest-qualification.json").write_text(json.dumps({
        "host_framing_tests_passed": True,
        "native_rv32_abi_compiled": True,
        "instruction": hex(instruction),
        "static_instruction_sites": words.count(instruction),
        "assembly_sha256": hashlib.sha256(emitted[0].read_bytes()).hexdigest(),
        "assembly": str(emitted[0].relative_to(ROOT)),
        "production_profile_active": False,
        "guest_execution_or_proof_qualified": False,
    }, indent=2) + "\n")
