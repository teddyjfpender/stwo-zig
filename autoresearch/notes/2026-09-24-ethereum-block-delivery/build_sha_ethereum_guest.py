"""Build the default SHA-capable Ethereum guest without replacing old evidence."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from zig_serial_build import build_lock

crate = ROOT / "autoresearch/benchmarks/guest_runtime/ethereum"
framing = crate.parent / "sha256_precompile_tests"
parser = argparse.ArgumentParser()
parser.add_argument("--output", type=Path, default=HERE / "ethereum-block-sha-default.elf")
args = parser.parse_args()
output = args.output.resolve()
with build_lock(label="ethereum-sha-guest-build"):
    if output.exists():
        raise FileExistsError(output)
    subprocess.run(["cargo", "test", "--locked", "--offline", "--release", "-j", "2"], cwd=framing, check=True)
    env = os.environ.copy()
    env["RUSTFLAGS"] = "-C link-arg=-Tlinker.ld"
    subprocess.run([
        "cargo", "+nightly-2026-08-08", "build", "--locked", "--offline", "-j", "2", "--release",
        "--target", "riscv32i-stwo.json", "-Z", "json-target-spec", "-Z", "build-std=core,alloc",
        "-Z", "build-std-features=compiler-builtins-mem",
    ], cwd=crate, env=env, check=True)
    executable = crate / "target/riscv32i-stwo/release/stwo-ethereum-guest"
    elf = executable.read_bytes()
    if elf[:6] != b"\x7fELF\x01\x01":
        raise ValueError("expected little-endian ELF32")
    section_offset = struct.unpack_from("<I", elf, 32)[0]
    section_size, section_count = struct.unpack_from("<HH", elf, 46)
    notes = []
    for index in range(section_count):
        section = section_offset + index * section_size
        if struct.unpack_from("<I", elf, section + 4)[0] != 7:
            continue
        start, size = struct.unpack_from("<II", elf, section + 16)
        at = start
        while at < start + size:
            name_size, desc_size, kind = struct.unpack_from("<III", elf, at)
            at += 12
            name = elf[at:at + name_size]
            at += (name_size + 3) & ~3
            desc = elf[at:at + desc_size]
            at += (desc_size + 3) & ~3
            if name == b"STWO\0" and kind == 1:
                notes.append(desc)
    semantic_digest = hashlib.sha256(b"riscv.ethereum.keccakf_1600.secp256k1_recover.sha256_compress.v1").digest()
    expected_note = b"STWZKVM\0" + struct.pack("<HHQHH", 1, 4, 14, 1, 0) + semantic_digest
    if notes != [expected_note]:
        raise ValueError("compiled guest capability note differs from the admitted SHA profile")
    shutil.copy2(executable, output)
    files = [*crate.glob("src/*.rs"), crate / "Cargo.toml", crate / "Cargo.lock",
             crate / "riscv32i-stwo.json", crate / "linker.ld", crate.parent / "sha256_precompile_v1.rs", crate.parent / "ethereum_admission_v1.rs", output]
    (output.with_suffix(".build.json")).write_text(json.dumps({
        "elf": str(output.relative_to(ROOT)),
        "expected_profile": "rv32im-zkvm-ethereum-sha-v1",
        "sha256_precompile_default": True,
        "compiled_capability_note_validated": True,
        "host_framing_tests_passed": True,
        "guest_execution_qualified": False,
        "full_block_proof_verified": False,
        "sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files},
    }, indent=2) + "\n")
