#!/usr/bin/env python3
"""Prepare and validate the fixed QEC Cairo1 task for circuit leaf wrapping.

The official runner executes the QEC executable directly, then executes the
same task through the pinned two-cell leaf bootloader. Both CPI inputs and the
bootloader's preimage are checked before publication to `leaf-wrap`.
"""

import argparse
import hashlib
import json
import mmap
import re
import struct
import subprocess
import tempfile
import time
from pathlib import Path

import generate as qec


CAIRO_PRIME = (1 << 251) + 17 * (1 << 192) + 1
BOOTLOADER_SHA256 = "5e2befae48dcdea8d19dc655e40ac236285d049d12573bfb341bec9ce39182f5"


class CompactInput:
    def __init__(self, data: mmap.mmap):
        self.data = data
        self.pos = 0
        if self.take(8) != b"STWZCPI\0":
            raise ValueError("not a compact Cairo input")
        if self.u32() != 1 or self.u32() != 0:
            raise ValueError("unsupported compact Cairo input version/flags")
        self.initial_pc, self.initial_ap, self.initial_fp = self.unpack("<III")
        self.final_pc, self.final_ap, self.final_fp = self.unpack("<III")
        self.pc_count = self.u64()
        self.public_segment_mask, reserved = self.unpack("<HH")
        if reserved or self.u32() or self.u32() != 20 or self.u32():
            raise ValueError("invalid compact Cairo input header")
        for _ in range(20):
            n = self.u64()
            self.take(n * 12)
        self.small_max = int.from_bytes(self.take(16), "little")
        self.small_capacity_log = self.u32()
        if self.u32():
            raise ValueError("nonzero compact input reserved word")
        self.n_address, self.n_large, self.n_small = self.unpack("<QQQ")
        self.ids_start = self.pos
        self.take(self.n_address * 4)
        self.large_start = self.pos
        self.take(self.n_large * 32)
        self.small_start = self.pos
        self.take(self.n_small * 16)
        n_public = self.u64()
        self.take(n_public * 4)
        self.segments = []
        for _ in range(9):
            present = self.take(1)[0]
            if present not in (0, 1) or self.take(7) != bytes(7):
                raise ValueError("invalid builtin segment header")
            begin, stop = self.unpack("<QQ")
            self.segments.append((bool(present), begin, stop))
        if self.pos != len(self.data):
            raise ValueError("trailing compact input data")

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError("truncated compact input")
        start = self.pos
        self.pos += n
        return self.data[start:self.pos]

    def unpack(self, fmt: str) -> tuple[int, ...]:
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))

    def u32(self) -> int:
        return self.unpack("<I")[0]

    def u64(self) -> int:
        return self.unpack("<Q")[0]

    def memory_value(self, address: int) -> int:
        if address >= self.n_address:
            raise ValueError(f"missing Cairo memory address {address}")
        raw_id = struct.unpack_from("<I", self.data, self.ids_start + address * 4)[0]
        if raw_id == 0xFFFFFFFF:
            raise ValueError(f"empty Cairo memory address {address}")
        tag, index = raw_id >> 30, raw_id & ((1 << 30) - 1)
        if tag == 0 and index < self.n_small:
            return int.from_bytes(self.data[self.small_start + index * 16:
                                            self.small_start + (index + 1) * 16], "little")
        if tag == 1 and index < self.n_large:
            return int.from_bytes(self.data[self.large_start + index * 32:
                                            self.large_start + (index + 1) * 32], "little")
        raise ValueError(f"invalid Cairo memory id at {address}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(4 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def blake_felt_bytes(values: list[int]) -> bytes:
    """Pinned StarkWare Blake2Felt252 u32 packing, before Blake2s-256."""
    encoded = bytearray()
    for value in values:
        if not 0 <= value < CAIRO_PRIME:
            raise ValueError("noncanonical Blake2Felt252 input")
        if value < 1 << 63:
            encoded.extend((value >> 32).to_bytes(4, "little"))
            encoded.extend((value & 0xffffffff).to_bytes(4, "little"))
        else:
            words = [int.from_bytes(value.to_bytes(32, "big")[i:i + 4], "big")
                     for i in range(0, 32, 4)]
            words[0] |= 1 << 31
            for word in words:
                encoded.extend(word.to_bytes(4, "little"))
    return bytes(encoded)


def executable_program_hash(artifact: dict, felts: list[int]) -> int:
    """`compute_program_hash_chain`'s Blake variant for the Bootloader entrypoint."""
    entrypoints = [entry for entry in artifact["entrypoints"]
                   if entry["kind"] == "Bootloader"]
    if len(entrypoints) != 1:
        raise ValueError("expected one Cairo1 Bootloader entrypoint")
    entrypoint = entrypoints[0]
    builtins = entrypoint["builtins"]
    if not isinstance(builtins, list) or any(not isinstance(name, str) or len(name) > 31
                                             for name in builtins):
        raise ValueError("invalid Cairo1 builtin list")
    header = [0, entrypoint["offset"], len(builtins)]
    builtin_felts = [int.from_bytes(name.encode("ascii"), "big") for name in builtins]
    digest = hashlib.blake2s(blake_felt_bytes(header + builtin_felts + felts)).digest()
    return int.from_bytes(digest, "little") % CAIRO_PRIME


def validate_bootloader_commitment(preimage: list[int], output: list[int],
                                   expected_program_hash: int,
                                   expected_qec_output: list[int]) -> None:
    if len(preimage) != 3 or preimage != [expected_program_hash, *expected_qec_output]:
        raise ValueError("bootloader preimage does not bind program and QEC output")
    digest = hashlib.blake2s(blake_felt_bytes(preimage)).digest()
    expected_output = [int.from_bytes(digest[i:i + 16], "little") for i in (0, 16)]
    if output != expected_output:
        raise ValueError("bootloader output is not the Blake2s preimage commitment")


def check_program_and_output(cpi: CompactInput, felts: list[int], output: list[int]) -> None:
    if cpi.initial_ap < 2 or cpi.initial_ap - 2 - cpi.initial_pc != len(felts):
        raise ValueError("adapted program range differs from compiled bytecode")
    for i, value in enumerate(felts):
        if cpi.memory_value(cpi.initial_pc + i) != value:
            raise ValueError(f"adapted program differs at bytecode cell {i}")
    present, begin, stop = cpi.segments[2]
    if not present or stop - begin != 2:
        raise ValueError("adapted execution does not have exactly two output cells")
    if [cpi.memory_value(begin + i) for i in range(2)] != output:
        raise ValueError("adapted output differs from expected commitment")


def check_and_publish(executable: Path, arguments: Path, statement: Path,
                      adapter: Path, bootloader: Path, out_dir: Path) -> None:
    bridge_started = time.perf_counter()
    out_dir.mkdir(parents=True, exist_ok=True)
    cpi_path = out_dir / "leaf.cpi"
    program_path = out_dir / "leaf-program.json"
    input_path = out_dir / "leaf-bootloader-input.json"
    preimage_path = out_dir / "leaf-preimage.json"
    receipt_path = out_dir / "bridge-receipt.json"
    for path in (cpi_path, program_path, input_path, preimage_path, receipt_path):
        if path.exists():
            raise ValueError(f"output already exists: {path}")
    if sha256_file(bootloader) != BOOTLOADER_SHA256:
        raise ValueError("circuit leaf bootloader changed")
    artifact = json.loads(executable.read_text())
    bytecode = artifact["program"]["bytecode"]
    if not isinstance(bytecode, list) or not bytecode:
        raise ValueError("Cairo executable has no bytecode")
    felts = []
    for item in bytecode:
        if not isinstance(item, str) or re.fullmatch(r"-?0x[0-9a-fA-F]+", item) is None:
            raise ValueError("nonhex Cairo executable bytecode")
        value = int(item, 16)
        if not -CAIRO_PRIME < value < CAIRO_PRIME:
            raise ValueError("noncanonical Cairo executable bytecode")
        value %= CAIRO_PRIME
        felts.append(value)
    expected = json.loads(statement.read_text())
    if expected.get("schema") != "qec-iadd256-fixed-leaf-v1":
        raise ValueError("wrong QEC leaf statement schema")
    raw = qec.FIXTURE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != qec.FIXTURE_SHA256 or \
            expected.get("fixture_sha256") != qec.FIXTURE_SHA256:
        raise ValueError("QEC fixture hash differs from pinned KMX")
    total_shots, batch, repetitions = (expected.get(key) for key in
                                       ("total_shots", "batch", "repetitions"))
    if any(type(value) is not int for value in (total_shots, batch, repetitions)):
        raise ValueError("QEC leaf geometry must be integer-valued")
    gates = qec.gates_from_fixture(raw)
    inputs, outputs = qec.inputs_and_expected(raw, gates, total_shots, batch,
                                               repetitions)
    digest = qec.leaf_digest(raw, total_shots, batch, repetitions, inputs, outputs)
    if expected.get("digest_sha256") != digest.hex():
        raise ValueError("QEC digest differs from independent fixture calculation")
    source = qec.render_source(gates, inputs, outputs, repetitions, digest)
    project = executable.resolve().parents[2]
    if (project / "src/lib.cairo").read_text() != source or \
            (project / "Scarb.toml").read_text() != qec.MANIFEST:
        raise ValueError("QEC executable project differs from pinned generated source")
    if [int(value, 16) for value in json.loads(arguments.read_text())] != \
            [512, *inputs, repetitions]:
        raise ValueError("QEC arguments differ from pinned SHAKE batch")
    # Recompile the exact regenerated source in a fresh project so an arbitrary
    # executable JSON cannot be substituted under the correct source path.
    source_compile_started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="qec-compile-", dir=out_dir) as temp:
        fresh = Path(temp)
        (fresh / "src").mkdir()
        (fresh / "src/lib.cairo").write_text(source)
        (fresh / "Scarb.toml").write_text(qec.MANIFEST)
        version = subprocess.run(["scarb", "--version"], capture_output=True,
                                 text=True, check=True).stdout
        if not version.startswith("scarb 2.18.0 "):
            raise ValueError("QEC executable requires Scarb 2.18.0")
        subprocess.run(["scarb", "build"], cwd=fresh, check=True,
                       stdout=subprocess.DEVNULL)
        reference = fresh / "target/dev/qec_iadd256.executable.json"
        if sha256_file(reference) != sha256_file(executable):
            raise ValueError("QEC executable differs from fresh pinned-source compile")
    source_compile_seconds = time.perf_counter() - source_compile_started
    output = [int(value, 16) for value in expected["output_cells_le_u128"]]
    if len(output) != 2 or any(value >= 1 << 128 or value < 0 for value in output):
        raise ValueError("leaf statement must have two u128 output cells")
    if output != [int.from_bytes(digest[i:i + 16], "little") for i in (0, 16)]:
        raise ValueError("QEC output cells differ from independently computed digest")

    # The direct execution establishes the exact QEC bytecode and two-cell
    # output before the bootloader adds its own circuit-friendly commitment.
    with tempfile.TemporaryDirectory(prefix="qec-direct-", dir=out_dir) as temp:
        direct_path = Path(temp) / "direct.cpi"
        direct_started = time.perf_counter()
        subprocess.run([str(adapter), "run", "--program", str(executable.resolve()),
                        "--program-type", "executable", "--arguments", str(arguments.resolve()),
                        "--input-format", "compact", "--prover-input-out", str(direct_path)],
                       check=True)
        direct_adapter_seconds = time.perf_counter() - direct_started
        with direct_path.open("rb") as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            check_program_and_output(CompactInput(mapped), felts, output)
        direct_sha256 = sha256_file(direct_path)

    bootloader_input = {
        "tasks": [{"type": "Cairo1Executable", "path": str(executable.resolve()),
                   "user_args_file": str(arguments.resolve()), "program_hash_function": "blake"}],
        "fact_topologies_path": None, "single_page": True,
        "output_preimage_dump_path": str(preimage_path.resolve()),
    }
    input_path.write_text(json.dumps(bootloader_input, indent=2, sort_keys=True) + "\n")
    bootloader_started = time.perf_counter()
    subprocess.run([str(adapter), "run", "--program", str(bootloader.resolve()),
                    "--program-type", "leaf-bootloader", "--arguments", str(input_path.resolve()),
                    "--input-format", "compact", "--prover-input-out", str(cpi_path)],
                   check=True)
    bootloader_adapter_seconds = time.perf_counter() - bootloader_started
    try:
        bootloader_program = json.loads(bootloader.read_text())
        bootloader_felts = [int(value, 16) % CAIRO_PRIME for value in bootloader_program["data"]]
        preimage = [int(value, 16) for value in json.loads(preimage_path.read_text())]
        expected_program_hash = executable_program_hash(artifact, felts)
        with cpi_path.open("rb") as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            cpi = CompactInput(mapped)
            if cpi.public_segment_mask != (1 << 11) - 1:
                raise ValueError("leaf circuit requires all eleven public segments")
            present, begin, stop = cpi.segments[2]
            if not present or stop - begin != 2:
                raise ValueError("leaf bootloader did not publish two output cells")
            bootloader_output = [cpi.memory_value(begin + i) for i in range(2)]
            if any(value >= 1 << 128 for value in bootloader_output):
                raise ValueError("leaf bootloader output does not fit in two u128 cells")
            check_program_and_output(cpi, bootloader_felts, bootloader_output)
            validate_bootloader_commitment(preimage, bootloader_output,
                                           expected_program_hash, output)
    except Exception:
        cpi_path.unlink(missing_ok=True)
        raise

    program_path.write_bytes(bootloader.read_bytes())
    bridge_seconds = time.perf_counter() - bridge_started
    receipt_path.write_text(json.dumps({
        "schema": "qec-cairo1-bootloader-leaf-bridge-v1",
        "executable_sha256": sha256_file(executable),
        "arguments_sha256": sha256_file(arguments),
        "direct_cpi_sha256": direct_sha256,
        "adapted_cpi_sha256": sha256_file(cpi_path),
        "leaf_program_sha256": sha256_file(program_path),
        "qec_program_cells": len(felts),
        "leaf_program_cells": len(bootloader_felts),
        "output_cells_le_u128": [hex(value) for value in output],
        "bootloader_output_cells_le_u128": [hex(value) for value in bootloader_output],
        "bootloader_program_hash_felt": hex(expected_program_hash),
        "leaf_digest_sha256": expected["digest_sha256"],
        "direct_adapter_seconds": direct_adapter_seconds,
        "bootloader_adapter_seconds": bootloader_adapter_seconds,
        "bridge_seconds": bridge_seconds,
        "source_compile_seconds": source_compile_seconds,
    }, indent=2, sort_keys=True) + "\n")
    print(receipt_path.read_text(), end="")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--arguments", type=Path, required=True)
    parser.add_argument("--statement", type=Path, required=True)
    parser.add_argument("--adapter", type=Path, required=True)
    parser.add_argument("--bootloader", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    check_and_publish(args.executable, args.arguments, args.statement,
                      args.adapter, args.bootloader, args.out)


if __name__ == "__main__":
    main()
