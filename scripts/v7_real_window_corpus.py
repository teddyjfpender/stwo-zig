#!/usr/bin/env python3
"""Import retained Ethereum sources, capture, prove and verify explicit windows.

This command never reports a window replay as an Ethereum proof. The current
terminal-only v7 verifier cannot admit an arbitrary unfinished prefix; a window
capsule is explicit benchmark input for a separate original partial-leaf proof,
not an accepted complete-union input or proof of the skipped Ethereum prefix.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PINS = {
    "guest.elf": ("ef68fdca9e627a4969e64aa97119f52f2d9c9d6b6e8d5cbbeb541fb93dab0688", 32 << 20),
    "input.bin": ("737368031bfec21aa2bd557a3a71d2cbf253ec730199f7ec4c3bccd628df8e82", 4 << 20),
    "expected-output.bin": ("730396807814bc71f14405b3ecf27237778a5359732001b32c93692c3275a8c5", 43),
}
EVIDENCE = "autoresearch/notes/2026-09-24-ethereum-block-delivery/exact-schedule-geometry-v1/qualification.json"
# The historical row is selection evidence, not an assertion about how many
# calls occur inside this smaller window. Capture emits the observed census.
CASES = {
    "startup": {"skip_cycles": 0, "cycles": 32768, "historical_segment": 0},
    "native-region": {"skip_cycles": 1, "cycles": 32768, "historical_segment": 0},
    "recovery-region": {"skip_cycles": 24718000, "cycles": 32768, "historical_segment": 50},
    "keccak-dense-region": {"skip_cycles": 42700000, "cycles": 32768, "historical_segment": 93},
}


def checked_bytes(path: Path, name: str) -> bytes:
    expected, maximum = PINS[name]
    with path.open("rb") as source:
        data = source.read(maximum + 1)
    if len(data) > maximum or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"{name}: retained source hash/size mismatch")
    if name == "expected-output.bin" and len(data) != 43:
        raise ValueError("expected-output.bin: invalid terminal length")
    return data


def import_artifacts(destination: Path, sources: dict[str, Path]) -> None:
    # Validate before publishing; copy the exact checked bytes, not a second
    # read of possibly replaced source paths. No partially admitted directory.
    payloads = {name: checked_bytes(sources[name], name) for name in PINS}
    if destination.exists():
        raise ValueError("destination already exists; refusing to overwrite")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".v7-corpus-", dir=destination.parent) as temporary:
        stage = Path(temporary) / "bundle"
        stage.mkdir()
        for name, payload in payloads.items():
            (stage / name).write_bytes(payload)
        manifest = {
            "schema": "stwo-v7-retained-ethereum-corpus-v1",
            "block_number": 24628607,
            "execution_profile": "rv32im_zkvm_ethereum_sha_v1",
            "historical_cycles": 139214856,
            "historical_evidence": EVIDENCE,
            "artifacts": {name: {"sha256": PINS[name][0], "bytes": len(data)} for name, data in payloads.items()},
            "cases": CASES,
            "scope": "source import only; no new execution or proof measurement",
        }
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        stage.rename(destination)


def validate_bundle(bundle: Path) -> None:
    for name in PINS:
        checked_bytes(bundle / name, name)


def recover(destination: Path) -> None:
    """Reproduce retained bytes; never substitute a merely similar guest."""
    from zig_serial_build import build_lock
    if destination.exists():
        raise ValueError("destination already exists; refusing to overwrite")
    build_manifest = ROOT / "autoresearch/notes/2026-09-24-ethereum-block-delivery/ethereum-block-sha-default-v3.build.json"
    for name, expected in json.loads(build_manifest.read_text())["sha256"].items():
        if name.endswith(".elf"):
            continue
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"historical build source differs: {name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".v7-recovery-", dir=destination.parent) as temporary:
        stage = Path(temporary).resolve()
        url = "https://raw.githubusercontent.com/0xPolygonHermez/zisk-eth-client/0887d43621931faba8cdf8da70402091bbe620ff/bin/guests/stateless-validator-reth/inputs/mainnet_24628607_66_7_zec_reth.bin"
        with urllib.request.urlopen(url, timeout=60) as response:
            transport = response.read((3 << 20) + 1)
        if len(transport) != 2718960 or hashlib.sha256(transport).hexdigest() != "e1c6d4e06a87649da68e461a91465e4123b990f531e68581ee1750599ff12376":
            raise ValueError("upstream historical transport mismatch")
        source = stage / "transport.bin"
        source.write_bytes(transport)
        guest = ROOT / "autoresearch/benchmarks/guest_runtime/ethereum"
        executable = guest / "target/riscv32i-stwo/release/stwo-ethereum-guest"
        # Compile only if the exact retained artifact is not already cached.
        cached = executable.is_file() and hashlib.sha256(executable.read_bytes()).hexdigest() == PINS["guest.elf"][0]
        with build_lock(label="v7-real-window-recovery"):
            if not cached:
                env = os.environ.copy()
                env["RUSTFLAGS"] = "-C link-arg=-Tlinker.ld"
                with (stage / "guest-build.log").open("wb") as log:
                    subprocess.run([
                        "cargo", "+nightly-2026-08-08", "build", "--locked", "-j", "2", "--release",
                        "--target", "riscv32i-stwo.json", "-Z", "json-target-spec", "-Z", "build-std=core,alloc",
                        "-Z", "build-std-features=compiler-builtins-mem",
                    ], cwd=guest, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
            checked_bytes(executable, "guest.elf")
            with (stage / "projection.log").open("wb") as log:
                subprocess.run([
                    "cargo", "+nightly-2026-08-08", "run", "--locked", "-j", "2",
                    "--manifest-path", "autoresearch/benchmarks/guest_runtime/projection/Cargo.toml", "--",
                    str(source), str(stage / "projected"),
                ], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
        # All twelve historical hints were successful. The guest still checks
        # their semantics; this regeneration is accepted only by exact hash.
        input_bytes = (stage / "projected/stwo-runner-input.bin").read_bytes()
        input_bytes += b"STWECR01" + (12).to_bytes(4, "little") + bytes.fromhex("ff0f")
        (stage / "input.bin").write_bytes(input_bytes)
        output = bytes.fromhex("e63d2797ca5c6f826a32d20c41ba552d25777533ab295f9d232560b014d09030")
        output += b"\x01" + (1).to_bytes(8, "little") + (5121).to_bytes(2, "little")
        (stage / "expected-output.bin").write_bytes(output)
        import_artifacts(destination, {"guest.elf": executable, "input.bin": stage / "input.bin", "expected-output.bin": stage / "expected-output.bin"})
        for name in ("guest-build.log", "projection.log"):
            if (stage / name).exists():
                (destination / name).write_bytes((stage / name).read_bytes())


def capture(bundle: Path, destination: Path, case: str, binary: Path | None) -> int:
    validate_bundle(bundle)
    if destination.exists():
        raise ValueError("capture directory already exists; refusing to overwrite")
    destination.mkdir(parents=True)
    env = os.environ.copy()
    env.update({
        "STWO_REAL_WINDOW_ELF": str((bundle / "guest.elf").resolve()),
        "STWO_REAL_WINDOW_INPUT": str((bundle / "input.bin").resolve()),
        "STWO_REAL_WINDOW_OUTPUT_DIR": str(destination.resolve()),
        "STWO_REAL_WINDOW_SKIP": str(CASES[case]["skip_cycles"]),
        "STWO_REAL_WINDOW_CYCLES": str(CASES[case]["cycles"]),
    })
    # Zig's standalone test runner has no runtime --test-filter option. A
    # prebuilt binary executes its compiled tests plus the opt-in capture.
    command = [str(binary.resolve())] if binary else [
        "python3", "scripts/zig_protocol_test.py",
        "src/frontends/riscv/block_v7_real_window_capture_test_root.zig",
        "-OReleaseSafe", "-fstrip", "--test-filter", "capture pinned retained",
    ]
    # Compilation/prefix replay are deliberately reported separately by Zig;
    # none of these host diagnostics are labelled proving time.
    with (destination / "capture.log").open("wb") as log:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=False)
    if result.returncode == 0 and not (destination / "capture.json").is_file():
        raise RuntimeError("capture command returned success without its capsule")
    return result.returncode


def prove(bundle: Path, destination: Path, case: str, binary: Path | None) -> int:
    if CASES[case]["skip_cycles"] == 0:
        raise ValueError("the explicit nonterminal proof does not admit the first-window I/O projection")
    validate_bundle(bundle)
    if destination.exists():
        raise ValueError("proof directory already exists; refusing to overwrite")
    destination.mkdir(parents=True)
    env = os.environ.copy()
    env.update({
        "STWO_REAL_WINDOW_PROOF_ELF": str((bundle / "guest.elf").resolve()),
        "STWO_REAL_WINDOW_PROOF_INPUT": str((bundle / "input.bin").resolve()),
        "STWO_REAL_WINDOW_PROOF_OUTPUT": str(destination.resolve()),
        "STWO_REAL_WINDOW_SKIP": str(CASES[case]["skip_cycles"]),
        "STWO_REAL_WINDOW_CYCLES": str(CASES[case]["cycles"]),
    })
    command = [str(binary.resolve())] if binary else [
        "python3", "scripts/zig_protocol_test.py",
        "src/frontends/riscv/block_v7_real_window_proof_test_root.zig",
        "-OReleaseSafe", "-fstrip", "--test-filter", "explicit nonterminal window original proof",
    ]
    with (destination / "qualification.log").open("wb") as log:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=False)
    if result.returncode == 0:
        for name in ("report.json", "window.proof", "window.admission"):
            if not (destination / name).is_file():
                raise RuntimeError(f"proof command returned success without {name}")
        print(json.dumps({"report_sha256": hashlib.sha256((destination / "report.json").read_bytes()).hexdigest()}))
    return result.returncode


def snapshot_bytes(directory: Path, name: str) -> bytes:
    maximum = 148 + 8 * 8_000_000
    raw = directory / name
    source = raw if raw.is_file() else directory / (name + ".gz")
    opener = gzip.open if source.suffix == ".gz" else open
    with opener(source, "rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("snapshot exceeds bounded decoder size")
    return data


def verify(bundle: Path, proof_directory: Path, snapshot_directory: Path, expected_report: str, binary: Path | None) -> int:
    validate_bundle(bundle)
    with (proof_directory / "report.json").open("rb") as source:
        report = source.read((1 << 20) + 1)
    if len(expected_report) != 64 or len(report) > 1 << 20 or hashlib.sha256(report).hexdigest() != expected_report:
        raise ValueError("report does not match independently selected benchmark admission")
    # Only bounded temporary raw snapshots are materialized. The Zig verifier
    # checks exact layout, complete state identities and all original proofs.
    with tempfile.TemporaryDirectory(prefix="v7-window-reload-") as temporary:
        stage = Path(temporary)
        for name in ("incoming.b7win", "outgoing.b7win"):
            (stage / name).write_bytes(snapshot_bytes(snapshot_directory, name))
        env = os.environ.copy()
        env.update({
            "STWO_REAL_WINDOW_RELOAD_DIRECTORY": str(proof_directory.resolve()),
            "STWO_REAL_WINDOW_EXPECTED_REPORT_SHA256": expected_report,
            "STWO_REAL_WINDOW_RELOAD_ELF": str((bundle / "guest.elf").resolve()),
            "STWO_REAL_WINDOW_RELOAD_INCOMING": str(stage / "incoming.b7win"),
            "STWO_REAL_WINDOW_RELOAD_OUTGOING": str(stage / "outgoing.b7win"),
        })
        command = [str(binary.resolve())] if binary else [
            "python3", "scripts/zig_protocol_test.py",
            "src/frontends/riscv/block_v7_real_window_reload_test_root.zig",
            "-OReleaseSafe", "-fstrip", "--test-filter", "fresh process reload verifies externally admitted",
        ]
        return subprocess.run(command, cwd=ROOT, env=env, check=False).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    status = commands.add_parser("status")
    status.add_argument("bundle", type=Path)
    recovery = commands.add_parser("recover", help="rebuild exact ELF and public fixture using pinned sources")
    recovery.add_argument("destination", type=Path)
    imp = commands.add_parser("import")
    imp.add_argument("destination", type=Path)
    imp.add_argument("--elf", type=Path, required=True)
    imp.add_argument("--input", type=Path, required=True)
    imp.add_argument("--expected-output", type=Path, required=True)
    run = commands.add_parser("capture")
    run.add_argument("bundle", type=Path)
    run.add_argument("destination", type=Path)
    run.add_argument("--case", choices=CASES, required=True)
    run.add_argument("--binary", type=Path)
    proof = commands.add_parser("prove", help="prove a selected nonterminal machine transition; prefix replay is unproved preparation")
    proof.add_argument("bundle", type=Path)
    proof.add_argument("destination", type=Path)
    proof.add_argument("--case", choices=("native-region", "recovery-region", "keccak-dense-region"), required=True)
    proof.add_argument("--binary", type=Path)
    reload = commands.add_parser("verify", help="fresh verifier using externally selected benchmark admission")
    reload.add_argument("bundle", type=Path)
    reload.add_argument("proof_directory", type=Path)
    reload.add_argument("--snapshot-directory", type=Path, required=True)
    reload.add_argument("--expected-report-sha256", required=True)
    reload.add_argument("--binary", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "recover":
            recover(args.destination)
        elif args.command == "import":
            import_artifacts(args.destination, {"guest.elf": args.elf, "input.bin": args.input, "expected-output.bin": args.expected_output})
        elif args.command == "status":
            records = {}
            for name in PINS:
                try:
                    checked_bytes(args.bundle / name, name)
                    records[name] = "verified"
                except (OSError, ValueError) as error:
                    records[name] = str(error)
            print(json.dumps({"artifacts": records, "ready": all(v == "verified" for v in records.values())}, indent=2))
            return 0 if all(v == "verified" for v in records.values()) else 1
        elif args.command == "capture":
            return capture(args.bundle, args.destination, args.case, args.binary)
        elif args.command == "prove":
            return prove(args.bundle, args.destination, args.case, args.binary)
        elif args.command == "verify":
            return verify(args.bundle, args.proof_directory, args.snapshot_directory, args.expected_report_sha256, args.binary)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(2, f"error: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
