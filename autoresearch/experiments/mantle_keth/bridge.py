#!/usr/bin/env python3
"""Experimental Keth Cairo PIE -> existing Stwo Zig product bridge.

This is developer orchestration, outside all released package closures.
A Cairo proof is never promoted to a Mantle/Kona validity claim here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PINS = json.loads((HERE / "pins.json").read_text())


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def write_new(path: Path, value: dict) -> None:
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def git(checkout: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(checkout), *args], text=True
    ).strip()


def authenticate(checkout: Path, pin: dict) -> dict:
    revision = git(checkout, "rev-parse", "HEAD")
    if revision != pin["revision"]:
        raise ValueError(f"source revision mismatch: {checkout}: {revision}")
    # Build outputs may be ignored by upstream; tracked changes and untracked
    # source files must not silently modify the program or its dependencies.
    if git(checkout, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError(f"source checkout is dirty: {checkout}")
    return {"repository": pin["repository"], "revision": revision,
            "git_tree": git(checkout, "rev-parse", "HEAD^{tree}")}


def claims() -> dict:
    return {
        "mantle_validity_proof": False,
        "kona_derivation_proved": False,
        "ethereum_block_statement_bound": False,
        "l1_verifier_compatible": False,
    }


def audit(keth: Path, op_succinct: Path) -> dict:
    identities = {
        "keth": authenticate(keth, PINS["keth"]),
        "mantle_op_succinct": authenticate(op_succinct, PINS["mantle_op_succinct"]),
    }
    cargo = (keth / "Cargo.toml").read_text()
    lock = (op_succinct / "Cargo.lock").read_text()
    if PINS["keth"]["stwo_cairo_revision"] not in cargo:
        raise ValueError("Keth Stwo-Cairo pin is absent")
    for key in ("kona_revision", "revm_revision"):
        if PINS["mantle_op_succinct"][key] not in lock:
            raise ValueError(f"Mantle lockfile is missing {key}")
    return {
        "schema": "stwo-zig-keth-source-audit-v1",
        "sources": identities,
        "transport": "cairo-pie-via-official-simple-bootloader",
        "raw_keth_prover_input_admitted": False,
        "claims": claims(),
        "blockers": [
            "Keth Prague execution is not Mantle/OP execution",
            "Kona L1 derivation and blob validation are not implemented in Cairo",
            "Keth main output does not expose the Mantle BootInfoStruct journal",
            "Segment output aggregation needs proof-authenticated composition",
            "Ethereum settlement needs a Stwo verifier or proof wrapper",
        ],
    }


def validate_zkpi(data_dir: Path, block: int) -> Path:
    if block < PINS["keth"]["minimum_block"]:
        raise ValueError("the pinned Keth program only supports Prague blocks")
    path = data_dir / "1" / str(block) / "zkpi.json"
    data = json.loads(path.read_text())
    # Do not infer OP support from Keth's generic --chain-id CLI option.
    if type(data["chainConfig"]["chainId"]) is not int or data["chainConfig"]["chainId"] != 1:
        raise ValueError("only Ethereum chain ID 1 is admitted; Mantle is unsupported")
    return path


def trace(args: argparse.Namespace) -> dict:
    source = authenticate(args.keth_checkout, PINS["keth"])
    zkpi = validate_zkpi(args.data_dir, args.block)
    compiled = args.keth_checkout / "build/main_compiled.json"
    if not compiled.is_file():
        raise ValueError("compile the pinned Keth programs first: uv run --frozen compile_keth")
    # Refuse reuse; the upstream CLI otherwise allows mutable run directories.
    args.out.mkdir(parents=True, exist_ok=False)
    inputs = {"zkpi_sha256": digest(zkpi), "compiled_program_sha256": digest(compiled)}
    command = [args.uv, "run", "--frozen", "keth", "trace", "-b", str(args.block),
               "--chain-id", "1", "--data-dir", str(args.data_dir.resolve()),
               "--proving-run-id", "stwo-zig-bridge", "--step", "main", "--cairo-pie",
               "--trace-path", str((args.out / "trace").resolve())]
    with (args.out / "trace.log").open("xb") as log:
        subprocess.run(command, cwd=args.keth_checkout, stdout=log,
                       stderr=subprocess.STDOUT, check=True)
    pie = args.out / "trace" / f"cairo_pie_{args.block}.zip"
    if not pie.is_file():
        raise ValueError("Keth did not emit the expected Cairo PIE; see trace.log")
    if inputs != {"zkpi_sha256": digest(zkpi), "compiled_program_sha256": digest(compiled)}:
        raise ValueError("Keth inputs changed during tracing")
    if authenticate(args.keth_checkout, PINS["keth"]) != source:
        raise ValueError("Keth source changed during tracing")
    result = {"schema": "stwo-zig-keth-trace-v1", "source": source,
              "chain_id": 1, "block_number": args.block, "step": "main",
              "inputs": inputs, "pie_sha256": digest(pie), "claims": claims()}
    write_new(args.out / "trace-receipt.json", result)
    return result


def prove(args: argparse.Namespace) -> dict:
    # Reuse the canonical benchmark's PCS policy, exact-byte proof receipt checks,
    # Zig self-verification and independent official Rust verification.
    sys.path.insert(0, str(ROOT))
    from scripts.benchmark_cairo import run_benchmark

    for path in (args.pie, args.product, args.oracle):
        if not path.is_file():
            raise ValueError(f"not a regular file: {path}")
    args.out.mkdir(parents=True, exist_ok=False)
    benchmark = run_benchmark(argparse.Namespace(
        product=args.product.resolve(), oracle=args.oracle.resolve(),
        program=args.pie.resolve(), program_type="pie", prover_input=None,
        arguments=None, params=None, trials=args.trials, out=args.out / "benchmark",
    ))
    # The exact PIE is replayed by the pinned bootloader and covered by the
    # product execution receipt. No application-level statement is inferred.
    result = {"schema": "stwo-zig-keth-pie-proof-v1", "scope": "cairo-pie-transport",
              "pie_sha256": digest(args.pie), "cairo_proof_verified": True,
              "application_program_provenance": "not-established-by-this-command",
              "claims": claims(), "benchmark": benchmark}
    write_new(args.out / "receipt.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    source = commands.add_parser("audit", help="authenticate and assess the pinned upstream sources")
    source.add_argument("--keth-checkout", type=Path, required=True)
    source.add_argument("--op-succinct-checkout", type=Path, required=True)
    source.add_argument("--out", type=Path, required=True)
    generate = commands.add_parser("trace", help="generate a main-step Ethereum Keth PIE")
    generate.add_argument("--keth-checkout", type=Path, required=True)
    generate.add_argument("--data-dir", type=Path, required=True)
    generate.add_argument("--block", type=int, required=True)
    generate.add_argument("--uv", default="uv")
    generate.add_argument("--out", type=Path, required=True)
    proof = commands.add_parser("prove", help="prove a PIE with the released CPU or Metal product")
    proof.add_argument("--pie", type=Path, required=True)
    proof.add_argument("--product", type=Path, required=True)
    proof.add_argument("--oracle", type=Path, required=True)
    proof.add_argument("--trials", type=int, default=1)
    proof.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "prove" and not 1 <= args.trials <= 100:
        parser.error("--trials must be between 1 and 100")
    try:
        if args.command == "audit":
            result = audit(args.keth_checkout, args.op_succinct_checkout)
            write_new(args.out, result)
        elif args.command == "trace":
            result = trace(args)
        else:
            result = prove(args)
        print(json.dumps({"schema": result["schema"], "claims": result["claims"]}))
    except (ValueError, OSError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"keth bridge: {error}\n")


if __name__ == "__main__":
    main()
