#!/usr/bin/env python3
"""Compare OP blob interpolation in the actual RV64 guest; never an OP proof.

Build with `opstack/build.py --variant blob-eval-probe --artifacts BUILD`,
then run this tool with --build BUILD --artifacts RESULTS. All results must
match independent Python field arithmetic before instruction counts are used.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from opstack.cpu import measured
from scripts.rv64.riscv64_csp_compare import elf_info

MODULUS = int("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
N = 4096
OMEGA = pow(7, (MODULUS - 1) // N, MODULUS)
assert pow(OMEGA, N, MODULUS) == 1
assert pow(OMEGA, N // 2, MODULUS) == MODULUS - 1


def polynomial(x):
    return (3 + 7 * x + 11 * x * x + 13 * pow(x, 7, MODULUS)) % MODULUS


def reverse12(index):
    return int(f"{index:012b}"[::-1], 2)


def barycentric(values, roots, point):
    # Independent Python batch inversion, rather than the guest's streaming
    # single fraction or its radix-2 fold. One modular inverse for all terms.
    differences = [(point - root) % MODULUS for root in roots]
    prefixes = []
    product = 1
    for difference in differences:
        prefixes.append(product)
        product = product * difference % MODULUS
    inverse = pow(product, -1, MODULUS)
    total = 0
    for root, value, difference, prefix in zip(
        reversed(roots),
        reversed(values),
        reversed(differences),
        reversed(prefixes),
    ):
        total = (total + root * value * inverse * prefix) % MODULUS
        inverse = inverse * difference % MODULUS
    return total * (pow(point, N, MODULUS) - 1) * pow(N, -1, MODULUS) % MODULUS


def cases():
    roots = [pow(OMEGA, reverse12(i), MODULUS) for i in range(N)]
    dense = [polynomial(root) for root in roots]
    sparse = [0] * N
    sparse[13] = 1234
    z = 17
    hashed = [
        int.from_bytes(hashlib.sha256(i.to_bytes(8, "big")).digest(), "big") % MODULUS
        for i in range(N)
    ]
    padded = hashed[: N // 2] + [0] * (N // 2)
    sparse_y = (
        1234
        * roots[13]
        * (pow(z, N, MODULUS) - 1)
        * pow(N * (z - roots[13]) % MODULUS, -1, MODULUS)
    ) % MODULUS
    return [
        ("dense", dense, z, polynomial(z)),
        ("dense-hash", hashed, z, barycentric(hashed, roots, z)),
        ("half-padded", padded, z, barycentric(padded, roots, z)),
        ("sparse", sparse, z, sparse_y),
        ("zero", [0] * N, z, 0),
        ("domain", dense, roots[29], dense[29]),
    ]


def encoded_cases(kzg=False):
    if not kzg:
        for name, values, point, expected in cases():
            output = (expected.to_bytes(32, "big") + b"BEV1" + bytes(5) + b"BP").hex()
            for mode, algorithm in ((0, "fraction"), (1, "adaptive")):
                payload = b"BEV1" + bytes([mode]) + point.to_bytes(32, "big") + b"".join(value.to_bytes(32, "big") for value in values)
                yield name, algorithm, payload, output
        return
    # Independent c-kzg 2.1.8 / Ethereum ceremony vectors also exercised by
    # anchored_blobs.rs. Input data are generated here, not by the guest.
    vectors = [
        (1, 3,
         "b150de850d4a7008b1b4f810add779e9e2fba3a66619413a0ee9cadbef7e56873503cdd01651529dc0e0addb8df20fab",
         "966e952d4cffa5c843d682cc60d2491c2e705280393c5ca70003d56b5eb15ed231ed23271df5ad0aa836a444ead2ca07"),
        (17, 2,
         "ac55315f6eb653492046af4a94d7237b16f2adb94ecdabecb909b7535a2833189c93d7713380e34bbcabd46e9c8932c7",
         "92ab28ca7a01eb62d4647629e7bd30412e8b0907a0b1494f1a29fae0e4284b642a46be061eb102cf9f031756f9910e9a"),
    ]
    entries = []
    for constant, exponent, commitment, proof in vectors:
        metadata = bytes.fromhex(commitment + proof)
        entries.append(metadata + b"".join((constant + i**exponent).to_bytes(32, "big") for i in range(N)))
    for count in (1, 2):
        payload = b"BKV1" + count.to_bytes(4, "little") + b"".join(entries[:count])
        metadata = b"".join(entry[:96] for entry in entries[:count])
        digest = hashlib.sha256(b"STWO/BLOB/KZG/PROBE1" + count.to_bytes(4, "little") + metadata).digest()
        output = (digest + b"BKV1" + count.to_bytes(4, "little") + b"\x00BP").hex()
        yield "kzg-single" if count == 1 else "kzg-batch", "production", payload, output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--kzg", action="store_true", help="Exercise complete one/two-blob KZG verification, including BLS12-381 arithmetic")
    parser.add_argument("--oracle", action="store_true", help="Also require independent Unicorn execution, registers, steps and service counts")
    parser.add_argument("--case",action="append",choices=("dense","dense-hash","half-padded","sparse","zero","domain","kzg-single","kzg-batch"),help="explicit bounded subset; default preserves all existing cases")
    parser.add_argument("--algorithm",choices=("fraction","adaptive","production"))
    parser.add_argument("--max-steps",type=int,help="explicit execution cap,1..100000000; default preserves prior diagnostic policy")
    args = parser.parse_args()
    if args.max_steps is not None and not 1<=args.max_steps<=100_000_000:parser.error("max-steps1..100000000")
    args.artifacts.mkdir(parents=True, exist_ok=False)
    build = args.build.resolve()
    artifacts = args.artifacts.resolve()
    elf = build / "guest.elf"
    _, elf_symbols, _ = elf_info(elf)
    names = (
        "input_start",
        "input_end",
        "halt_flag",
        "output_len",
        "output_data",
        "output_end",
        "stack_bottom",
        "stack_top",
        "heap_start",
        "heap_end",
    )
    symbols = {name: elf_symbols["__" + name] for name in names}
    records = []
    for name, algorithm, payload, output in encoded_cases(args.kzg):
        if args.case and name not in args.case:continue
        if args.algorithm and algorithm!=args.algorithm:continue
        prefix = artifacts / f"{name}-{algorithm}"
        input_path = prefix.with_suffix(".input")
        input_path.write_bytes(payload)
        native = subprocess.run(
            [str(build / "host"), "blob-eval-probe", str(input_path)],
            check=True,
            text=True,
            capture_output=True,
            timeout=args.timeout,
        ).stdout.strip()
        if native != output:
            raise ValueError(f"native/Python field mismatch: {name}/{algorithm}")
        config = {
            "elf": str(elf),
            "input": str(input_path),
            "expected_output": output,
            "elf_sha256": hashlib.sha256(elf.read_bytes()).hexdigest(),
            "input_sha256": hashlib.sha256(payload).hexdigest(),
            "max_steps": args.max_steps if args.max_steps is not None else 2_000_000_000 if args.kzg else 100_000_000,
            "engine": "fast",
            "execution_profile": "ethereum_services_v3",
            "symbols": symbols,
        }
        request = prefix.with_suffix(".config.json")
        request.write_text(json.dumps(config, indent=2) + "\n")
        resource = measured(
            [str(build / "rv64-execution"), str(request)],
            prefix,
            args.timeout,
            os.environ.copy(),
        )
        execution = json.loads(prefix.with_suffix(".stdout").read_text())
        if (
            execution["status"] != "completed"
            or not execution["verified_output"]
            or execution["output"] != output
        ):
            raise ValueError(f"RV64/Python field mismatch: {name}/{algorithm}")
        if args.oracle:
            from opstack.oracle import execute

            independent = execute(config, execution["instructions"], timeout=args.timeout, output_kind="blob-probe")
            if (independent["output"] != execution["output"]
                    or independent["final_registers"] != execution["final_registers"]
                    or independent["post_store_pc"] != execution["pc"]):
                raise ValueError("RV64/Unicorn probe mismatch")
            for key, value in independent["services"].items():
                native_key = "keccak_sponge_calls" if key == "sponge_calls" else key
                if execution[native_key] != value:
                    raise ValueError(f"RV64/Unicorn service mismatch: {key}")
            prefix.with_suffix(".oracle.json").write_text(json.dumps(independent, indent=2) + "\n")
        records.append(
            {
                "case": name,
                "algorithm": algorithm,
                "resources": resource,
                "input_sha256": config["input_sha256"],
                "expected_output": output,
                "execution": execution,
            }
        )
        report = {
            "schema": "stwo.opstack.blob-kzg-probe.v1" if args.kzg else "stwo.opstack.blob-evaluation-probe.v1",
            "scope": "isolated actual RV64 KZG verification, not OP validity or full transition performance" if args.kzg else "isolated actual RV64 blob evaluation, not OP validity or full transition performance",
            "elf_sha256": config["elf_sha256"],
            "records": records,
            "selection":{"cases":args.case,"algorithm":args.algorithm,"max_steps":args.max_steps},
            "oracle": "known c-kzg 2.1.8 blob/proof vectors; native Arkworks and RV64 agree; independent Python pins metadata framing" if args.kzg else "independent Python polynomial and single-support Lagrange evaluations; native Arkworks and RV64 both agree",
        }
        (artifacts / "receipt.json").write_text(json.dumps(report, indent=2) + "\n")
        print(name, algorithm, execution["instructions"], flush=True)
    if not records:raise ValueError("no probe cases selected")


if __name__ == "__main__":
    main()
