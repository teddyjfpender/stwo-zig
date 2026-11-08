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
from scripts.riscv64_csp_compare import elf_info

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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
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
    for name, values, point, expected in cases():
        output = (expected.to_bytes(32, "big") + b"BEV1" + bytes(5) + b"BP").hex()
        for mode, algorithm in ((0, "fraction"), (1, "adaptive")):
            prefix = artifacts / f"{name}-{algorithm}"
            payload = (
                b"BEV1"
                + bytes([mode])
                + point.to_bytes(32, "big")
                + b"".join(value.to_bytes(32, "big") for value in values)
            )
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
                "max_steps": 100_000_000,
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
                "schema": "stwo.opstack.blob-evaluation-probe.v1",
                "scope": "isolated actual RV64 blob evaluation, not OP validity or full transition performance",
                "elf_sha256": config["elf_sha256"],
                "records": records,
                "oracle": "independent Python polynomial and single-support Lagrange evaluations; native Arkworks and RV64 both agree",
            }
            (artifacts / "receipt.json").write_text(json.dumps(report, indent=2) + "\n")
            print(name, algorithm, execution["instructions"], flush=True)


if __name__ == "__main__":
    main()
