#!/usr/bin/env python3
"""One verified peak-resident-memory sample per matched arithmetic profile."""

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import argparse

import benchmark_v1
import s31


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, nargs="+", default=[256, 32768])
    args = parser.parse_args()
    fingerprint = s31.compiler_fingerprint()
    work = s31.ROOT / "zig-out" / "s31" / "benchmark-direct-v4" / fingerprint[:16]
    result = []
    for rounds in args.rounds:
        valid = work / f"step{rounds}.trial-0.valid.json"
        statement = work / f"step{rounds}.trial-0.statement.json"
        for profile in ("sparse-gate", "sparse-chip", "direct-gate", "direct-chip"):
            package = work / f"{rounds}-{profile}" / "package"
            s31.verify_package(package)
            prover = package / "bin" / f"s31-step{rounds}-prover"
            verifier = package / "bin" / f"s31-step{rounds}-native-verifier"
            proof = work / f"{rounds}-{profile}" / "memory.proof"
            usage = benchmark_v1.measured(str(prover), "prove", str(valid), str(proof))
            s31.invoke(str(verifier), str(proof), str(statement), str(package / "verification-key.json"))
            item = {
                "rounds": rounds,
                "profile": profile,
                "max_resident_bytes": usage["max_resident_bytes"],
                "prover_process_wall_s": usage["wall_seconds"],
                "proof_bytes": proof.stat().st_size,
                "proof_sha256": s31.file_hash(proof),
            }
            result.append(item)
            print(f"{rounds} {profile}: {item['max_resident_bytes'] / (1 << 20):.1f} MiB", flush=True)
    record = {
        "schema": "s31-direct-memory-v4",
        "compiler_sha256": fingerprint,
        "method": "os.wait4 ru_maxrss; bytes on macOS, KiB converted to bytes on Linux; one verified sample per case",
        "cases": result,
    }
    output = s31.ROOT / "design" / "s31" / "measurements" / "direct-memory-v4-2026-10-06.json"
    s31.write_json(output, record)
    print(output)


if __name__ == "__main__":
    main()
