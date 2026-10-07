#!/usr/bin/env python3
"""Record native-verified generic, SHA shift v3, and fused v4 Bitcoin proofs.

Run the ReleaseFast production executable. Each profile proves the same three
valid headers in rotating order, with warm fixed commitments and canonical PoW.
"""

from __future__ import annotations

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess


HERE = S31_SOURCE_ROOT
PROFILES = ("generic", "shift_v3", "fused_v4")
WITNESSES = ("genesis", "height_1", "height_2")
TIMINGS = (
    "prove_ns", "nonpow_ns", "interaction_pow_ns", "fri_pow_ns", "verify_ns",
    "composition_eval_ns", "quotient_commit_ns",
)


def fields(line: str) -> dict[str, str]:
    return dict(part.split("=", 1) for part in line.split()[1:] if "=" in part)


def typed(row: dict[str, str]) -> dict[str, int | str]:
    return {key: int(value) if value.isdecimal() else value for key, value in row.items()}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def spread(values: list[int]) -> dict[str, float | int]:
    ordered = sorted(values)
    lower = ordered[: len(ordered) // 2] or ordered[:1]
    upper = ordered[(len(ordered) + 1) // 2 :] or ordered[-1:]
    return {
        "n": len(ordered),
        "median": statistics.median(ordered),
        "min": ordered[0],
        "max": ordered[-1],
        "q1": statistics.median(lower),
        "q3": statistics.median(upper),
    }


def summarize(rows: list[dict[str, int | str]]) -> dict[str, object]:
    return {
        **{key: spread([int(row[key]) for row in rows]) for key in TIMINGS},
        "proof_bytes": spread([int(row["proof_bytes"]) for row in rows]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="compiled ReleaseFast production executable")
    parser.add_argument("--rounds", type=int, default=3, help="rotations over all three headers, 1..9")
    parser.add_argument("--out", type=Path, required=True, help="JSON measurement output")
    args = parser.parse_args()
    if not 1 <= args.rounds <= 9:
        parser.error("--rounds must be 1..9")
    binary = args.binary.resolve(strict=True)
    env = dict(os.environ, S31_BITCOIN_MULTI_WITNESS_ROUNDS=str(args.rounds))
    completed = subprocess.run([str(binary)], cwd=HERE.parents[2], env=env, capture_output=True, text=True)
    output = completed.stdout + completed.stderr
    if completed.returncode:
        raise SystemExit(output)

    setup: dict[str, int | str] | None = None
    witnesses: dict[str, dict[str, int | str]] = {}
    samples: list[dict[str, int | str]] = []
    for line in output.splitlines():
        marker = line.find("S31_MULTI_")
        if marker >= 0:
            line = line[marker:]
        if line.startswith("S31_MULTI_SETUP "):
            setup = typed(fields(line))
        elif line.startswith("S31_MULTI_WITNESS "):
            row = typed(fields(line))
            name = str(row.pop("name"))
            if name in witnesses:
                raise ValueError(f"duplicate witness {name}")
            witnesses[name] = row
        elif line.startswith("S31_MULTI_SAMPLE "):
            samples.append(typed(fields(line)))
    if setup is None or setup.get("execution_mode") != "production":
        raise ValueError("ReleaseFast production executable required; Zig test mode disables the global work pool and forces one PoW worker")
    if setup.get("rounds") != args.rounds or setup.get("samples_per_profile") != 3 * args.rounds:
        raise ValueError("benchmark setup disagrees with requested rounds")
    if set(witnesses) != set(WITNESSES):
        raise ValueError(f"expected {WITNESSES}, got {tuple(witnesses)}")
    if len({row["header_sha256d_display"] for row in witnesses.values()}) != 3:
        raise ValueError("all three headers must have distinct SHA256d hashes")
    if len(samples) != len(PROFILES) * len(WITNESSES) * args.rounds:
        raise ValueError(f"expected {len(PROFILES) * len(WITNESSES) * args.rounds} samples, got {len(samples)}")
    for profile in PROFILES:
        for witness in WITNESSES:
            pair = [row for row in samples if row.get("profile") == profile and row.get("witness") == witness]
            if len(pair) != args.rounds or {row["round"] for row in pair} != set(range(args.rounds)):
                raise ValueError(f"missing or duplicate rounds for {profile}/{witness}")
            if len({row["proof_sha256"] for row in pair}) != 1:
                raise ValueError(f"canonical PoW/proof bytes changed for {profile}/{witness}")
            for row in pair:
                if row["prove_ns"] != row["nonpow_ns"] + row["interaction_pow_ns"] + row["fri_pow_ns"]:
                    raise ValueError(f"timing decomposition failed for {profile}/{witness}")

    summary = {
        profile: summarize([row for row in samples if row["profile"] == profile])
        for profile in PROFILES
    }
    per_witness = {
        witness: {
            profile: summarize([row for row in samples if row["profile"] == profile and row["witness"] == witness])
            for profile in PROFILES
        }
        for witness in WITNESSES
    }
    median_nonpow = {name: summary[name]["nonpow_ns"]["median"] for name in PROFILES}
    comparisons = (
        ("generic", "shift_v3"), ("generic", "fused_v4"), ("shift_v3", "fused_v4"),
    )
    comparison = {
        f"{earlier}_over_{later}_nonpow": {
            "per_witness": {
                witness: per_witness[witness][earlier]["nonpow_ns"]["median"]
                / per_witness[witness][later]["nonpow_ns"]["median"]
                for witness in WITNESSES
            },
            "median_of_witness_ratios": statistics.median(
                per_witness[witness][earlier]["nonpow_ns"]["median"]
                / per_witness[witness][later]["nonpow_ns"]["median"]
                for witness in WITNESSES
            ),
            "pooled_sample_median_ratio": median_nonpow[earlier] / median_nonpow[later],
        }
        for earlier, later in comparisons
    }
    fixtures = {
        "genesis": HERE / "examples/bitcoin/bitcoin_header_pow.valid.json",
        "height_1": HERE / "examples/bitcoin/bitcoin_header_link.valid.json",
        "height_2": HERE / "examples/bitcoin/bitcoin_block2_header.valid.json",
    }
    record = {
        "schema": "s31-bitcoin-multi-witness-generic-v3-v4-v1",
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "host": platform.platform(),
        "python": platform.python_version(),
        "binary": str(binary),
        "binary_sha256": sha256(binary),
        "execution_mode": "production",
        "source_sha256": sha256(HERE / "examples/bitcoin/bitcoin_header_pow.s31.json"),
        "fixture_sha256": {name: sha256(path) for name, path in fixtures.items()},
        "proof_parameters": {
            "fri_pow_bits": setup["fri_pow_bits"],
            "fri_queries": setup["fri_queries"],
            "fri_log_blowup_factor": setup["fri_log_blowup_factor"],
            "fri_fold_step": setup["fri_fold_step"],
            "fri_log_last_layer_degree_bound": setup["fri_log_last_layer_degree_bound"],
            "fri_last_layer_degree_bound": setup["fri_last_layer_degree_bound"],
            "interaction_pow_bits": setup["interaction_pow_bits"],
        },
        "setup": setup,
        "witnesses": witnesses,
        "samples": samples,
        "summary": summary,
        "per_witness": per_witness,
        "comparison": comparison,
        "timing_policy": "Same in-process GPA; warm fixed commitments and keys built before timer; 3 profiles rotate per witness and round. Prove excludes serialization and native verification. Interaction and FRI PoW timers are subtracted separately; total prove includes both. Native verification times are reported separately. Repeated rounds on a fixed witness are timing repetitions of one deterministic transcript, not independent PoW nonce draws; ratio headline uses medians per distinct witness.",
        "scope": "Three valid historical mainnet headers at heights 0, 1, 2. The source and public Poseidon root relation are identical across profiles; private header and digest are not ZK because current trace openings are unmasked. Results do not establish throughput or recursion performance.",
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"summary": summary, "comparison": comparison}, indent=2))
    print(f"Saved {args.out}")


if __name__ == "__main__":
    main()
