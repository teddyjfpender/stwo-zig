#!/usr/bin/env python3
"""Run the compiled production Bitcoin generic/shift benchmark executable.

The executable prepares both backends once, alternates warm proof trials, then
measures one-shot fixed commitments for each backend. This runner records every
native-verified sample and its PoW-separated timings as JSON.
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
PROFILES = ("generic_warm", "sha_shift_warm", "generic_cold", "sha_shift_cold")


def fields(line: str) -> dict[str, str]:
    return dict(part.split("=", 1) for part in line.split()[1:] if "=" in part)


def integers(values: dict[str, str]) -> dict[str, int | str]:
    return {key: int(value) if value.isdecimal() else value for key, value in values.items()}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="compiled ReleaseFast production executable")
    parser.add_argument("--trials", type=int, default=5, help="alternating trial pairs, 1..9")
    parser.add_argument("--out", required=True, type=Path, help="JSON measurement output")
    args = parser.parse_args()
    if not 1 <= args.trials <= 9:
        parser.error("--trials must be 1..9")
    binary = args.binary.resolve(strict=True)
    env = dict(os.environ, S31_BITCOIN_MATCHED_TRIALS=str(args.trials))
    completed = subprocess.run([str(binary)], cwd=HERE.parents[2], env=env, capture_output=True, text=True)
    output = completed.stdout + completed.stderr
    if completed.returncode:
        raise SystemExit(output)

    samples: dict[str, list[dict[str, int | str]]] = {name: [] for name in PROFILES}
    stages: dict[str, list[dict[str, int | str]]] = {name: [] for name in PROFILES}
    setup: dict[str, int | str] | None = None
    reported_median: dict[str, int | str] | None = None
    for line in output.splitlines():
        # Zig's direct test runner may prefix the first debug print with its
        # "1/N test..." progress text on the same line.
        marker = line.find("S31_MATCHED")
        if marker >= 0:
            line = line[marker:]
        if line.startswith("S31_MATCHED_SETUP "):
            setup = integers(fields(line))
        elif line.startswith("S31_MATCHED profile="):
            row = integers(fields(line))
            profile = row.pop("profile")
            if profile not in samples:
                raise ValueError(f"unknown benchmark profile: {profile}")
            samples[profile].append(row)
        elif line.startswith("S31_MATCHED_SHIFT_STAGES "):
            row = integers(fields(line))
            profile = row.pop("profile")
            if profile not in stages:
                raise ValueError(f"unknown stage profile: {profile}")
            stages[profile].append(row)
        elif line.startswith("S31_MATCHED_MEDIAN "):
            reported_median = integers(fields(line))
    if setup is None or reported_median is None:
        raise ValueError(f"benchmark output lacks setup or median: {output[:1000]!r}")
    if setup.get("execution_mode") != "production":
        raise ValueError("production comparison requires zig build-exe; Zig test mode disables the global work pool and forces one PoW worker")
    for name in PROFILES:
        if len(samples[name]) != args.trials:
            raise ValueError(f"{name}: expected {args.trials} native-verified samples, got {len(samples[name])}")
        if len({row["proof_bytes"] for row in samples[name]}) != 1:
            raise ValueError(f"{name}: proof size varied across identical trials")
    for name in ("sha_shift_warm", "sha_shift_cold"):
        if len(stages[name]) != args.trials:
            raise ValueError(f"{name}: missing stage samples")

    summary = {
        name: {
            "prove_excluding_both_pow_ns_median": statistics.median(row["prove_excluding_pow_ns"] for row in rows),
            "verify_ns_median": statistics.median(row["verify_ns"] for row in rows),
            "fixed_setup_ns_median": statistics.median(row["fixed_setup_ns"] for row in rows),
            "proof_bytes": rows[0]["proof_bytes"],
        }
        for name, rows in samples.items()
    }
    stage_summary = {
        name: {
            key: statistics.median(row[key] for row in rows)
            for key in rows[0]
            if key != "trial"
        }
        for name, rows in stages.items()
        if rows
    }
    comparison = {
        "warm_prover_speedup_generic_over_shift": summary["generic_warm"]["prove_excluding_both_pow_ns_median"] / summary["sha_shift_warm"]["prove_excluding_both_pow_ns_median"],
        "cold_prover_speedup_generic_over_shift": summary["generic_cold"]["prove_excluding_both_pow_ns_median"] / summary["sha_shift_cold"]["prove_excluding_both_pow_ns_median"],
        "shift_over_generic_native_verify_time": summary["sha_shift_warm"]["verify_ns_median"] / summary["generic_warm"]["verify_ns_median"],
        "shift_over_generic_proof_bytes": summary["sha_shift_warm"]["proof_bytes"] / summary["generic_warm"]["proof_bytes"],
    }
    source = HERE / "examples/bitcoin/bitcoin_header_pow.s31.json"
    assignment = HERE / "examples/bitcoin/bitcoin_header_pow.valid.json"
    record = {
        "schema": "s31-bitcoin-generic-vs-sha-shift-matched-v1",
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "host": platform.platform(),
        "python": platform.python_version(),
        "binary": str(binary),
        "binary_sha256": sha256(binary),
        "execution_mode": setup["execution_mode"],
        "source_sha256": sha256(source),
        "assignment_sha256": sha256(assignment),
        "proof_parameters": {"fri_pow_bits": 26, "fri_queries": 70, "fri_log_blowup_factor": 1, "interaction_pow_bits": 20},
        "public_output": "same eight M31 words of Poseidon2 root; private 80-byte header and private SHA digest",
        "privacy_limit": "Header and SHA digest are absent from the public statement. Current trace openings are unmasked, so this is not a zero-knowledge confidentiality claim.",
        "timing_policy": "same in-process GPA and native verifier; prove excludes serialization; interaction and FRI PoW subtracted separately; warm fixed trees prepared before timer; cold fixed trees prepared inside timer",
        "setup": setup,
        "samples": samples,
        "shift_stages": stages,
        "shift_stage_medians": stage_summary,
        "summary": summary,
        "comparison": comparison,
        "zig_reported_median": reported_median,
        "scope": "One host and one fixed Bitcoin header. Do not extrapolate to throughput or recursion. PoW duration is transcript dependent; compare non-PoW timings. The generic and shift proof formats differ.",
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    print(f"Saved {args.out}")


if __name__ == "__main__":
    main()
