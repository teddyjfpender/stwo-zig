#!/usr/bin/env python3
"""Run and record the test-security generic versus fused SHA fold comparison."""

from __future__ import annotations

import hashlib
import json
import platform
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[3]
S31 = ROOT / "src/frontends/s31"
OUTPUT = ROOT / "design/s31/measurements/bitcoin-fold-generic-vs-fused-sha-test-fri-2026-10-07.json"
COMMAND = [
    "zig", "build", "--build-file", "src/frontends/s31/build.zig",
    "test-sha-fused-fold-matched-bench", "-Doptimize=ReleaseFast", "-j1",
]
BASE_STAGES = (
    "fixed_ns", "composition_eval_ns", "composition_interpolate_ns",
    "composition_commit_ns", "fri_quotient_ns", "fri_decommit_ns",
)
EXTRA_STAGES = (
    "witness_ns", "main_commit_ns", "interaction_ns", "interaction_commit_ns",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_fields(line: str) -> dict[str, str | int]:
    fields: dict[str, str | int] = {}
    for item in line.split()[1:]:
        key, value = item.split("=", 1)
        fields[key] = int(value) if value.isdecimal() else value
    return fields


def main() -> None:
    result = subprocess.run(COMMAND, cwd=ROOT, capture_output=True, text=True, check=True)
    setup_lines = [line for line in result.stderr.splitlines() if line.startswith("S31_FOLD_MATCHED_SETUP ")]
    proof_lines = [line for line in result.stderr.splitlines() if line.startswith("S31_FOLD_MATCHED profile=")]
    if len(setup_lines) != 1 or len(proof_lines) != 2:
        raise ValueError(f"missing matched proof results: {result.stderr[:2000]}")
    setup = parse_fields(setup_lines[0])
    proofs = [parse_fields(line) for line in proof_lines]
    if {item["profile"] for item in proofs} != {"generic", "fused_sha"}:
        raise ValueError("expected one generic and one fused SHA native proof")
    expected_setup = {
        "child_pow": 26, "child_queries": 70, "child_fold": 4,
        "outer_pow": 0, "outer_queries": 12, "outer_fold": 1,
        "fixed_policy": "cold", "outer_security": "test_only",
    }
    if setup != expected_setup:
        raise ValueError(f"unexpected comparison configuration: {setup}")
    expected_metrics = {"profile", "prove_ns", "verify_ns", "proof_bytes", *BASE_STAGES}
    allowed_metrics = expected_metrics | set(EXTRA_STAGES)
    for proof in proofs:
        if not expected_metrics.issubset(proof) or not set(proof).issubset(allowed_metrics) or any(proof[k] <= 0 for k in set(proof) - {"profile"}):
            raise ValueError(f"incomplete stage or proof metric: {proof}")
    zig_version = subprocess.check_output(["zig", "version"], cwd=ROOT, text=True).strip()
    source_files = (
        "sha_fused_fold_matched_bench_test.zig", "bitcoin_chain_fold.zig",
        "bitcoin_fold_step.zig", "bitcoin_fold_digest.zig",
        "bitcoin_chain_anchor.zig", "sha_fused_fold_profile.zig",
        "sha_fused_fold_prover.zig", "sha_fused_fold_native_verifier.zig",
    )
    record = {
        "schema": "s31-bitcoin-fold-generic-vs-fused-sha-test-fri-v1",
        "command": " ".join(COMMAND),
        "compiler": {"zig_version": zig_version, "optimization": "ReleaseFast"},
        "machine": {"platform": platform.platform(), "architecture": platform.machine(), "processor": platform.processor()},
        "setup": setup,
        "proofs": proofs,
        "stage_coverage": "The six base stage fields are captured in all samples. Base witness and interaction fields are captured by benchmark versions that emit them; missing fields were not measured.",
        "native_verification": "both proof byte streams accepted by their native verifiers after independent key and public output derivation",
        "timing_scope": "outer prove only, with one shared production child proof, parsed witness, circuit topology, preprocessed columns, and independent keys prepared before each timed prove call; both fixed commitments are cold and inside the respective prove call",
        "measurement_limit": "Single sequential sample, generic then fused SHA. Outer FRI0/12/fold1 is a test configuration and provides no production security or speed claim. Child anchor uses production FRI26/70/fold4.",
        "separate_production_joined_observation": {
            "profile": "fused_sha_only", "outer_fri_pow_bits": 26,
            "outer_fri_queries": 70, "outer_fri_fold": 1,
            "proof_bytes": 659942, "prove_ns": 12544000000, "verify_ns": 16000000,
            "provenance": "Separate single ReleaseFast joined proof reported by the full-proof test; generic production outer proof was not measured alongside it. Do not compare this timing to the matched test-FRI samples.",
        },
        "source_sha256": {name: sha256(S31 / name) for name in source_files},
        "projection_sha256": sha256(ROOT / "vectors/circuit/official/compiled_air_constraints_v1.bin"),
        "fixture_sha256": sha256(S31 / "examples/bitcoin_header_link.valid.json"),
    }
    OUTPUT.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"Recorded matched test-FRI native proofs in {OUTPUT.relative_to(ROOT)}")
    for item in proofs:
        print(f"{item['profile']}: {item['prove_ns'] / 1e9:.3f}s prove, {item['verify_ns'] / 1e6:.2f}ms verify, {item['proof_bytes']} B")


if __name__ == "__main__":
    main()
