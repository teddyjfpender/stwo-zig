#!/usr/bin/env python3
"""Reproduce the Bitcoin checkpoint, fold-0, and recursive fold-1 proof run."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import time


ROOT = Path(__file__).resolve().parents[3]
S31 = ROOT / "src/frontends/s31"
MEASUREMENTS = ROOT / "design/s31/measurements"
COMMAND = [
    "zig", "build", "--build-file", "src/frontends/s31/build.zig",
    "test-bitcoin-chain-fold-proof", "-Doptimize=ReleaseSafe", "-j2",
]
PATTERN = re.compile(
    r"Bitcoin (checkpoint anchor|chain fold step [01]): "
    r"proof_bytes=(\d+) prove_seconds=([0-9.]+) root=([0-9a-f]{64})"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    started = time.monotonic()
    result = subprocess.run(COMMAND, cwd=ROOT, capture_output=True, text=True, check=True)
    wall_seconds = time.monotonic() - started
    observations = {
        match.group(1): {
            "proof_bytes": int(match.group(2)),
            "prove_seconds": float(match.group(3)),
            "preprocessed_root": match.group(4),
        }
        for match in PATTERN.finditer(result.stderr)
    }
    assert set(observations) == {"checkpoint anchor", "chain fold step 0", "chain fold step 1"}
    assert "Bitcoin chain fold: forged prior state rejected" in result.stderr
    topology = json.loads((MEASUREMENTS / "bitcoin-chain-fold-topology-v1-2026-10-07.json").read_text())
    assert observations["checkpoint anchor"]["preprocessed_root"] == topology["anchor_preprocessed_root"]
    assert all(
        observations[name]["preprocessed_root"] == topology["candidate_preprocessed_root"]
        for name in ("chain fold step 0", "chain fold step 1")
    )
    files = (
        "bitcoin_chain_anchor.zig", "bitcoin_chain_fold.zig", "bitcoin_fold_step.zig",
        "bitcoin_fold_digest.zig", "bitcoin_chain_anchor_proof_test.zig",
        "bitcoin_target.zig", "sha256d.zig", "poseidon2.zig",
        "recursion_counter.zig", "recursion_gate.zig", "native_verifier.zig",
        "mod.zig", "build.zig",
        "examples/bitcoin_header_link.valid.json", "examples/bitcoin_block2_header.valid.json",
    )
    record = {
        "schema": "s31-bitcoin-chain-two-step-proof-v1",
        "command": " ".join(COMMAND),
        "observations": observations,
        "wall_seconds": round(wall_seconds, 3),
        "native_verification_passed": True,
        "changed_public_statement_rejected_at_both_fold_steps": True,
        "forged_prior_state_rejected_by_full_circuit": True,
        "source_sha256": {name: sha256(S31 / name) for name in files},
        "air_bundle_sha256": sha256(ROOT / "vectors/circuit/official/circuit_air.air_programs_v1.bin"),
        "projection_sha256": sha256(ROOT / "vectors/circuit/official/compiled_air_constraints_v1.bin"),
        "topology_record_sha256": sha256(MEASUREMENTS / "bitcoin-chain-fold-topology-v1-2026-10-07.json"),
        "scope": "One local low-memory proving run; no comparative speed or security bound claim.",
    }
    output = MEASUREMENTS / "bitcoin-chain-two-step-proof-v1-2026-10-07.json"
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"Recorded native Bitcoin chain proofs in {output.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
