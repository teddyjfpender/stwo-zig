#!/usr/bin/env python3
"""Reproduce the Bitcoin checkpoint, fold-0, and recursive fold-1 proof run."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[3]
S31 = ROOT / "src/frontends/s31"
MEASUREMENTS = ROOT / "design/s31/measurements"
COMMAND = [
    "zig", "build", "--build-file", "src/frontends/s31/build.zig",
    "test-bitcoin-chain-fold-proof", "-Doptimize=ReleaseSafe", "-j1",
]
CLI_BUILD = ["zig", "build", "bitcoin-chain-cli", "--build-file", "src/frontends/s31/build.zig", "-Doptimize=ReleaseSafe", "-j1"]
CLI_ACCEPTANCE = ["python3", "src/frontends/s31/acceptance_bitcoin_chain_cli.py"]
PATTERN = re.compile(
    r"Bitcoin (checkpoint anchor|chain fold step [01]): "
    r"proof_bytes=(\d+) prove_seconds=([0-9.]+) root=([0-9a-f]{64})"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    started = time.monotonic()
    try:
        result = subprocess.run(COMMAND, cwd=ROOT, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(exc.stdout or "")
        sys.stderr.write(exc.stderr or "")
        raise
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
    key_match = re.search(
        r"Bitcoin chain verifier: key_sha256=([0-9a-f]{64}) "
        r"step_1_accepted=true replay_rejected=true", result.stderr,
    )
    assert key_match is not None
    topology_path = MEASUREMENTS / "bitcoin-chain-fold-topology-v3-2026-10-07.json"
    topology = json.loads(topology_path.read_text())
    assert observations["checkpoint anchor"]["preprocessed_root"] == topology["anchor_preprocessed_root"]
    assert all(
        observations[name]["preprocessed_root"] == topology["candidate_preprocessed_root"]
        for name in ("chain fold step 0", "chain fold step 1")
    )
    files = (
        "bitcoin_chain_anchor.zig", "bitcoin_chain_fold.zig", "bitcoin_fold_step.zig",
        "bitcoin_fold_digest.zig", "bitcoin_chain_anchor_proof_test.zig",
        "bitcoin_chain_verifier.zig", "bitcoin_chain_cli.zig",
        "bitcoin_target.zig", "sha256d.zig", "acceptance_bitcoin_chain_cli.py",
        "examples/bitcoin_header_link.valid.json", "examples/bitcoin_block2_header.valid.json",
    )
    subprocess.run(CLI_BUILD, cwd=ROOT, check=True)
    subprocess.run(CLI_ACCEPTANCE, cwd=ROOT, check=True)
    artifacts = ROOT / "zig-out/s31/bitcoin-chain-two-step"
    for name in ("fold0", "fold1"):
        observations[f"chain fold step {name[-1]}"]["proof_sha256"] = sha256(artifacts / f"{name}.proof")
        observations[f"chain fold step {name[-1]}"]["statement_sha256"] = sha256(artifacts / f"{name}.statement.json")
    record = {
        "schema": "s31-bitcoin-chain-two-step-proof-v3",
        "command": " ".join(COMMAND),
        "cli_build_command": " ".join(CLI_BUILD),
        "cli_acceptance_command": " ".join(CLI_ACCEPTANCE),
        "observations": observations,
        "wall_seconds": round(wall_seconds, 3),
        "core_reference_commit": "aef8a04966d7ab6c04edc5d19b733e78205405de",
        "native_verification_passed": True,
        "sealed_key_sha256": key_match.group(1),
        "standalone_key_statement_and_replay_checks_passed": True,
        "changed_public_statement_rejected_at_both_fold_steps": True,
        "changed_timestamp_window_rejected": True,
        "wrong_step_replay_rejected": True,
        "forged_prior_state_rejected_by_full_circuit": True,
        "source_sha256": {name: sha256(S31 / name) for name in files},
        "air_bundle_sha256": sha256(ROOT / "vectors/circuit/official/circuit_air.air_programs_v1.bin"),
        "projection_sha256": sha256(ROOT / "vectors/circuit/official/compiled_air_constraints_v1.bin"),
        "topology_record_sha256": sha256(topology_path),
        "scope": "Genesis first-epoch SHA256d, exact bits, recursive median-time-past. One local ReleaseSafe low-memory proving run; timings include prover-internal work and exclude test setup and native verification. No comparative speed or full-consensus security claim.",
    }
    output = MEASUREMENTS / "bitcoin-chain-two-step-proof-v3-2026-10-07.json"
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"Recorded native Bitcoin chain proofs in {output.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
