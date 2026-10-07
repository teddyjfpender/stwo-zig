#!/usr/bin/env python3
"""Regenerate the witness-free Bitcoin chain-fold topology measurement."""

import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[3]
S31 = ROOT / "src/frontends/s31"
MEASUREMENTS = ROOT / "design/s31/measurements"
COMMAND = [
    "zig", "build", "--build-file", "src/frontends/s31/build.zig",
    "inspect-bitcoin-chain-fold", "-Doptimize=ReleaseSafe", "-j2",
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    result = subprocess.run(COMMAND, cwd=ROOT, capture_output=True, text=True, check=True)
    cases = [json.loads(line) for line in result.stderr.splitlines() if line.startswith("{")]
    by_name = {case["case"]: case for case in cases}
    expected = {
        "baseline", "qm31-expanded", "candidate-base", "candidate-recursive",
        "candidate-u16-carry", "candidate-u32-max", "changed-checkpoint",
        "changed-base-root",
    }
    assert set(by_name) == expected
    base = by_name["candidate-base"]
    assert all(by_name[name]["fixed_point"] for name in expected if name.startswith("candidate-") or name.startswith("changed-"))
    assert all(
        by_name[name]["preprocessed_root"] == base["preprocessed_root"]
        for name in ("candidate-recursive", "candidate-u16-carry", "candidate-u32-max")
    )
    assert all(
        by_name[name]["preprocessed_root"] != base["preprocessed_root"]
        for name in ("changed-checkpoint", "changed-base-root")
    )
    assert len({case["anchor_root"] for case in cases}) == 1
    assert base["padded"]["eq"] == base["child_eq_rows"]
    assert base["padded"]["qm31_ops"] == base["child_qm31_rows"]
    paths = (
        "bitcoin_chain_anchor.zig", "bitcoin_chain_fold.zig", "bitcoin_fold_step.zig", "bitcoin_fold_digest.zig",
        "inspect_bitcoin_chain_fold.zig",
    )
    record = {
        "schema": "s31-bitcoin-chain-fold-topology-v1",
        "command": " ".join(COMMAND),
        "cases": cases,
        "candidate_preprocessed_root": base["preprocessed_root"],
        "anchor_preprocessed_root": base["anchor_root"],
        "candidate_padded_rows": base["padded"],
        "source_sha256": {path: sha256(S31 / path) for path in paths},
        "projection_sha256": sha256(ROOT / "vectors/circuit/official/compiled_air_constraints_v1.bin"),
        "reference_sha256": sha256(MEASUREMENTS / "bitcoin-sparse-wide-fold-stages-v1-2026-10-07.json"),
        "scope": "Witness-free topology and preprocessed roots only; no Bitcoin chain-fold proof or timed proving benchmark.",
    }
    output = MEASUREMENTS / "bitcoin-chain-fold-topology-v1-2026-10-07.json"
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"Recorded {len(cases)} fold geometries in {output.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
