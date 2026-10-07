#!/usr/bin/env python3
"""Regenerate the value-free fused-SHA Bitcoin fold topology and cost record."""

from __future__ import annotations

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import hashlib
import json
from pathlib import Path
import subprocess


ROOT = S31_SOURCE_ROOT.parents[2]
S31 = ROOT / "src/frontends/s31"
MEASUREMENTS = ROOT / "design/s31/measurements"
COMMAND = [
    "zig", "build", "--build-file", "src/frontends/s31/build.zig",
    "inspect-bitcoin-chain-fold-fused", "-Doptimize=ReleaseSafe", "-j1",
]
GENERIC = MEASUREMENTS / "bitcoin-chain-fold-topology-v3-2026-10-07.json"
REFERENCE = MEASUREMENTS / "bitcoin-sparse-wide-fold-stages-v1-2026-10-07.json"
OUTPUT = MEASUREMENTS / "bitcoin-chain-fold-fused-topology-v1-2026-10-07.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fields(line: str) -> dict[str, str | int]:
    return {
        k: int(v) if v.isdecimal() else v
        for k, v in (part.split("=", 1) for part in line.split()[1:])
    }


def main() -> None:
    result = subprocess.run(COMMAND, cwd=ROOT, capture_output=True, text=True, check=True)
    cases = [fields(line) for line in result.stderr.splitlines() if line.startswith("S31_FUSED_FOLD_TOPOLOGY ")]
    if len(cases) != 2 or {case["step"] for case in cases} != {0, 1}:
        raise ValueError(f"expected value-free topology at steps 0 and 1: {result.stderr[:1000]}")
    for field in ("raw_vars", "eq", "qm31", "u32", "xor", "blake", "anchor_root", "fixed_root", "boundary_sha256", "boundary_first", "boundary_last"):
        if cases[0][field] != cases[1][field]:
            raise ValueError(f"step-dependent fused fold {field}")
    generic = json.loads(GENERIC.read_text())
    baseline = next(case for case in generic["cases"] if case["case"] == "candidate-base")
    child = generic["candidate_padded_rows"]
    raw = {"eq": cases[0]["eq"], "qm31_ops": cases[0]["qm31"], "m31_to_u32": cases[0]["u32"], "triple_xor": cases[0]["xor"], "blake_g": cases[0]["blake"]}
    if any(raw[name] > child[name] for name in raw):
        raise ValueError("fused fold exceeds child geometry")
    source_files = (
        "bitcoin_chain_fold.zig", "bitcoin_fold_step.zig", "bitcoin_fold_digest.zig",
        "bitcoin_chain_anchor.zig", "inspect_bitcoin_chain_fold_fused.zig",
    )
    record = {
        "schema": "s31-bitcoin-chain-fold-fused-topology-v1",
        "command": " ".join(COMMAND),
        "cases": cases,
        "child_padded_rows": child,
        "fused_raw_rows": raw,
        "generic_raw_rows": baseline["raw"],
        "raw_row_difference_fused_minus_generic": {name: raw[name] - baseline["raw"][name] for name in raw},
        "fused_raw_vars": cases[0]["raw_vars"],
        "generic_raw_vars": baseline["raw_vars"],
        "anchor_preprocessed_root": cases[0]["anchor_root"],
        "fused_preprocessed_root": cases[0]["fixed_root"],
        "canonical_sha_boundary_addresses_sha256": cases[0]["boundary_sha256"],
        "source_sha256": {name: sha256(S31 / name) for name in source_files},
        "projection_sha256": sha256(ROOT / "vectors/circuit/official/compiled_air_constraints_v1.bin"),
        "reference_sha256": sha256(REFERENCE),
        "generic_topology_sha256": sha256(GENERIC),
        "scope": "Value-free one-header SHA-external fold topology. Fixed root and 56-address Gate boundary are stable at steps 0 and 1. The inspector rejects duplicate/public boundary addresses. This is not a joined native proof or a speed measurement.",
    }
    OUTPUT.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"Recorded fused fold topology in {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
