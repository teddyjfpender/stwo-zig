#!/usr/bin/env python3
"""Prove that the Cairo Metal product rejects substituted AOT bundles."""

from __future__ import annotations

import argparse
from pathlib import Path
import os
import shutil
import subprocess
import tempfile


CASES = (
    ("stwo_zig_core.manifest.json", "ManifestTrustAnchorMismatch"),
    ("stwo_zig_core.metal", "CoreSourceIdentityMismatch"),
    ("stwo_zig_core.metallib", "MetallibIdentityMismatch"),
)


def mutate_first_byte(path: Path) -> None:
    payload = bytearray(path.read_bytes())
    if not payload:
        raise ValueError(f"cannot mutate empty AOT artifact: {path}")
    payload[0] ^= 1
    path.write_bytes(payload)


def run_rejection(
    executable: Path,
    bundle: Path,
    prover_input: Path,
    params: Path,
    expected_error: str,
    output_dir: Path,
) -> None:
    output_dir.mkdir(parents=True)
    proof = output_dir / "proof.json"
    report = output_dir / "report.json"
    environment = os.environ.copy()
    environment["STWO_CAIRO_METAL_AOT_BUNDLE"] = str(bundle)
    result = subprocess.run(
        (
            str(executable),
            "prove",
            "--prover-input",
            str(prover_input),
            "--params",
            str(params),
            "--proof",
            str(proof),
            "--report-out",
            str(report),
            "--verify",
        ),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    diagnostic = result.stdout + result.stderr
    if result.returncode == 0:
        raise ValueError(f"substituted AOT bundle was admitted: {bundle}")
    if expected_error not in diagnostic:
        raise ValueError(
            f"expected {expected_error} for {bundle}, got:\n{diagnostic}"
        )
    if proof.exists() or report.exists():
        raise ValueError("failed AOT admission published proof output")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--prover-input", type=Path, required=True)
    parser.add_argument("--params", type=Path, required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="stwo-cairo-metal-aot-") as raw:
        root = Path(raw)
        for index, (filename, expected_error) in enumerate(CASES):
            candidate = root / f"case-{index}"
            shutil.copytree(args.bundle, candidate)
            mutate_first_byte(candidate / filename)
            run_rejection(
                args.executable,
                candidate,
                args.prover_input,
                args.params,
                expected_error,
                root / f"outputs-{index}",
            )

        missing = root / "missing"
        run_rejection(
            args.executable,
            missing,
            args.prover_input,
            args.params,
            "FileNotFound",
            root / "outputs-missing",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
