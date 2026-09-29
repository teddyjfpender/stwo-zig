#!/usr/bin/env python3
"""Regenerate the circuit recursion parity fixtures under vectors/circuit/.

Builds `tools/stwo-circuit-oracle-rs` from its lockfile, locates the `proving`
checkout Cargo resolved for the pinned revision, runs every oracle subcommand,
copies the upstream goldens the rungs consume, and writes the provenance record
that `scripts/check_upstream_pins.py` authenticates. Every command but
`prove-cairo` only builds circuits or hashes data; `prove-cairo` proves two small
Cairo programs (all_opcodes, all_builtins), so everything runs on a laptop.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from upstream_pins_lib import circuit_recursion as lane
    from upstream_pins_lib.model import parse_ledger
except ModuleNotFoundError:  # Imported as scripts.generate_circuit_oracle_vectors in tests.
    from scripts.upstream_pins_lib import circuit_recursion as lane
    from scripts.upstream_pins_lib.model import parse_ledger


ROOT = Path(__file__).resolve().parents[1]
ORACLE_BINARY = "stwo-circuit-oracle"


def cargo(*arguments: str, capture: bool = False) -> str:
    """Runs cargo inside the oracle crate, so rustup applies its `rust-toolchain.toml`."""
    return subprocess.run(
        ["cargo", *arguments],
        cwd=ROOT / lane.ORACLE,
        check=True,
        capture_output=capture,
        text=True,
    ).stdout


def cargo_json(*arguments: str) -> dict:
    return json.loads(cargo(*arguments, "--format-version", "1", capture=True))


def proving_root(repository: str, revision: str) -> Path:
    """The checkout Cargo uses for the pinned `circuits` crate: `<root>/crates/circuits`."""
    source = lane.lock_source(repository, revision)
    for package in cargo_json("metadata", "--locked")["packages"]:
        if package["name"] == "circuits" and package.get("source") == source:
            return Path(package["manifest_path"]).parents[2]
    raise SystemExit(f"cargo metadata did not resolve circuits from {source}")


def build_oracle() -> Path:
    cargo("build", "--release", "--locked")
    target = Path(cargo_json("metadata", "--no-deps", "--locked")["target_directory"])
    return target / "release" / ORACLE_BINARY


def artifact_record(staging: Path, path: str, **fields: object) -> dict:
    data = (staging / path).read_bytes()
    return {"path": path, **fields, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def generate(staging: Path, oracle: Path, proving: Path) -> list[dict]:
    artifacts = []
    for path, rung, subcommand, reads_upstream in lane.ORACLE_ARTIFACTS:
        (staging / path).parent.mkdir(parents=True, exist_ok=True)
        root_arguments = ["--proving-root", str(proving)] if reads_upstream else []
        subprocess.run(
            [str(oracle), subcommand, *root_arguments, "--output", str(staging / path)],
            check=True,
        )
        recorded = [ORACLE_BINARY, subcommand]
        if reads_upstream:
            recorded += ["--proving-root", lane.PROVING_ROOT_PLACEHOLDER]
        artifacts.append(
            artifact_record(staging, path, rung=rung, command=recorded + ["--output", path])
        )
    for path, rung, prover_input, registry in lane.CAIRO_PROOF_ARTIFACTS:
        # Leaf-lane Cairo proofs of small programs: seconds and about 2 GB each.
        (staging / path).parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [str(oracle), "prove-cairo", "--prover-input", prover_input, "--params", registry,
             "--proving-root", str(proving), "--output", str(staging / path)],
            check=True,
            cwd=ROOT,
        )
        artifacts.append(
            artifact_record(
                staging, path, rung=rung, command=lane.cairo_proof_command(path, prover_input, registry)
            )
        )
    for path, upstream_path in lane.UPSTREAM_COPIES:
        (staging / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(proving / upstream_path, staging / path)
        artifacts.append(artifact_record(staging, path, upstream_path=upstream_path))
    return sorted(artifacts, key=lambda artifact: artifact["path"])


def provenance(artifacts: list[dict], ledger, generated_on: str) -> dict:
    return {
        "schema": lane.PROVENANCE_SCHEMA,
        "upstream": {
            "repository": ledger.circuit_recursion_repository,
            "revision": ledger.circuit_recursion_revision,
        },
        "oracle": {
            "manifest": lane.MANIFEST,
            "toolchain": ledger.circuit_recursion_toolchain,
            "source_sha256": lane.oracle_source_sha256(ROOT),
        },
        "generator": "scripts/generate_circuit_oracle_vectors.py",
        "generated_on": generated_on,
        "host": f"{platform.system()} {platform.machine()}",
        "artifacts": artifacts,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--date", default=datetime.date.today().isoformat(), help="generation date")
    args = parser.parse_args(argv)

    ledger = parse_ledger(ROOT / "conformance" / "upstream.md")
    oracle = build_oracle()
    proving = proving_root(ledger.circuit_recursion_repository, ledger.circuit_recursion_revision)
    vectors = ROOT / lane.VECTORS
    vectors.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=vectors.parent) as directory:
        staging = Path(directory)
        artifacts = generate(staging, oracle, proving)
        record = provenance(artifacts, ledger, args.date)
        (staging / lane.PROVENANCE).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        for path in (*lane.MANAGED, lane.PROVENANCE):
            (ROOT / path).parent.mkdir(parents=True, exist_ok=True)
            os.replace(staging / path, ROOT / path)
    errors = lane.check(
        ROOT,
        repository=ledger.circuit_recursion_repository,
        revision=ledger.circuit_recursion_revision,
        toolchain=ledger.circuit_recursion_toolchain,
    )
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
