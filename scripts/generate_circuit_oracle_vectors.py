#!/usr/bin/env python3
"""Regenerate the circuit recursion parity fixtures under vectors/circuit/.

Builds `tools/stwo-circuit-oracle-rs` from its lockfile, locates the `proving`
checkout Cargo resolved for the pinned revision, runs every oracle subcommand,
copies the upstream goldens the rungs consume, and writes the provenance record
that `scripts/check_upstream_pins.py` authenticates. Every subcommand builds
circuits, hashes data or proves small instances: `prove-small` proves the small
`prover_test.rs` circuits under the oracle's default memory budget, and
`adapt-program` and `prove-cairo` run and prove small Cairo programs (seconds
and 2-4 GB each). The heaviest (`topology`) peaks at about 7.1 GB resident. On
a shared host run it under the heavy-command wrapper.

The provenance names only host-independent inputs: the toolchain, the oracle's
`Cargo.lock` digest and the digest of every oracle source.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from upstream_pins_lib import circuit_recursion as lane
    from upstream_pins_lib.model import parse_ledger
    from upstream_pins_lib.official_cairo_air import bundle_summary
except ModuleNotFoundError:  # Imported as scripts.generate_circuit_oracle_vectors in tests.
    from scripts.upstream_pins_lib import circuit_recursion as lane
    from scripts.upstream_pins_lib.model import parse_ledger
    from scripts.upstream_pins_lib.official_cairo_air import bundle_summary


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


def generate(staging: Path, oracle: Path, proving: Path, zig_emit_dir: Path | None) -> list[dict]:
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
        fields: dict[str, object] = {"rung": rung, "command": recorded + ["--output", path]}
        if path == lane.AIR_PROGRAMS:
            fields.update(bundle_summary((staging / path).read_bytes()))
        artifacts.append(artifact_record(staging, path, **fields))
    for path, rung, program, task in lane.ADAPTED_PROGRAMS:
        (staging / path).parent.mkdir(parents=True, exist_ok=True)
        program_input: list[str] = []
        fields: dict[str, object] = {"rung": rung, "command": lane.adapt_program_command(path, program, task)}
        if task:
            # The bootloader reads its task and dumps the hashed-output preimage at the paths the
            # input names; the dump must be upstream's golden preimage, so the adapted run is the
            # execution the golden leaf proves.
            dump = staging / "leaf_preimage.dump.json"
            input_file = staging / "leaf_bootloader_input.json"
            input_file.write_text(
                json.dumps(lane.leaf_bootloader_input(task, str(proving), str(dump)), indent=2),
                encoding="utf-8",
            )
            program_input = ["--program-input", str(input_file)]
            fields["program_input"] = lane.leaf_bootloader_input(
                task, lane.PROVING_ROOT_PLACEHOLDER, lane.PREIMAGE_DUMP_PLACEHOLDER
            )
        subprocess.run(
            [str(oracle), "adapt-program", "--proving-root", str(proving), "--program", program,
             *program_input, "--output", str(staging / path)],
            check=True,
        )
        if task:
            if dump.read_bytes() != (proving / task[2]).read_bytes():
                raise SystemExit(f"{path}: the bootloader's preimage dump differs from {task[2]}")
            dump.unlink()
            input_file.unlink()
        artifacts.append(artifact_record(staging, path, **fields))
    adapted = {path for path, *_ in lane.ADAPTED_PROGRAMS}
    for path, rung, prover_input, registry, policy in lane.CAIRO_PROOF_ARTIFACTS:
        # Leaf-lane Cairo proofs of small programs: seconds and 2-4 GB each. An input
        # adapted above is read from the staging tree, under the same relative path.
        (staging / path).parent.mkdir(parents=True, exist_ok=True)
        command = lane.cairo_proof_command(
            str(staging / path), prover_input, registry, policy, proving_root=str(proving)
        )
        subprocess.run(
            [str(oracle), *command[1:]],
            check=True,
            cwd=staging if prover_input in adapted else ROOT,
        )
        artifacts.append(
            artifact_record(
                staging, path, rung=rung,
                command=lane.cairo_proof_command(path, prover_input, registry, policy),
            )
        )
    # The multiverifier's circuit-prover inputs (179 MB) stay outside the tree; only the
    # checkpoint that pins them is managed.
    path = lane.MULTIVERIFIER_INPUTS
    (staging / path).parent.mkdir(parents=True, exist_ok=True)
    inputs_file = staging / "multiverifier_inputs.stwzcirc"
    subprocess.run(
        [str(oracle), *lane.multiverifier_inputs_command(
            str(staging / path), proving_root=str(proving), inputs_output=str(inputs_file)
        )[1:]],
        check=True,
    )
    inputs_file.unlink()
    artifacts.append(
        artifact_record(staging, path, rung="r7", command=lane.multiverifier_inputs_command(path))
    )
    # Verdicts on Zig-emitted proofs: regenerated from `--zig-emit-dir`, otherwise kept.
    for path, label in lane.VERIFY_VERDICTS:
        (staging / path).parent.mkdir(parents=True, exist_ok=True)
        if zig_emit_dir is None:
            shutil.copyfile(ROOT / path, staging / path)
        else:
            subprocess.run(
                [str(oracle), *lane.verify_circuit_command(
                    str(staging / path), label, emit_dir=str(zig_emit_dir)
                )[1:]],
                check=True,
            )
        artifacts.append(
            artifact_record(staging, path, rung="r7", command=lane.verify_circuit_command(path, label))
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
            "lock": lane.LOCK,
            "lock_sha256": lane.sha256_file(ROOT / lane.LOCK),
            "source_sha256": lane.oracle_source_sha256(ROOT),
        },
        "generator": "scripts/generate_circuit_oracle_vectors.py",
        "generated_on": generated_on,
        "artifacts": artifacts,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--date", default=datetime.date.today().isoformat(), help="generation date")
    parser.add_argument(
        "--zig-emit-dir",
        type=Path,
        help="STWO_CIRCUIT_R7_EMIT_DIR of the Zig circuit-parity-r7 steps; without it the "
        "committed verify-circuit verdicts are kept",
    )
    args = parser.parse_args(argv)

    ledger = parse_ledger(ROOT / "conformance" / "upstream.md")
    oracle = build_oracle()
    proving = proving_root(ledger.circuit_recursion_repository, ledger.circuit_recursion_revision)
    vectors = ROOT / lane.VECTORS
    vectors.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=vectors.parent) as directory:
        staging = Path(directory)
        artifacts = generate(staging, oracle, proving, args.zig_emit_dir)
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
