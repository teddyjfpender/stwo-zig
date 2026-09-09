#!/usr/bin/env python3
"""Validate compact replay evidence or admit it to the benchmark matrix."""

from __future__ import annotations

import argparse
import copy
from pathlib import Path
import sys


BENCHMARK_DIR = Path(__file__).resolve().parent
REPOSITORY = Path(__file__).resolve().parents[2]
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_benchmark_matrix as matrix_protocol  # noqa: E402
import ethereum_block_compact_replay_admission as admission  # noqa: E402
import ethereum_block_compact_replay_evidence as replay_evidence  # noqa: E402
from scripts import ethereum_block_proof_protocol as proof_protocol  # noqa: E402


def admit(
    matrix: dict, fixture_id: str, replay_receipt: Path,
) -> dict:
    matrix_protocol.validate_matrix(matrix)
    result = copy.deepcopy(matrix)
    result.pop("content_sha256")
    fixture = next(
        (item for item in result["fixtures"] if item["fixture_id"] == fixture_id),
        None,
    )
    if fixture is None:
        raise admission.ReplayAdmissionError("matrix replay fixture is unknown")
    source_corpus = matrix_protocol._validate_source_authorities(matrix)[0]
    source = next(
        item for item in source_corpus["fixtures"] if item["fixture_id"] == fixture_id
    )
    evidence = replay_evidence.validate(replay_receipt.absolute())
    fixture["systems"]["stwo_zig"]["stages"]["execution"] = (
        admission.validate_stage(evidence, source)
    )
    result["aggregate"] = matrix_protocol._derived_aggregate(result["fixtures"])
    return proof_protocol.seal(result)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-replay")
    validate.add_argument("--replay-receipt", type=Path, required=True)
    admit_command = commands.add_parser("admit")
    admit_command.add_argument("--matrix", type=Path, required=True)
    admit_command.add_argument("--fixture-id", required=True)
    admit_command.add_argument("--replay-receipt", type=Path, required=True)
    admit_command.add_argument("--output", type=Path, required=True)
    admit_command.add_argument("--staging-directory", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "validate-replay":
            evidence = replay_evidence.validate(arguments.replay_receipt.absolute())
            print(proof_protocol.canonical_bytes({
                "schema": replay_evidence.REPLAY_SCHEMA,
                "status": "valid-diagnostic-only",
                "receipt_sha256": evidence["receipt"]["sha256"],
                "matrix_timing_admissible": False,
                "proof_complete": False,
            }).decode("ascii"), end="")
            return 0
        value = admit(
            matrix_protocol.load_matrix(arguments.matrix.absolute()),
            arguments.fixture_id,
            arguments.replay_receipt.absolute(),
        )
        matrix_protocol.publish_matrix(
            arguments.output.absolute(), arguments.staging_directory.absolute(), value,
        )
        return 0
    except (
        admission.ReplayAdmissionError,
        matrix_protocol.MatrixError,
        proof_protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
