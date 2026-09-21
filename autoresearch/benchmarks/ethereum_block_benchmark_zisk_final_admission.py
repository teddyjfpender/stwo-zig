#!/usr/bin/env python3
"""Admit sealed ZisK final-proof correctness evidence to the 5x2 matrix."""

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
import ethereum_block_zisk_final_admission as admission  # noqa: E402
import ethereum_block_zisk_final_evidence as evidence_protocol  # noqa: E402
from scripts import ethereum_block_proof_protocol as proof_protocol  # noqa: E402


def admit(matrix: dict, fixture_id: str, receipt: Path) -> dict:
    matrix_protocol.validate_matrix(matrix)
    result = copy.deepcopy(matrix)
    result.pop("content_sha256")
    fixture = next((item for item in result["fixtures"]
                    if item["fixture_id"] == fixture_id), None)
    if fixture is None:
        raise admission.ZiskFinalAdmissionError("ZisK final-proof fixture is unknown")
    corpus = matrix_protocol._validate_source_authorities(matrix)[0]
    source = next(item for item in corpus["fixtures"]
                  if item["fixture_id"] == fixture_id)
    evidence = evidence_protocol.evidence(receipt.absolute())
    for scope in admission.SUPPORTED_SCOPES:
        fixture["systems"]["zisk"]["stages"][scope] = admission.validate_stage(
            evidence, source, matrix["reference_manifest"], scope,
        )
    result["aggregate"] = matrix_protocol._derived_aggregate(result["fixtures"])
    return proof_protocol.seal(result)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--fixture-id", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--staging-directory", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        value = admit(
            matrix_protocol.load_matrix(arguments.matrix.absolute()),
            arguments.fixture_id, arguments.receipt.absolute(),
        )
        matrix_protocol.publish_matrix(
            arguments.output.absolute(), arguments.staging_directory.absolute(), value,
        )
        return 0
    except (
        admission.ZiskFinalAdmissionError,
        evidence_protocol.ZiskFinalEvidenceError,
        matrix_protocol.MatrixError,
        proof_protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
