"""Validate official Stwo-Cairo input, proof, and semantic-summary vectors."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def check(
    root: Path,
    *,
    cairo_repository: str,
    cairo_revision: str,
    stwo_repository: str,
    stwo_revision: str,
) -> list[str]:
    authority = {
        "repository": cairo_repository,
        "revision": cairo_revision,
        "stwo_repository": stwo_repository,
        "stwo_revision": stwo_revision,
    }
    errors = _check_record(
        root,
        "vectors/cairo/official/all_opcodes_blake2s.provenance.json",
        "stwo_cairo_official_oracle_vector_v1",
        authority,
        requires_proof=True,
    )
    errors.extend(
        _check_record(
            root,
            "vectors/cairo/official/all_builtins.provenance.json",
            "stwo_cairo_official_input_vector_v1",
            authority,
            requires_proof=False,
        )
    )
    return errors


def _check_record(
    root: Path,
    relative_path: str,
    schema: str,
    authority: dict[str, str],
    *,
    requires_proof: bool,
) -> list[str]:
    try:
        record = json.loads((root / relative_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"{relative_path}: invalid provenance: {error}"]
    if not isinstance(record, dict) or record.get("schema") != schema:
        return [f"{relative_path}: invalid schema"]

    source = record.get("source")
    prover_input = record.get("prover_input")
    if not isinstance(source, dict) or not isinstance(prover_input, dict):
        return [f"{relative_path}: source and prover_input objects are required"]
    errors = [
        f"{relative_path}: source {key!r} is {source.get(key)!r}, expected {expected!r}"
        for key, expected in authority.items()
        if source.get(key) != expected
    ]
    if requires_proof:
        proof = record.get("proof")
        if not isinstance(proof, dict):
            errors.append(f"{relative_path}: proof object is required")
        else:
            errors.extend(_check_proof(root, relative_path, proof))
    errors.extend(_check_input(root, relative_path, source, prover_input))
    return errors


def _check_proof(
    root: Path,
    relative_path: str,
    proof: dict[str, object],
) -> list[str]:
    path = proof.get("path")
    if not isinstance(path, str) or Path(path).is_absolute():
        return [f"{relative_path}: proof path is invalid"]
    try:
        vector = (root / path).read_bytes()
    except OSError as error:
        return [f"{relative_path}: unable to read proof vector: {error}"]
    errors: list[str] = []
    if proof.get("bytes") != len(vector):
        errors.append(f"{relative_path}: proof byte count drifted")
    if proof.get("sha256") != hashlib.sha256(vector).hexdigest():
        errors.append(f"{relative_path}: proof digest drifted")
    if proof.get("channel") != "blake2s" or proof.get("format") != "binary":
        errors.append(f"{relative_path}: proof transport identity drifted")
    return errors


def _check_input(
    root: Path,
    relative_path: str,
    source: dict[str, object],
    prover_input: dict[str, object],
) -> list[str]:
    path = prover_input.get("path")
    if not isinstance(path, str) or Path(path).is_absolute():
        return [f"{relative_path}: prover input path is invalid"]
    try:
        encoded = (root / path).read_bytes()
    except OSError as error:
        return [f"{relative_path}: unable to read prover input: {error}"]

    errors: list[str] = []
    digest = hashlib.sha256(encoded).hexdigest()
    if prover_input.get("bytes") != len(encoded):
        errors.append(f"{relative_path}: prover input byte count drifted")
    if prover_input.get("sha256") != digest:
        errors.append(f"{relative_path}: prover input digest drifted")
    if source.get("prover_input_sha256") != digest:
        errors.append(f"{relative_path}: source prover input digest drifted")
    if prover_input.get("format") != "official_json":
        errors.append(f"{relative_path}: prover input transport identity drifted")
    summary = prover_input.get("summary")
    if not isinstance(summary, dict):
        return errors + [f"{relative_path}: prover input summary is required"]
    errors.extend(_check_summary(root, relative_path, summary, digest))
    return errors


def _check_summary(
    root: Path,
    relative_path: str,
    summary: dict[str, object],
    input_digest: str,
) -> list[str]:
    path = summary.get("path")
    if not isinstance(path, str) or Path(path).is_absolute():
        return [f"{relative_path}: prover input summary path is invalid"]
    try:
        encoded = (root / path).read_bytes()
        document = json.loads(encoded)
    except (OSError, json.JSONDecodeError) as error:
        return [f"{relative_path}: invalid prover input summary: {error}"]

    errors: list[str] = []
    if summary.get("bytes") != len(encoded):
        errors.append(f"{relative_path}: prover input summary byte count drifted")
    if summary.get("sha256") != hashlib.sha256(encoded).hexdigest():
        errors.append(f"{relative_path}: prover input summary digest drifted")
    schema = "stwo_cairo_official_input_summary_v2"
    if (
        summary.get("schema") != schema
        or not isinstance(document, dict)
        or document.get("schema") != schema
    ):
        errors.append(f"{relative_path}: prover input summary schema drifted")
    if document.get("input_sha256") != input_digest:
        errors.append(f"{relative_path}: prover input summary authority drifted")
    return errors
