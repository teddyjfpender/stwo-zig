#!/usr/bin/env python3
"""Validate focused/aggregate Native behavior and independent verification parity."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from scripts.product_identity_lib import validate_canonical_identity


ARTIFACT_FIELDS = {
    "schema_version", "upstream_commit", "exchange_mode", "generator", "example",
    "prove_mode", "pcs_config", "blake_statement", "plonk_statement",
    "poseidon_statement", "state_machine_statement", "wide_fibonacci_statement",
    "xor_statement", "proof_bytes_hex",
}
VERIFY_FIELDS = {
    "schema_version", "status", "product", "artifact_schema_version",
    "upstream_commit", "exchange_mode", "security_policy", "claimed_generator",
    "air", "proof_bytes", "proof_sha256",
}
SEMANTIC_REPORT_FIELDS = {
    "schema_version", "backend", "evidence_class", "profiled", "protocol", "workload",
    "provenance", "session", "runtime_admission", "proof", "backend_telemetry",
}
PARITY_RECEIPT_FIELDS = {
    "schema", "status", "normalization", "semantic_sha256", "proof_sha256",
    "artifacts", "reports", "verify_receipts",
}
SHARED_IDENTITY_FIELDS = {
    "schema_version", "implementation_repository", "implementation_commit",
    "implementation_tree", "implementation_dirty", "dirty_content_sha256",
    "zig_version", "target_arch", "target_os", "target_abi", "cpu_model",
    "cpu_features_sha256", "optimize",
}
PRODUCT_IDENTITY_FIELDS = sorted(
    {
        "name", "frontend", "backend", "role", "protocol_features",
        "protocol_manifest_sha256", "identity_sha256", "runtime_manifest",
        "sdk_manifest", "aot_manifest",
    }
)
IDENTITY_POLICY = {
    "stwo-native-cpu": {
        "frontend": "native-examples", "backend": "cpu", "role": "cli",
        "protocol_features": "native-examples-v1+lifted-pcs-v1",
        "runtime_manifest": "none", "sdk_manifest": "none", "aot_manifest": "none",
    },
    "stwo-zig": {
        "frontend": "aggregate", "backend": "cpu", "role": "cli",
        "protocol_features": "aggregate-compat-v1+cpu",
        "runtime_manifest": "none", "sdk_manifest": "none", "aot_manifest": "none",
    },
}


class ParityError(ValueError):
    """Focused and aggregate behavior evidence is incomplete or inconsistent."""


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ParityError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    if not isinstance(value, dict):
        raise ParityError(f"{path} does not contain one JSON object")
    return value, raw


def artifact(path: Path) -> tuple[dict[str, Any], bytes, str]:
    value, raw = load(path)
    if set(value) != ARTIFACT_FIELDS:
        raise ParityError(f"{path} is not a canonical Native proof artifact")
    if value["schema_version"] != 1 or value["exchange_mode"] != "proof_exchange_json_wire_v1":
        raise ParityError(f"{path} proof artifact protocol drifted")
    proof = value["proof_bytes_hex"]
    if not isinstance(proof, str) or not proof or len(proof) % 2:
        raise ParityError(f"{path} proof payload is invalid")
    try:
        proof_digest = hashlib.sha256(bytes.fromhex(proof)).hexdigest()
    except ValueError as error:
        raise ParityError(f"{path} proof payload is not hex") from error
    return value, raw, proof_digest


def report(path: Path, product_name: str, proof_digest: str) -> tuple[dict[str, Any], bytes]:
    value, raw = load(path)
    identity = validate_canonical_identity(value.get("product_identity"), context=str(path))
    policy = IDENTITY_POLICY.get(product_name)
    if identity["name"] != product_name or policy is None or any(
        identity[field] != expected for field, expected in policy.items()
    ):
        raise ParityError(f"{path} product identity differs from the expected CPU product")
    if value.get("schema_version") != 7 or value.get("backend") != "cpu_native":
        raise ParityError(f"{path} machine report schema/backend drifted")
    if value.get("evidence_class") != "correctness_only" or value.get("profiled") is not False:
        raise ParityError(f"{path} evidence classification drifted")
    proof = value.get("proof")
    if not isinstance(proof, dict) or proof.get("verified_samples") != 1:
        raise ParityError(f"{path} does not bind one locally verified sample")
    samples = proof.get("samples")
    artifact_record = proof.get("artifact")
    if (
        proof.get("all_samples_byte_identical") is not True
        or not isinstance(samples, list) or len(samples) != 1
        or not isinstance(artifact_record, dict)
        or samples[0].get("sha256") != proof_digest
        or artifact_record.get("sha256") != proof_digest
    ):
        raise ParityError(f"{path} proof digest/verification evidence is inconsistent")
    return value, raw


def verify_receipt(
    path: Path, product_name: str, artifact_value: dict[str, Any], proof_digest: str,
) -> tuple[dict[str, Any], bytes]:
    value, raw = load(path)
    if set(value) != VERIFY_FIELDS:
        raise ParityError(f"{path} independent verification receipt fields drifted")
    identity = validate_canonical_identity(value["product"], context=str(path))
    policy = IDENTITY_POLICY.get(product_name)
    if identity["name"] != product_name or policy is None or any(
        identity[field] != expected for field, expected in policy.items()
    ):
        raise ParityError(f"{path} verifier product identity drifted")
    expected = {
        "schema_version": 1,
        "status": "verified",
        "artifact_schema_version": artifact_value["schema_version"],
        "upstream_commit": artifact_value["upstream_commit"],
        "exchange_mode": artifact_value["exchange_mode"],
        "security_policy": "smoke",
        "claimed_generator": artifact_value["generator"],
        "air": artifact_value["example"],
        "proof_bytes": len(bytes.fromhex(artifact_value["proof_bytes_hex"])),
        "proof_sha256": proof_digest,
    }
    if {key: value[key] for key in expected} != expected:
        raise ParityError(f"{path} independent verification result differs from proof")
    return value, raw


def semantic_report(value: dict[str, Any]) -> dict[str, Any]:
    semantic = {key: value[key] for key in SEMANTIC_REPORT_FIELDS}
    identity = validate_canonical_identity(
        value.get("product_identity"), context="semantic product identity",
    )
    semantic["product_identity"] = {
        key: item for key, item in identity.items()
        if key in SHARED_IDENTITY_FIELDS
    }
    proof = dict(semantic["proof"])
    artifact_record = dict(proof["artifact"])
    artifact_record.pop("path", None)
    proof["artifact"] = artifact_record
    semantic["proof"] = proof
    return semantic


def validate(
    *, focused_path: Path, aggregate_path: Path, focused_report_path: Path,
    aggregate_report_path: Path, focused_verify_path: Path, aggregate_verify_path: Path,
) -> dict[str, object]:
    focused, focused_raw, focused_proof = artifact(focused_path)
    aggregate, aggregate_raw, aggregate_proof = artifact(aggregate_path)
    focused_report, focused_report_raw = report(
        focused_report_path, "stwo-native-cpu", focused_proof,
    )
    aggregate_report, aggregate_report_raw = report(
        aggregate_report_path, "stwo-zig", aggregate_proof,
    )
    focused_verify, focused_verify_raw = verify_receipt(
        focused_verify_path, "stwo-native-cpu", focused, focused_proof,
    )
    aggregate_verify, aggregate_verify_raw = verify_receipt(
        aggregate_verify_path, "stwo-zig", aggregate, aggregate_proof,
    )
    if focused != aggregate or focused_raw != aggregate_raw or focused_proof != aggregate_proof:
        raise ParityError("focused and aggregate proof artifacts differ")
    focused_semantic = semantic_report(focused_report)
    aggregate_semantic = semantic_report(aggregate_report)
    if focused_semantic != aggregate_semantic:
        raise ParityError("focused and aggregate statement/protocol/report semantics differ")
    if focused_verify["proof_sha256"] != aggregate_verify["proof_sha256"]:
        raise ParityError("independent verifier receipts differ on proof identity")
    semantic = focused_semantic
    return {
        "schema": "build-architecture-aggregate-parity-v2",
        "status": "PASS",
        "normalization": [
            *[f"product_identity.{field}" for field in PRODUCT_IDENTITY_FIELDS],
            "timing.excluded", "throughput.excluded",
            "proof.artifact.path",
        ],
        "semantic_sha256": hashlib.sha256(
            json.dumps(semantic, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "proof_sha256": focused_proof,
        "artifacts": {
            "focused": hashlib.sha256(focused_raw).hexdigest(),
            "aggregate": hashlib.sha256(aggregate_raw).hexdigest(),
        },
        "reports": {
            "focused": hashlib.sha256(focused_report_raw).hexdigest(),
            "aggregate": hashlib.sha256(aggregate_report_raw).hexdigest(),
        },
        "verify_receipts": {
            "focused": hashlib.sha256(focused_verify_raw).hexdigest(),
            "aggregate": hashlib.sha256(aggregate_verify_raw).hexdigest(),
        },
    }


def validate_receipt(path: Path) -> dict[str, Any]:
    value, _ = load(path)
    if set(value) != PARITY_RECEIPT_FIELDS:
        raise ParityError("aggregate parity receipt fields drifted")
    if value["schema"] != "build-architecture-aggregate-parity-v2" or value["status"] != "PASS":
        raise ParityError("aggregate parity receipt did not pass")
    expected_normalization = [
        *[f"product_identity.{field}" for field in PRODUCT_IDENTITY_FIELDS],
        "timing.excluded", "throughput.excluded",
        "proof.artifact.path",
    ]
    if value["normalization"] != expected_normalization:
        raise ParityError("aggregate parity normalization drifted")
    for field in ("semantic_sha256", "proof_sha256"):
        digest = value[field]
        if not isinstance(digest, str) or len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise ParityError(f"aggregate parity {field} is invalid")
    for field in ("artifacts", "reports", "verify_receipts"):
        digests = value[field]
        if not isinstance(digests, dict) or set(digests) != {"focused", "aggregate"}:
            raise ParityError(f"aggregate parity {field} coverage drifted")
        for digest in digests.values():
            if not isinstance(digest, str) or len(digest) != 64:
                raise ParityError(f"aggregate parity {field} digest is invalid")
    if value["artifacts"]["focused"] != value["artifacts"]["aggregate"]:
        raise ParityError("aggregate parity receipt does not bind equal artifacts")
    return value


def write(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--focused", type=Path, required=True)
    parser.add_argument("--aggregate", type=Path, required=True)
    parser.add_argument("--focused-report", type=Path, required=True)
    parser.add_argument("--aggregate-report", type=Path, required=True)
    parser.add_argument("--focused-verify", type=Path, required=True)
    parser.add_argument("--aggregate-verify", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report_value = validate(
            focused_path=args.focused, aggregate_path=args.aggregate,
            focused_report_path=args.focused_report,
            aggregate_report_path=args.aggregate_report,
            focused_verify_path=args.focused_verify,
            aggregate_verify_path=args.aggregate_verify,
        )
        write(args.output, report_value)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"aggregate parity: FAIL: {error}")
        return 2
    print("aggregate parity: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
