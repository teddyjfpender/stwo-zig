#!/usr/bin/env python3
"""Canonical custody join for one Poseidon Ethereum SegmentV4 leaf.

This module does not prove or verify.  It independently reopens the request,
proof, producer result, fresh-verifier result, executables, and the negative
wrong-source run, then publishes one create-only receipt.  A missing verifier
timing sidecar is represented explicitly and can never become performance
evidence by omission.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import sys
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import ethereum_block_proof_protocol as protocol
from scripts import ethereum_block_proof_store as store


JOIN_SCHEMA = "stwo.ethereum.poseidon-v4-leaf-evidence-join.v1"
REQUEST_SCHEMA = "stwo.ethereum.poseidon-v4-leaf-product-request.v1"
PRODUCER_RESULT_SCHEMA = "stwo.ethereum.poseidon-v4-leaf-producer-result.v1"
VERIFIER_RESULT_SCHEMA = "stwo.ethereum.poseidon-v4-leaf-verifier-result.v1"
VERIFIER_TIMING_SCHEMA = (
    "stwo.ethereum.poseidon-v4-leaf-verifier-timing-receipt.v1"
)
SOURCE_SCHEMA = "stwo.ethereum.block-proof-leaf-stream-source.v2"
DESCRIPTOR_UNAVAILABLE = "verifier_minted_recursive_descriptor_unavailable"
RECURSIVE_SECURITY_IDENTITY = (
    "bc339bc9bcf2d57ed49caccff618e944ddd03b401d528e7b3cb0d2f514306b04"
)
VERIFY_TIMING_SCOPE = "verify-poseidon-v4-artifact-with-capture-v1"
WRONG_SOURCE_CLASSIFICATION = "VerifiedPoseidonSourceMismatch"
WRONG_SOURCE_STDERR = b"error: VerifiedPoseidonSourceMismatch\n"
M31_MODULUS = (1 << 31) - 1
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_TRANSPORT_BYTES = 1024 * 1024

REQUEST_KEYS = {
    "content_sha256", "expected_recursive_statement_sha256",
    "expected_source_public_statement_sha256", "producer_sha256", "schema",
    "segment_index", "session_id", "source_request", "source_segment",
    "verifier_sha256",
}
PRODUCER_RESULT_KEYS = {
    "content_sha256", "descriptor_status", "producer_sha256", "proof",
    "prove_timing", "recursive_admissible", "recursive_statement_sha256",
    "request_sha256", "root_sha256", "schema", "security_identity_sha256",
    "segment_index", "source_public_statement_sha256", "status",
    "transcript_state_sha256", "verified_capture_sha256",
    "verified_link_id_m31_le",
}
VERIFIER_RESULT_KEYS = {
    "content_sha256", "descriptor_status", "fresh_verification", "proof_bytes",
    "proof_sha256", "recursive_admissible", "recursive_statement_sha256",
    "request_sha256", "root_sha256", "schema", "security_identity_sha256",
    "segment_index", "source_public_statement_sha256", "status",
    "transcript_state_sha256", "verified_capture_sha256",
    "verified_link_id_m31_le", "verifier_sha256",
}
VERIFIER_TIMING_KEYS = {
    "content_sha256", "fresh_verification", "proof", "request",
    "request_content_sha256", "schema", "segment_index", "status",
    "timing_scope", "verifier_result", "verifier_sha256", "verify_timing",
}
JOIN_KEYS = {
    "bindings", "content_sha256", "evidence_complete", "files",
    "performance_claim_eligible", "promotion_ready", "recursive_admissible",
    "schema", "status", "timing", "wrong_source_rejection",
}


@dataclass(frozen=True)
class WrongSourceObservation:
    request_path: Path
    exit_code: int
    stdout_path: Path
    stderr_path: Path
    forbidden_result_path: Path
    forbidden_timing_receipt_path: Path


def _absolute(path: Path, where: str) -> Path:
    protocol.require(path.is_absolute() and ".." not in path.parts,
                     f"{where} path is not canonical absolute")
    return path


def _identity(path: Path, where: str, *, allow_empty: bool = False) -> dict[str, Any]:
    path = _absolute(path, where)
    if not allow_empty:
        return {"path": str(path), **store.file_identity(path, where)}
    raw = store.read_regular(path, where, maximum=MAX_TRANSPORT_BYTES)
    return {"path": str(path), "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}


def _json(path: Path, keys: set[str], schema: str, where: str) -> tuple[
    dict[str, Any], dict[str, Any]
]:
    path = _absolute(path, where)
    raw = store.read_regular(path, where, maximum=MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    value = protocol.exact(value, keys, where)
    protocol.require(raw == protocol.canonical_bytes(value),
                     f"{where} is not canonical JSON")
    protocol.require(value["schema"] == schema, f"{where}.schema differs")
    protocol.require(value["content_sha256"] == protocol.content_sha256(value),
                     f"{where} content seal differs")
    return value, {
        "path": str(path), "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _sha(value: Any, where: str) -> str:
    return protocol._sha(value, where)


def _m31(value: Any, where: str) -> str:
    protocol.require(type(value) is str and len(value) == 64, f"{where} differs")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise protocol.ProofProtocolError(f"{where} differs") from error
    protocol.require(value == raw.hex(), f"{where} differs")
    for offset in range(0, len(raw), 4):
        protocol.require(
            int.from_bytes(raw[offset:offset + 4], "little") < M31_MODULUS,
            f"{where} contains a non-canonical M31 limb",
        )
    return value


def _timing(value: Any, where: str) -> dict[str, int]:
    value = protocol.exact(value, {"system_ns", "user_ns", "wall_ns"}, where)
    for field in ("system_ns", "user_ns", "wall_ns"):
        protocol.require(type(value[field]) is int and value[field] >= 0,
                         f"{where}.{field} differs")
    protocol.require(value["wall_ns"] > 0, f"{where}.wall_ns differs")
    return value


def _declared_identity(
    value: Any, actual: dict[str, Any], where: str, *, typed_schema: str | None = None,
) -> dict[str, Any]:
    keys = {"bytes", "path", "sha256"} | ({"schema"} if typed_schema else set())
    value = protocol.exact(value, keys, where)
    if typed_schema is not None:
        protocol.require(value["schema"] == typed_schema, f"{where}.schema differs")
    protocol.require(
        type(value["bytes"]) is int and value["bytes"] > 0
        and type(value["path"]) is str and Path(value["path"]).is_absolute(),
        f"{where} differs",
    )
    _sha(value["sha256"], f"{where}.sha256")
    expected = {key: value[key] for key in ("path", "bytes", "sha256")}
    observed = {key: actual[key] for key in ("path", "bytes", "sha256")}
    protocol.require(expected == observed, f"{where} file identity differs")
    return value


def _validate_request(path: Path, where: str) -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]
]:
    request, request_identity = _json(path, REQUEST_KEYS, REQUEST_SCHEMA, where)
    for field in (
        "content_sha256", "expected_recursive_statement_sha256",
        "expected_source_public_statement_sha256", "producer_sha256", "session_id",
        "verifier_sha256",
    ):
        _sha(request[field], f"{where}.{field}")
    protocol.require(
        type(request["segment_index"]) is int
        and 0 <= request["segment_index"] <= 0xFFFF_FFFF,
        f"{where}.segment_index differs",
    )
    source_request_declaration = protocol.exact(
        request["source_request"], {"bytes", "path", "schema", "sha256"},
        f"{where}.source_request",
    )
    protocol.require(type(source_request_declaration["path"]) is str,
                     f"{where}.source_request.path differs")
    source_request_path = _absolute(Path(source_request_declaration["path"]),
                                    f"{where}.source_request")
    source_request_identity = _identity(
        source_request_path, f"{where}.source_request",
    )
    _declared_identity(
        source_request_declaration, source_request_identity,
        f"{where}.source_request", typed_schema=SOURCE_SCHEMA,
    )
    source_request_identity = {"schema": SOURCE_SCHEMA, **source_request_identity}
    source_segment_declaration = protocol.exact(
        request["source_segment"], {"bytes", "path", "sha256"},
        f"{where}.source_segment",
    )
    protocol.require(type(source_segment_declaration["path"]) is str,
                     f"{where}.source_segment.path differs")
    source_segment_path = _absolute(Path(source_segment_declaration["path"]),
                                    f"{where}.source_segment")
    source_segment_identity = _identity(
        source_segment_path, f"{where}.source_segment",
    )
    _declared_identity(
        source_segment_declaration, source_segment_identity,
        f"{where}.source_segment",
    )
    return request, request_identity, source_request_identity, source_segment_identity


def _validate_results(
    producer_path: Path, verifier_path: Path, request: dict[str, Any],
    proof_identity: dict[str, Any], producer_executable: dict[str, Any],
    verifier_executable: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    producer, producer_identity = _json(
        producer_path, PRODUCER_RESULT_KEYS, PRODUCER_RESULT_SCHEMA, "producer result",
    )
    verifier, verifier_identity = _json(
        verifier_path, VERIFIER_RESULT_KEYS, VERIFIER_RESULT_SCHEMA, "verifier result",
    )
    protocol.require(
        producer["status"] == "proved"
        and producer["descriptor_status"] == DESCRIPTOR_UNAVAILABLE
        and producer["recursive_admissible"] is False,
        "producer result status differs",
    )
    protocol.require(
        verifier["status"] == "verified"
        and verifier["descriptor_status"] == DESCRIPTOR_UNAVAILABLE
        and verifier["fresh_verification"] is True
        and verifier["recursive_admissible"] is False,
        "verifier result status differs",
    )
    producer_proof = _declared_identity(
        producer["proof"], proof_identity, "producer result proof",
    )
    protocol.require(
        {"bytes": verifier["proof_bytes"], "sha256": verifier["proof_sha256"]}
        == {key: proof_identity[key] for key in ("bytes", "sha256")},
        "verifier result proof differs",
    )
    protocol.require(producer_proof["path"] == proof_identity["path"],
                     "producer result proof path differs")
    for field in (
        "recursive_statement_sha256", "request_sha256", "root_sha256",
        "security_identity_sha256", "source_public_statement_sha256",
        "transcript_state_sha256", "verified_capture_sha256",
    ):
        _sha(producer[field], f"producer result.{field}")
        _sha(verifier[field], f"verifier result.{field}")
        protocol.require(producer[field] == verifier[field],
                         f"producer/verifier {field} differs")
    _m31(producer["verified_link_id_m31_le"], "producer verified link")
    _m31(verifier["verified_link_id_m31_le"], "verifier verified link")
    protocol.require(
        producer["verified_link_id_m31_le"] == verifier["verified_link_id_m31_le"],
        "producer/verifier verified link differs",
    )
    protocol.require(
        producer["request_sha256"] == request["content_sha256"]
        and producer["segment_index"] == request["segment_index"]
        and verifier["segment_index"] == request["segment_index"]
        and producer["recursive_statement_sha256"]
        == request["expected_recursive_statement_sha256"]
        and producer["source_public_statement_sha256"]
        == request["expected_source_public_statement_sha256"],
        "result/request authority differs",
    )
    protocol.require(
        producer["producer_sha256"] == request["producer_sha256"]
        == producer_executable["sha256"],
        "producer executable authority differs",
    )
    protocol.require(
        verifier["verifier_sha256"] == request["verifier_sha256"]
        == verifier_executable["sha256"],
        "verifier executable authority differs",
    )
    protocol.require(
        producer["security_identity_sha256"] == RECURSIVE_SECURITY_IDENTITY,
        "recursive security identity differs",
    )
    _timing(producer["prove_timing"], "producer result prove timing")
    return producer, producer_identity, verifier, verifier_identity


def _validate_verifier_timing(
    timing_path: Path | None, request: dict[str, Any], request_identity: dict[str, Any],
    proof_identity: dict[str, Any], verifier_identity: dict[str, Any],
    verifier_executable: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if timing_path is None:
        return None, None
    value, identity = _json(
        timing_path, VERIFIER_TIMING_KEYS, VERIFIER_TIMING_SCHEMA,
        "verifier timing receipt",
    )
    protocol.require(
        value["status"] == "verified" and value["fresh_verification"] is True
        and value["timing_scope"] == VERIFY_TIMING_SCOPE
        and value["segment_index"] == request["segment_index"]
        and value["request_content_sha256"] == request["content_sha256"]
        and value["verifier_sha256"] == verifier_executable["sha256"],
        "verifier timing receipt authority differs",
    )
    for declared, actual, where in (
        (value["request"], request_identity, "verifier timing request"),
        (value["proof"], proof_identity, "verifier timing proof"),
        (value["verifier_result"], verifier_identity, "verifier timing result"),
    ):
        _declared_identity(declared, actual, where)
    _timing(value["verify_timing"], "verifier timing")
    return value, identity


def _require_absent(path: Path, where: str) -> None:
    path = _absolute(path, where)
    store.require_directory(path.parent, f"{where} parent")
    protocol.require(not os.path.lexists(path), f"{where} unexpectedly exists")


def _wrong_source(
    observation: WrongSourceObservation, honest_request: dict[str, Any],
    proof_identity: dict[str, Any], verifier_executable: dict[str, Any],
) -> dict[str, Any]:
    wrong, wrong_identity, _, wrong_segment = _validate_request(
        observation.request_path, "wrong-source request",
    )
    protocol.require(
        wrong["content_sha256"] != honest_request["content_sha256"]
        and wrong["source_segment"]["sha256"]
        != honest_request["source_segment"]["sha256"],
        "wrong-source request does not select an unrelated source",
    )
    for field in ("producer_sha256", "verifier_sha256", "session_id", "source_request"):
        protocol.require(wrong[field] == honest_request[field],
                         f"wrong-source request {field} differs")
    protocol.require(observation.exit_code == 1, "wrong-source exit code differs")
    stdout_raw = store.read_regular(
        _absolute(observation.stdout_path, "wrong-source stdout"),
        "wrong-source stdout", maximum=MAX_TRANSPORT_BYTES,
    )
    stderr_raw = store.read_regular(
        _absolute(observation.stderr_path, "wrong-source stderr"),
        "wrong-source stderr", maximum=MAX_TRANSPORT_BYTES,
    )
    stdout = {"path": str(observation.stdout_path), "bytes": len(stdout_raw),
              "sha256": hashlib.sha256(stdout_raw).hexdigest()}
    stderr = {"path": str(observation.stderr_path), "bytes": len(stderr_raw),
              "sha256": hashlib.sha256(stderr_raw).hexdigest()}
    protocol.require(
        stdout_raw == b"" and stderr_raw == WRONG_SOURCE_STDERR,
        "wrong-source transport differs",
    )
    _require_absent(observation.forbidden_result_path, "wrong-source verifier result")
    _require_absent(
        observation.forbidden_timing_receipt_path,
        "wrong-source verifier timing receipt",
    )
    argv = [
        verifier_executable["path"], "ethereum-poseidon-v4-leaf-verifier",
        "--proof", proof_identity["path"], "--request", wrong_identity["path"],
        "--result", str(observation.forbidden_result_path),
        "--timing-receipt", str(observation.forbidden_timing_receipt_path),
    ]
    return {
        "argv": argv,
        "classification": WRONG_SOURCE_CLASSIFICATION,
        "exit_code": 1,
        "forbidden_result_absent": True,
        "forbidden_result_path": str(observation.forbidden_result_path),
        "forbidden_timing_receipt_absent": True,
        "forbidden_timing_receipt_path": str(
            observation.forbidden_timing_receipt_path
        ),
        "request": wrong_identity,
        "request_content_sha256": wrong["content_sha256"],
        "source_segment": wrong_segment,
        "stderr": stderr,
        "stdout": stdout,
        "verifier_executable": verifier_executable,
    }


def build_receipt(
    *, request_path: Path, proof_path: Path, producer_result_path: Path,
    verifier_result_path: Path, producer_executable_path: Path,
    verifier_executable_path: Path, verifier_timing_receipt_path: Path | None,
    wrong_source: WrongSourceObservation,
) -> dict[str, Any]:
    """Reopen every retained authority and return a sealed canonical join."""
    request, request_identity, source_request, source_segment = _validate_request(
        request_path, "Poseidon leaf request",
    )
    proof = _identity(proof_path, "Poseidon leaf proof")
    producer_executable = _identity(producer_executable_path, "producer executable")
    verifier_executable = _identity(verifier_executable_path, "verifier executable")
    producer, producer_identity, verifier, verifier_identity = _validate_results(
        producer_result_path, verifier_result_path, request, proof,
        producer_executable, verifier_executable,
    )
    verifier_timing, verifier_timing_identity = _validate_verifier_timing(
        verifier_timing_receipt_path, request, request_identity, proof,
        verifier_identity, verifier_executable,
    )
    rejection = _wrong_source(
        wrong_source, request, proof, verifier_executable,
    )
    complete = verifier_timing is not None
    status = (
        "joined_evidence_complete_descriptor_unavailable" if complete
        else "joined_nonpromotable_missing_verifier_timing"
    )
    return protocol.seal({
        "schema": JOIN_SCHEMA,
        "status": status,
        "evidence_complete": complete,
        "performance_claim_eligible": complete,
        "promotion_ready": False,
        "recursive_admissible": False,
        "files": {
            "producer_executable": producer_executable,
            "producer_result": producer_identity,
            "proof": proof,
            "request": request_identity,
            "source_request": source_request,
            "source_segment": source_segment,
            "verifier_executable": verifier_executable,
            "verifier_result": verifier_identity,
            "verifier_timing_receipt": verifier_timing_identity,
        },
        "bindings": {
            "descriptor_status": DESCRIPTOR_UNAVAILABLE,
            "producer_result_content_sha256": producer["content_sha256"],
            "proof_sha256": proof["sha256"],
            "recursive_statement_sha256": producer["recursive_statement_sha256"],
            "request_content_sha256": request["content_sha256"],
            "root_sha256": producer["root_sha256"],
            "security_identity_sha256": producer["security_identity_sha256"],
            "segment_index": request["segment_index"],
            "source_public_statement_sha256": producer[
                "source_public_statement_sha256"
            ],
            "transcript_state_sha256": producer["transcript_state_sha256"],
            "verified_capture_sha256": producer["verified_capture_sha256"],
            "verified_link_id_m31_le": producer["verified_link_id_m31_le"],
            "verifier_result_content_sha256": verifier["content_sha256"],
            "verifier_timing_content_sha256": (
                None if verifier_timing is None
                else verifier_timing["content_sha256"]
            ),
        },
        "timing": {
            "prove": producer["prove_timing"],
            "verify": (
                None if verifier_timing is None
                else verifier_timing["verify_timing"]
            ),
        },
        "wrong_source_rejection": rejection,
    })


def publish_receipt(
    receipt_path: Path, staging_directory: Path, **inputs: Any,
) -> dict[str, Any]:
    receipt_path = _absolute(receipt_path, "join receipt")
    staging_directory = _absolute(staging_directory, "join staging directory")
    store.require_directory(staging_directory, "join staging directory", create=True)
    first = build_receipt(**inputs)
    protocol.require(first == build_receipt(**inputs),
                     "join inputs changed during admission")
    payload = protocol.canonical_bytes(first)
    store.publish_new_or_identical(
        receipt_path, payload, staging_directory=staging_directory,
    )
    return validate_receipt(receipt_path)


def validate_receipt(path: Path) -> dict[str, Any]:
    value, _ = _json(path, JOIN_KEYS, JOIN_SCHEMA, "Poseidon leaf evidence join")
    files = protocol.exact(value["files"], {
        "producer_executable", "producer_result", "proof", "request",
        "source_request", "source_segment", "verifier_executable",
        "verifier_result", "verifier_timing_receipt",
    }, "join files")
    rejection = protocol.exact(value["wrong_source_rejection"], {
        "argv", "classification", "exit_code", "forbidden_result_absent",
        "forbidden_result_path", "forbidden_timing_receipt_absent",
        "forbidden_timing_receipt_path", "request", "request_content_sha256",
        "source_segment", "stderr", "stdout", "verifier_executable",
    }, "wrong-source rejection")
    timing_identity = files["verifier_timing_receipt"]
    protocol.require(timing_identity is None or type(timing_identity) is dict,
                     "join timing receipt identity differs")
    rebuilt = build_receipt(
        request_path=Path(files["request"]["path"]),
        proof_path=Path(files["proof"]["path"]),
        producer_result_path=Path(files["producer_result"]["path"]),
        verifier_result_path=Path(files["verifier_result"]["path"]),
        producer_executable_path=Path(files["producer_executable"]["path"]),
        verifier_executable_path=Path(files["verifier_executable"]["path"]),
        verifier_timing_receipt_path=(
            None if timing_identity is None else Path(timing_identity["path"])
        ),
        wrong_source=WrongSourceObservation(
            request_path=Path(rejection["request"]["path"]),
            exit_code=rejection["exit_code"],
            stdout_path=Path(rejection["stdout"]["path"]),
            stderr_path=Path(rejection["stderr"]["path"]),
            forbidden_result_path=Path(rejection["forbidden_result_path"]),
            forbidden_timing_receipt_path=Path(
                rejection["forbidden_timing_receipt_path"]
            ),
        ),
    )
    protocol.require(value == rebuilt, "Poseidon leaf evidence join replay differs")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    join = subcommands.add_parser("join")
    for name in (
        "request", "proof", "producer-result", "verifier-result",
        "producer-executable", "verifier-executable", "wrong-source-request",
        "wrong-source-stdout", "wrong-source-stderr", "forbidden-result",
        "forbidden-timing-receipt", "receipt", "staging-directory",
    ):
        join.add_argument(f"--{name}", required=True)
    join.add_argument("--verifier-timing-receipt")
    join.add_argument("--wrong-source-exit-code", required=True, type=int)
    replay = subcommands.add_parser("replay")
    replay.add_argument("--receipt", required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if arguments.command == "replay":
        validate_receipt(Path(arguments.receipt).absolute())
        return 0
    publish_receipt(
        Path(arguments.receipt).absolute(),
        Path(arguments.staging_directory).absolute(),
        request_path=Path(arguments.request).absolute(),
        proof_path=Path(arguments.proof).absolute(),
        producer_result_path=Path(arguments.producer_result).absolute(),
        verifier_result_path=Path(arguments.verifier_result).absolute(),
        producer_executable_path=Path(arguments.producer_executable).absolute(),
        verifier_executable_path=Path(arguments.verifier_executable).absolute(),
        verifier_timing_receipt_path=(
            None if arguments.verifier_timing_receipt is None
            else Path(arguments.verifier_timing_receipt).absolute()
        ),
        wrong_source=WrongSourceObservation(
            request_path=Path(arguments.wrong_source_request).absolute(),
            exit_code=arguments.wrong_source_exit_code,
            stdout_path=Path(arguments.wrong_source_stdout).absolute(),
            stderr_path=Path(arguments.wrong_source_stderr).absolute(),
            forbidden_result_path=Path(arguments.forbidden_result).absolute(),
            forbidden_timing_receipt_path=Path(
                arguments.forbidden_timing_receipt
            ).absolute(),
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
