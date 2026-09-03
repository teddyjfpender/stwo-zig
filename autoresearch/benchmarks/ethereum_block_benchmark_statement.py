"""Typed benchmark-statement and recursive-root binding authority."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


STATEMENT_SCHEMA = "stwo.ethereum.cross-system-statement-authority.v1"
BINDING_SCHEMA = "stwo.ethereum.block-proof-statement-binding.v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class StatementAuthorityError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise StatementAuthorityError(message)


def _exact(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys, f"{where} keys differ")
    return value


def _transport(value: Any, where: str) -> dict[str, Any]:
    value = _exact(value, {"bytes", "sha256", "framing"}, where)
    _require(type(value["bytes"]) is int and value["bytes"] > 0,
             f"{where} bytes differ")
    _require(type(value["sha256"]) is str and SHA256.fullmatch(value["sha256"]),
             f"{where} sha256 differs")
    _require(type(value["framing"]) is str and value["framing"],
             f"{where} framing differs")
    return value


def sealed_sha256(value: dict[str, Any]) -> str:
    unsigned = dict(value)
    unsigned.pop("content_sha256", None)
    encoded = (json.dumps(
        unsigned, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ) + "\n").encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def validate_binding(
    value: Any, expected_benchmark_statement_sha256: str, where: str,
) -> dict[str, Any]:
    value = _exact(value, {
        "schema", "benchmark_statement_sha256", "proved_root_statement_sha256",
        "block_authority_sha256", "elf", "input", "expected_output",
        "source_request_sha256", "matched_guest_statement_reproduced",
        "content_sha256",
    }, where)
    _require(value["schema"] == BINDING_SCHEMA, f"{where}.schema differs")
    for field in (
        "benchmark_statement_sha256", "proved_root_statement_sha256",
        "block_authority_sha256", "source_request_sha256", "content_sha256",
    ):
        _require(type(value[field]) is str and SHA256.fullmatch(value[field]),
                 f"{where}.{field} differs")
    _require(value["benchmark_statement_sha256"]
             == expected_benchmark_statement_sha256,
             f"{where}.benchmark_statement_sha256 differs")
    for field in ("elf", "input", "expected_output"):
        identity = _exact(value[field], {"path", "bytes", "sha256"},
                          f"{where}.{field}")
        _require(type(identity["path"]) is str and identity["path"]
                 and type(identity["bytes"]) is int and identity["bytes"] > 0
                 and type(identity["sha256"]) is str
                 and SHA256.fullmatch(identity["sha256"]),
                 f"{where}.{field} differs")
    _require(type(value["matched_guest_statement_reproduced"]) is bool,
             f"{where}.matched_guest_statement_reproduced differs")
    _require(value["content_sha256"] == sealed_sha256(value),
             f"{where}.content_sha256 differs")
    return value


def validate_statement(
    statement: Any, statement_sha256: str, manifest: dict[str, Any], where: str,
) -> dict[str, Any]:
    statement = _exact(statement, {
        "schema", "block", "inputs", "outputs", "matched_guest_statement_reproduced",
    }, where)
    _require(statement["schema"] == STATEMENT_SCHEMA, f"{where}.schema differs")
    block = manifest["block"]
    block_fields = (
        "chain_id", "number", "hash", "parent_hash", "state_root", "transactions_root",
        "receipts_root", "withdrawals_root", "requests_hash", "transaction_count",
        "gas_used", "timestamp",
    )
    _require(statement["block"] == {field: block[field] for field in block_fields},
             "benchmark block authority differs")
    inputs = _exact(statement["inputs"], {
        "equivalence_status", "zisk_transport", "stwo_transport",
    }, f"{where}.inputs")
    _require(inputs["equivalence_status"]
             == "codec-specific-projections-not-yet-cross-verified",
             "benchmark input equivalence is overstated")
    fixture = manifest["zisk"]["fixture"]
    projection = manifest["stwo"]["semantic_projection"]
    _require(_transport(inputs["zisk_transport"], "benchmark ZisK input") == {
        "bytes": fixture["bytes"], "sha256": fixture["sha256"],
        "framing": "zisk-stdin-u64le-frames-bincode-v2",
    }, "benchmark ZisK input authority differs")
    _require(_transport(inputs["stwo_transport"], "benchmark Stwo input")
             == projection["stwo_runner_input"],
             "benchmark Stwo input authority differs")
    outputs = _exact(statement["outputs"], {
        "equivalence_status", "zisk_transport", "stwo_transport",
    }, f"{where}.outputs")
    _require(outputs["equivalence_status"]
             == "different-public-meanings-not-yet-normalized",
             "benchmark output equivalence is overstated")
    _require(_transport(outputs["zisk_transport"], "benchmark ZisK output")
             == manifest["zisk"]["execution"]["output"],
             "benchmark ZisK output authority differs")
    host = projection["host_validation"]
    _require(_transport(outputs["stwo_transport"], "benchmark Stwo output") == {
        "bytes": host["output_bytes"], "sha256": host["output_sha256"],
        "framing": "payload-request-root-plus-success-chain-and-schema",
    }, "benchmark Stwo output authority differs")
    _require(statement["matched_guest_statement_reproduced"] is False,
             "benchmark statement match is not yet evidenced")
    encoded = json.dumps(
        statement, ensure_ascii=True, separators=(",", ":"),
    ).encode("ascii")
    _require(statement_sha256 == hashlib.sha256(encoded).hexdigest(),
             "benchmark statement digest differs")
    return statement
