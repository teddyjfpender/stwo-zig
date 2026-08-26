"""Fail-closed node-layout normalization for formal AIR program inputs.

The production symbolic scalar hash-conses expression nodes in first-use
order. Moving an algebraically identical helper between the direct and lookup
recipes can therefore renumber the DAG even when every expression and event is
structurally unchanged. Lean bridge proofs intentionally pin node indices, so
the formal package normalizes such exports to one reviewed topological layout.

Normalization is deliberately stricter than polynomial equivalence. A
candidate must contain exactly the reviewed set of recursively hashed
expression trees, and after reindexing its complete unsigned AIR IR v2 object
must have the reviewed canonical byte digest. Constraint order, lookup order,
roles, tuples, projections, columns, and fixed-table identities are therefore
all part of the admission decision. Source identity is attached only after
this check and continues to bind the live typed implementation.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Mapping

from . import codec
from .air_program_contract import OPCODES
from .model import RefinementError


RECEIPT_SCHEMA_VERSION = 1
RECEIPT_KIND = "stwo-riscv-air-program-node-layout"
RECEIPT_RELATIVE_PATH = Path(
    "formal/riscv-refinement/air-program-node-layout-v1.json"
)
MNEMONICS = tuple(mnemonic for _, mnemonic, _ in OPCODES)


class LayoutError(RefinementError):
    """A layout receipt or candidate AIR program is malformed or drifted."""


def _sha256_object(value: Any) -> str:
    return codec.sha256_bytes(codec.canonical_bytes(value))


def _unsigned(payload: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(dict(payload))
    result.pop("content_digest", None)
    result.pop("source_identity", None)
    return result


def _node_digests(nodes: Any, context: str) -> list[str]:
    if not isinstance(nodes, list) or not nodes:
        raise LayoutError(f"{context}.nodes must be a nonempty array")
    result: list[str] = []
    for index, raw in enumerate(nodes):
        label = f"{context}.nodes[{index}]"
        if not isinstance(raw, dict) or not isinstance(raw.get("op"), str):
            raise LayoutError(f"{label} must be an expression object")
        operation = raw["op"]
        if operation == "col":
            if set(raw) != {"op", "column"} or type(raw["column"]) is not int:
                raise LayoutError(f"{label} malformed column node")
            structural = {"column": raw["column"], "op": operation}
        elif operation == "const":
            if set(raw) != {"op", "value"} or type(raw["value"]) is not int:
                raise LayoutError(f"{label} malformed constant node")
            structural = {"op": operation, "value": raw["value"]}
        elif operation in {"neg", "add", "sub", "mul"}:
            arguments = raw.get("args")
            arity = 1 if operation == "neg" else 2
            if (
                set(raw) != {"op", "args"}
                or not isinstance(arguments, list)
                or len(arguments) != arity
                or any(type(argument) is not int for argument in arguments)
                or any(argument < 0 or argument >= index for argument in arguments)
            ):
                raise LayoutError(f"{label} malformed or non-topological {operation} node")
            structural = {
                "args": [result[argument] for argument in arguments],
                "op": operation,
            }
        else:
            raise LayoutError(f"{label} has unsupported operation {operation!r}")
        result.append(_sha256_object(structural))
    if len(result) != len(set(result)):
        raise LayoutError(
            f"{context}.nodes are not structurally hash-consed or a digest collided"
        )
    return result


def _receipt_digest(receipt: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in receipt.items()
                if key != "canonical_digest"}
    return _sha256_object(unsigned)


def build_receipt(
    reviewed: Mapping[str, Mapping[str, Any]],
    reviewed_revision: str,
) -> dict[str, Any]:
    """Build a receipt from reviewed signed or unsigned selector programs."""
    if tuple(sorted(reviewed)) != tuple(sorted(MNEMONICS)):
        raise LayoutError("reviewed AIR program inventory is not exactly RV32IM")
    if (
        not isinstance(reviewed_revision, str)
        or len(reviewed_revision) != 40
        or any(character not in "0123456789abcdef" for character in reviewed_revision)
    ):
        raise LayoutError("reviewed revision must be a lowercase Git object ID")
    programs: list[dict[str, Any]] = []
    for mnemonic in MNEMONICS:
        payload = _unsigned(reviewed[mnemonic])
        selector = payload.get("opcode_selector")
        if not isinstance(selector, dict) or selector.get("mnemonic") != mnemonic:
            raise LayoutError(f"{mnemonic} reviewed selector identity drifted")
        nodes = payload.get("nodes")
        digests = _node_digests(nodes, mnemonic)
        events = payload.get("events")
        if not isinstance(events, list):
            raise LayoutError(f"{mnemonic}.events must be an array")
        programs.append({
            "event_count": len(events),
            "family": payload.get("family"),
            "mnemonic": mnemonic,
            "node_count": len(digests),
            "ordered_node_structural_sha256": digests,
            "unsigned_canonical_sha256": _sha256_object(payload),
        })
    receipt: dict[str, Any] = {
        "kind": RECEIPT_KIND,
        "programs": programs,
        "reviewed_revision": reviewed_revision,
        "schema_version": RECEIPT_SCHEMA_VERSION,
    }
    receipt["canonical_digest"] = _receipt_digest(receipt)
    validate_receipt(receipt)
    return receipt


def validate_receipt(receipt: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(receipt, dict) or set(receipt) != {
        "canonical_digest",
        "kind",
        "programs",
        "reviewed_revision",
        "schema_version",
    }:
        raise LayoutError("node-layout receipt schema drifted")
    if (
        receipt["schema_version"] != RECEIPT_SCHEMA_VERSION
        or receipt["kind"] != RECEIPT_KIND
        or receipt["canonical_digest"] != _receipt_digest(receipt)
    ):
        raise LayoutError("node-layout receipt identity or digest drifted")
    revision = receipt["reviewed_revision"]
    if (
        not isinstance(revision, str)
        or len(revision) != 40
        or any(character not in "0123456789abcdef" for character in revision)
    ):
        raise LayoutError("node-layout reviewed revision drifted")
    programs = receipt["programs"]
    if not isinstance(programs, list) or [
        item.get("mnemonic") for item in programs if isinstance(item, dict)
    ] != list(MNEMONICS):
        raise LayoutError("node-layout program inventory or order drifted")
    by_mnemonic: dict[str, dict[str, Any]] = {}
    for item in programs:
        if not isinstance(item, dict) or set(item) != {
            "event_count",
            "family",
            "mnemonic",
            "node_count",
            "ordered_node_structural_sha256",
            "unsigned_canonical_sha256",
        }:
            raise LayoutError("node-layout program record schema drifted")
        mnemonic = item["mnemonic"]
        digests = item["ordered_node_structural_sha256"]
        if (
            not isinstance(item["family"], str)
            or type(item["node_count"]) is not int
            or item["node_count"] <= 0
            or type(item["event_count"]) is not int
            or item["event_count"] <= 0
            or not isinstance(digests, list)
            or len(digests) != item["node_count"]
            or len(digests) != len(set(digests))
            or any(
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
                for digest in digests
            )
            or not isinstance(item["unsigned_canonical_sha256"], str)
            or len(item["unsigned_canonical_sha256"]) != 64
            or any(
                character not in "0123456789abcdef"
                for character in item["unsigned_canonical_sha256"]
            )
        ):
            raise LayoutError(f"{mnemonic} node-layout record is malformed")
        by_mnemonic[mnemonic] = item
    return by_mnemonic


def load_receipt(path: Path) -> dict[str, Any]:
    try:
        receipt = codec.load_json(path)
    except (OSError, UnicodeError, ValueError) as exc:
        raise LayoutError(f"cannot read node-layout receipt {path}") from exc
    validate_receipt(receipt)
    return receipt


def _remap_reference(
    value: Any,
    mapping: Mapping[int, int],
    context: str,
) -> int:
    if type(value) is not int or value not in mapping:
        raise LayoutError(f"{context} is not a reviewed node reference")
    return mapping[value]


def _normalize_with_record(
    candidate: Mapping[str, Any],
    mnemonic: str,
    record: Mapping[str, Any],
) -> dict[str, Any]:
    if "content_digest" in candidate or "source_identity" in candidate:
        raise LayoutError(f"{mnemonic} layout normalization requires unsigned AIR")
    payload = copy.deepcopy(dict(candidate))
    selector = payload.get("opcode_selector")
    if (
        not isinstance(selector, dict)
        or selector.get("mnemonic") != mnemonic
        or payload.get("family") != record["family"]
    ):
        raise LayoutError(f"{mnemonic} selector or family identity drifted")
    events = payload.get("events")
    if not isinstance(events, list) or len(events) != record["event_count"]:
        raise LayoutError(f"{mnemonic} event geometry drifted")

    nodes = payload.get("nodes")
    candidate_digests = _node_digests(nodes, mnemonic)
    target_digests = record["ordered_node_structural_sha256"]
    if (
        len(candidate_digests) != record["node_count"]
        or set(candidate_digests) != set(target_digests)
    ):
        raise LayoutError(f"{mnemonic} structural expression set drifted")
    candidate_index = {
        digest: index for index, digest in enumerate(candidate_digests)
    }
    candidate_to_target = {
        candidate_index[digest]: target_index
        for target_index, digest in enumerate(target_digests)
    }

    normalized_nodes: list[dict[str, Any]] = []
    for target_index, digest in enumerate(target_digests):
        node = copy.deepcopy(nodes[candidate_index[digest]])
        if "args" in node:
            node["args"] = [
                _remap_reference(argument, candidate_to_target, f"{mnemonic}.nodes")
                for argument in node["args"]
            ]
            if any(argument >= target_index for argument in node["args"]):
                raise LayoutError(f"{mnemonic} reviewed node layout is not topological")
        normalized_nodes.append(node)
    payload["nodes"] = normalized_nodes
    payload["active_row"] = _remap_reference(
        payload.get("active_row"), candidate_to_target,
        f"{mnemonic}.active_row",
    )

    for ordinal, event in enumerate(events):
        if not isinstance(event, dict):
            raise LayoutError(f"{mnemonic}.events[{ordinal}] is malformed")
        if event.get("kind") == "constraint":
            event["root"] = _remap_reference(
                event.get("root"), candidate_to_target,
                f"{mnemonic}.events[{ordinal}].root",
            )
        elif event.get("kind") == "lookup":
            event["numerator"] = _remap_reference(
                event.get("numerator"), candidate_to_target,
                f"{mnemonic}.events[{ordinal}].numerator",
            )
            values = event.get("tuple")
            if not isinstance(values, list):
                raise LayoutError(f"{mnemonic}.events[{ordinal}].tuple is malformed")
            event["tuple"] = [
                _remap_reference(
                    value, candidate_to_target,
                    f"{mnemonic}.events[{ordinal}].tuple",
                )
                for value in values
            ]
        else:
            raise LayoutError(f"{mnemonic}.events[{ordinal}] has unknown kind")

    selector["expression"] = _remap_reference(
        selector.get("expression"), candidate_to_target,
        f"{mnemonic}.opcode_selector.expression",
    )
    projection = payload.get("projection")
    if not isinstance(projection, dict):
        raise LayoutError(f"{mnemonic}.projection is malformed")
    projection["next_pc"] = _remap_reference(
        projection.get("next_pc"), candidate_to_target,
        f"{mnemonic}.projection.next_pc",
    )
    observed = _sha256_object(payload)
    if observed != record["unsigned_canonical_sha256"]:
        raise LayoutError(
            f"{mnemonic} normalized unsigned AIR differs from reviewed bytes"
        )
    return payload


def normalize(
    candidate: Mapping[str, Any],
    mnemonic: str,
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Reindex a structurally exact candidate to its reviewed node layout."""
    records = validate_receipt(receipt)
    try:
        record = records[mnemonic]
    except KeyError as exc:
        raise LayoutError(f"unknown node-layout mnemonic {mnemonic}") from exc
    return _normalize_with_record(candidate, mnemonic, record)


def normalize_inventory(
    candidates: Mapping[str, Mapping[str, Any]],
    receipt: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    if tuple(sorted(candidates)) != tuple(sorted(MNEMONICS)):
        raise LayoutError("candidate AIR program inventory is not exactly RV32IM")
    records = validate_receipt(receipt)
    return {
        mnemonic: _normalize_with_record(
            candidates[mnemonic],
            mnemonic,
            records[mnemonic],
        )
        for mnemonic in MNEMONICS
    }
