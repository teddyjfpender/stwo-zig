#!/usr/bin/env python3
"""Audit raw RISC-V symbolic-AIR rebindings by exact polynomial semantics.

The symbolic exporter interns an expression DAG.  A source migration may
therefore change node order and raw JSON hashes without changing any AIR
polynomial.  This module deliberately ignores DAG identity and expands every
node into a sparse polynomial over the export's prime field.  It still pins
ordered column metadata, constraints, lookup roles/domains/numerators/tuples,
and the declared count of bus requests outside the row-local model.

This is a migration audit, not a general polynomial optimizer and not a proof
of cross-row lookup closure.  Unsupported JSON shapes fail closed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TEAM_B_FAMILIES = (
    "shifts_reg",
    "shifts_imm",
    "load_store",
    "mul",
    "mulh",
    "div",
)
RECEIPT_KIND = "stwo-riscv-team-b-air-semantic-equivalence"
RECEIPT_SCHEMA_VERSION = 1
SOURCE_REASON = (
    "constraint_program.Builder now constructs each family through its "
    "typed_*_authority.Evaluator. Direct and lookup sections intern the same "
    "field expressions in a different order, changing node IDs and raw JSON "
    "bytes while preserving the ordered row-local polynomial program."
)
SOURCE_PATHS = (
    "src/frontends/riscv/air/constraint_program.zig",
    "src/frontends/riscv/air/extract/program.zig",
    "src/frontends/riscv/air/extract/model.zig",
    "src/frontends/riscv/air/lang/typed_shifts_reg_authority.zig",
    "src/frontends/riscv/air/lang/typed_shifts_imm_authority.zig",
    "src/frontends/riscv/air/lang/typed_load_store_authority.zig",
    "src/frontends/riscv/air/lang/typed_mul_authority.zig",
    "src/frontends/riscv/air/lang/typed_mulh_authority.zig",
    "src/frontends/riscv/air/lang/typed_div_authority.zig",
)

Monomial = tuple[tuple[int, int], ...]
Polynomial = dict[Monomial, int]


class EquivalenceError(RuntimeError):
    """The export or equivalence receipt is malformed or has drifted."""


def _canonical_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_digest(payload: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in payload.items()
                if key != "canonical_digest"}
    return hashlib.sha256(_canonical_bytes(unsigned)).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _integer(value: Any, label: str) -> int:
    if type(value) is not int:
        raise EquivalenceError(f"{label} must be an integer")
    return value


def _load(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EquivalenceError(f"cannot read symbolic AIR at {path}") from exc
    if not isinstance(payload, dict):
        raise EquivalenceError(f"symbolic AIR at {path} is not an object")
    return payload


def _add(left: Polynomial, right: Polynomial, modulus: int, sign: int = 1) -> Polynomial:
    result = dict(left)
    for monomial, coefficient in right.items():
        value = (result.get(monomial, 0) + sign * coefficient) % modulus
        if value:
            result[monomial] = value
        else:
            result.pop(monomial, None)
    return result


def _multiply(left: Polynomial, right: Polynomial, modulus: int) -> Polynomial:
    result: Polynomial = {}
    for left_monomial, left_coefficient in left.items():
        for right_monomial, right_coefficient in right.items():
            exponents: dict[int, int] = {}
            for variable, exponent in left_monomial + right_monomial:
                exponents[variable] = exponents.get(variable, 0) + exponent
            monomial = tuple(sorted(exponents.items()))
            coefficient = (
                result.get(monomial, 0)
                + left_coefficient * right_coefficient
            ) % modulus
            if coefficient:
                result[monomial] = coefficient
            else:
                result.pop(monomial, None)
    return result


def _encoded_polynomial(polynomial: Polynomial) -> list[list[Any]]:
    return [
        [coefficient, [[variable, exponent] for variable, exponent in monomial]]
        for monomial, coefficient in sorted(polynomial.items())
    ]


def semantic_projection(payload: dict[str, Any], expected_family: str | None = None) -> dict[str, Any]:
    required = {
        "family",
        "modulus",
        "notes",
        "unmodelled_bus_requests",
        "columns",
        "nodes",
        "constraints",
        "lookups",
    }
    if set(payload) != required:
        missing = sorted(required - set(payload))
        extra = sorted(set(payload) - required)
        raise EquivalenceError(
            f"symbolic AIR keys drifted; missing={missing}, extra={extra}"
        )
    family = payload["family"]
    if not isinstance(family, str) or not family:
        raise EquivalenceError("symbolic AIR family must be a non-empty string")
    if expected_family is not None and family != expected_family:
        raise EquivalenceError(
            f"symbolic AIR family is {family!r}, expected {expected_family!r}"
        )
    modulus = _integer(payload["modulus"], f"{family} modulus")
    if modulus <= 2:
        raise EquivalenceError(f"{family} modulus is not a supported field")
    notes = payload["notes"]
    if not isinstance(notes, str):
        raise EquivalenceError(f"{family} notes must be a string")
    unmodelled = _integer(
        payload["unmodelled_bus_requests"],
        f"{family} unmodelled_bus_requests",
    )
    if unmodelled < 0:
        raise EquivalenceError(f"{family} has a negative bus-request count")

    columns = payload["columns"]
    if not isinstance(columns, list) or not columns:
        raise EquivalenceError(f"{family} columns must be a non-empty list")
    column_indexes: dict[str, int] = {}
    for index, column in enumerate(columns):
        if (
            not isinstance(column, dict)
            or set(column) != {"name", "role"}
            or not isinstance(column["name"], str)
            or not column["name"]
            or not isinstance(column["role"], str)
            or not column["role"]
        ):
            raise EquivalenceError(f"{family} column {index} is malformed")
        if column["name"] in column_indexes:
            raise EquivalenceError(
                f"{family} repeats column name {column['name']!r}"
            )
        column_indexes[column["name"]] = index

    nodes = payload["nodes"]
    if not isinstance(nodes, list) or not nodes:
        raise EquivalenceError(f"{family} nodes must be a non-empty list")
    polynomials: list[Polynomial] = []

    def argument(node: dict[str, Any], node_index: int, offset: int) -> Polynomial:
        args = node.get("args")
        if not isinstance(args, list) or offset >= len(args):
            raise EquivalenceError(f"{family} node {node_index} has malformed arguments")
        reference = _integer(args[offset], f"{family} node {node_index} argument")
        if reference < 0 or reference >= node_index:
            raise EquivalenceError(
                f"{family} node {node_index} has a non-topological reference"
            )
        return polynomials[reference]

    for node_index, node in enumerate(nodes):
        if not isinstance(node, dict) or not isinstance(node.get("op"), str):
            raise EquivalenceError(f"{family} node {node_index} is malformed")
        op = node["op"]
        if op == "col":
            if set(node) != {"op", "name"} or node.get("name") not in column_indexes:
                raise EquivalenceError(f"{family} column node {node_index} is malformed")
            polynomial = {((column_indexes[node["name"]], 1),): 1}
        elif op == "const":
            if set(node) != {"op", "value"}:
                raise EquivalenceError(f"{family} constant node {node_index} is malformed")
            value = _integer(node["value"], f"{family} constant node {node_index}") % modulus
            polynomial = {(): value} if value else {}
        elif op == "neg":
            if set(node) != {"op", "args"} or len(node["args"]) != 1:
                raise EquivalenceError(f"{family} negation node {node_index} is malformed")
            polynomial = {
                monomial: (-coefficient) % modulus
                for monomial, coefficient in argument(node, node_index, 0).items()
            }
        elif op in {"add", "sub", "mul"}:
            if set(node) != {"op", "args"} or len(node["args"]) != 2:
                raise EquivalenceError(f"{family} binary node {node_index} is malformed")
            left = argument(node, node_index, 0)
            right = argument(node, node_index, 1)
            if op == "add":
                polynomial = _add(left, right, modulus)
            elif op == "sub":
                polynomial = _add(left, right, modulus, -1)
            else:
                polynomial = _multiply(left, right, modulus)
        else:
            raise EquivalenceError(
                f"{family} node {node_index} uses unsupported op {op!r}"
            )
        polynomials.append(polynomial)

    def referenced_polynomial(value: Any, label: str) -> list[list[Any]]:
        reference = _integer(value, label)
        if reference < 0 or reference >= len(polynomials):
            raise EquivalenceError(f"{label} references an absent node")
        return _encoded_polynomial(polynomials[reference])

    constraints = payload["constraints"]
    if not isinstance(constraints, list):
        raise EquivalenceError(f"{family} constraints must be a list")
    normalized_constraints = [
        referenced_polynomial(root, f"{family} constraint {index}")
        for index, root in enumerate(constraints)
    ]

    lookups = payload["lookups"]
    if not isinstance(lookups, list):
        raise EquivalenceError(f"{family} lookups must be a list")
    normalized_lookups: list[dict[str, Any]] = []
    for index, lookup in enumerate(lookups):
        if (
            not isinstance(lookup, dict)
            or set(lookup) != {"label", "domain", "numerator", "tuple"}
            or not isinstance(lookup["label"], str)
            or not isinstance(lookup["domain"], str)
            or not isinstance(lookup["tuple"], list)
        ):
            raise EquivalenceError(f"{family} lookup {index} is malformed")
        normalized_lookups.append({
            "label": lookup["label"],
            "domain": lookup["domain"],
            "numerator": referenced_polynomial(
                lookup["numerator"], f"{family} lookup {index} numerator"
            ),
            "tuple": [
                referenced_polynomial(
                    item, f"{family} lookup {index} tuple item {tuple_index}"
                )
                for tuple_index, item in enumerate(lookup["tuple"])
            ],
        })

    return {
        "family": family,
        "modulus": modulus,
        "notes": notes,
        "unmodelled_bus_requests": unmodelled,
        "columns": columns,
        "constraints": normalized_constraints,
        "lookups": normalized_lookups,
    }


def semantic_digest(payload: dict[str, Any], expected_family: str | None = None) -> str:
    return hashlib.sha256(
        _canonical_bytes(semantic_projection(payload, expected_family))
    ).hexdigest()


def _family_record(family: str, baseline_path: Path, candidate_path: Path) -> dict[str, Any]:
    baseline = _load(baseline_path)
    candidate = _load(candidate_path)
    baseline_projection = semantic_projection(baseline, family)
    candidate_projection = semantic_projection(candidate, family)
    if baseline_projection != candidate_projection:
        differing = [
            key for key in baseline_projection
            if baseline_projection[key] != candidate_projection[key]
        ]
        raise EquivalenceError(
            f"{family} semantic projection drifted in {', '.join(differing)}"
        )
    normalized_digest = hashlib.sha256(
        _canonical_bytes(candidate_projection)
    ).hexdigest()
    return {
        "family": family,
        "baseline_raw_sha256": sha256_file(baseline_path),
        "candidate_raw_sha256": sha256_file(candidate_path),
        "baseline_semantic_sha256": normalized_digest,
        "candidate_semantic_sha256": normalized_digest,
        "column_count": len(candidate["columns"]),
        "node_count": {
            "baseline": len(baseline["nodes"]),
            "candidate": len(candidate["nodes"]),
        },
        "constraint_count": len(candidate["constraints"]),
        "lookup_count": len(candidate["lookups"]),
        "unmodelled_bus_requests": candidate["unmodelled_bus_requests"],
    }


def build_receipt(baseline_dir: Path, candidate_dir: Path) -> dict[str, Any]:
    records = [
        _family_record(
            family,
            baseline_dir / f"{family}.json",
            candidate_dir / f"{family}.json",
        )
        for family in TEAM_B_FAMILIES
    ]
    sources = []
    for relative in SOURCE_PATHS:
        path = REPOSITORY_ROOT / relative
        if not path.is_file():
            raise EquivalenceError(f"typed migration source is absent at {relative}")
        sources.append({"path": relative, "sha256": sha256_file(path)})
    payload: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "kind": RECEIPT_KIND,
        "claim_boundary": {
            "ordered_column_metadata_equal": True,
            "ordered_constraint_polynomials_equal": True,
            "ordered_lookup_roles_domains_numerators_tuples_equal": True,
            "unmodelled_bus_request_counts_equal": True,
            "field_coefficients_reduced_modulo_exported_prime": True,
            "witness_generation_equivalence": False,
            "cross_row_or_multiset_closure": False,
            "sail_semantic_equivalence": False,
        },
        "source_transition": {
            "reason": SOURCE_REASON,
            "files": sources,
        },
        "families": records,
    }
    payload["canonical_digest"] = canonical_digest(payload)
    return payload


def write_receipt(receipt: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def check_receipt(receipt_path: Path, candidate_dir: Path) -> str:
    receipt = _load(receipt_path)
    if receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION or receipt.get("kind") != RECEIPT_KIND:
        raise EquivalenceError("semantic-equivalence receipt identity drifted")
    if receipt.get("canonical_digest") != canonical_digest(receipt):
        raise EquivalenceError("semantic-equivalence receipt digest mismatch")
    boundary = receipt.get("claim_boundary")
    required_true = {
        "ordered_column_metadata_equal",
        "ordered_constraint_polynomials_equal",
        "ordered_lookup_roles_domains_numerators_tuples_equal",
        "unmodelled_bus_request_counts_equal",
        "field_coefficients_reduced_modulo_exported_prime",
    }
    required_false = {
        "witness_generation_equivalence",
        "cross_row_or_multiset_closure",
        "sail_semantic_equivalence",
    }
    if (
        not isinstance(boundary, dict)
        or any(boundary.get(key) is not True for key in required_true)
        or any(boundary.get(key) is not False for key in required_false)
    ):
        raise EquivalenceError("semantic-equivalence claim boundary drifted")
    transition = receipt.get("source_transition")
    if not isinstance(transition, dict) or transition.get("reason") != SOURCE_REASON:
        raise EquivalenceError("semantic-equivalence source reason drifted")
    source_records = transition.get("files")
    if (
        not isinstance(source_records, list)
        or any(not isinstance(item, dict) for item in source_records)
        or [item.get("path") for item in source_records if isinstance(item, dict)]
        != list(SOURCE_PATHS)
        or any(
            not isinstance(item.get("sha256"), str)
            or len(item["sha256"]) != 64
            for item in source_records
        )
    ):
        raise EquivalenceError("semantic-equivalence source inventory drifted")

    records = receipt.get("families")
    if not isinstance(records, list) or [
        item.get("family") for item in records if isinstance(item, dict)
    ] != list(TEAM_B_FAMILIES):
        raise EquivalenceError("semantic-equivalence family inventory drifted")
    for record in records:
        family = record["family"]
        path = candidate_dir / f"{family}.json"
        candidate = _load(path)
        raw = sha256_file(path)
        normalized = semantic_digest(candidate, family)
        if record.get("candidate_raw_sha256") != raw:
            raise EquivalenceError(f"{family} typed raw AIR digest drifted")
        if (
            record.get("baseline_semantic_sha256") != normalized
            or record.get("candidate_semantic_sha256") != normalized
        ):
            raise EquivalenceError(f"{family} polynomial semantics drifted")
        if record.get("baseline_raw_sha256") == raw:
            raise EquivalenceError(f"{family} receipt does not describe a raw-DAG rebind")
        if (
            record.get("column_count") != len(candidate["columns"])
            or record.get("constraint_count") != len(candidate["constraints"])
            or record.get("lookup_count") != len(candidate["lookups"])
            or record.get("unmodelled_bus_requests")
            != candidate["unmodelled_bus_requests"]
        ):
            raise EquivalenceError(f"{family} recorded AIR geometry drifted")
    return (
        f"team B typed-AIR rebind: {len(records)} raw exports preserve exact "
        "ordered polynomial constraints and lookups"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture = subparsers.add_parser("capture")
    capture.add_argument("--baseline-dir", type=Path, required=True)
    capture.add_argument("--candidate-dir", type=Path, required=True)
    capture.add_argument("--output", type=Path, required=True)
    check = subparsers.add_parser("check")
    check.add_argument("--candidate-dir", type=Path, required=True)
    check.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            receipt = build_receipt(args.baseline_dir, args.candidate_dir)
            write_receipt(receipt, args.output)
            print(
                f"captured {len(receipt['families'])} exact polynomial AIR rebindings "
                f"to {args.output}"
            )
        else:
            print(check_receipt(args.receipt, args.candidate_dir))
    except EquivalenceError as error:
        print(f"AIR equivalence audit failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
