#!/usr/bin/env python3
"""Machine-check the sparse-Merkle index and depth recurrences.

The production Merkle bus exposes children at ``index`` and ``index + 1`` and
consumes their parent at ``index / 2, depth - 1``.  Following one child from a
root therefore applies

    child_index = 2 * parent_index + path_bit.

This module checks, by a 30-step symbolic induction, that a path rooted at
index zero reaches exactly the integer represented by its 30 path bits and
never wraps M31.  It also computes the additive order of the depth step ``-1``:
a detached cycle needs exactly p edges and p distinct depths.  The production
statement guard admits fewer than p Merkle rows, so such a cycle cannot fit.

Run from the repository root:

    python3 -m scripts.riscv_merkle_recurrence
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import math
import re
from collections.abc import Iterable, Sequence
from pathlib import Path


M31_MODULUS = (1 << 31) - 1
MERKLE_PATH_DEPTH = 30


@dataclasses.dataclass(frozen=True)
class ReachableInterval:
    """Exact canonical indices reachable after one prefix length."""

    prefix_bits: int
    minimum: int
    maximum: int
    count: int


@dataclasses.dataclass(frozen=True)
class IndexCertificate:
    root_index: int
    path_depth: int
    binary_weights: tuple[int, ...]
    minimum_leaf_index: int
    maximum_leaf_index: int
    reachable_leaf_indices: int
    field_modulus: int
    canonical_without_wrap: bool
    parity_is_path_bit: bool


@dataclasses.dataclass(frozen=True)
class DepthCycleCertificate:
    field_modulus: int
    depth_step: int
    step_modulus_gcd: int
    minimum_positive_cycle_rows: int
    distinct_depths_before_repeat: int
    statement_row_limit_exclusive: int
    maximum_admitted_rows: int
    detached_cycle_excluded: bool


@dataclasses.dataclass(frozen=True)
class ProductionContract:
    m31_source: str
    merkle_relation_source: str
    admission_source: str
    source_modulus: int
    source_inverse_two: int
    child_recurrence: str
    depth_recurrence: str
    admission_rule: str


def _checked_bit(value: int) -> int:
    if value not in (0, 1):
        raise ValueError(f"path bit must be 0 or 1, got {value!r}")
    return value


def fold_path(
    path_bits_root_to_leaf: Iterable[int],
    *,
    modulus: int | None = None,
) -> int:
    """Apply ``index <- 2 * index + bit`` from root index zero."""

    if modulus is not None and modulus <= 1:
        raise ValueError("modulus must be greater than one")
    index = 0
    for value in path_bits_root_to_leaf:
        bit = _checked_bit(value)
        index = 2 * index + bit
        if modulus is not None:
            index %= modulus
    return index


def binary_weights(depth: int) -> tuple[int, ...]:
    """Symbolically fold bits, returning their root-to-leaf coefficients."""

    if depth < 0:
        raise ValueError("depth must be non-negative")
    weights: tuple[int, ...] = ()
    for _ in range(depth):
        weights = tuple(2 * weight for weight in weights) + (1,)
    expected = tuple(1 << shift for shift in range(depth - 1, -1, -1))
    if weights != expected:
        raise AssertionError("symbolic path fold is not the binary place-value fold")
    return weights


def reachable_intervals(depth: int) -> tuple[ReachableInterval, ...]:
    """Inductively certify the exact set ``[0, 2**k)`` at every prefix.

    If the current set is every integer from 0 through n, its two children are
    the adjacent pairs ``(0, 1), (2, 3), ..., (2n, 2n + 1)``.  Thus checking
    the endpoints and doubled cardinality is a compact check over all paths.
    """

    if depth < 0:
        raise ValueError("depth must be non-negative")
    levels = [ReachableInterval(0, 0, 0, 1)]
    for prefix_bits in range(1, depth + 1):
        previous = levels[-1]
        current = ReachableInterval(
            prefix_bits=prefix_bits,
            minimum=2 * previous.minimum,
            maximum=2 * previous.maximum + 1,
            count=2 * previous.count,
        )
        expected_count = 1 << prefix_bits
        if (
            current.minimum != 0
            or current.maximum != expected_count - 1
            or current.count != expected_count
            or current.maximum - current.minimum + 1 != current.count
        ):
            raise AssertionError("binary child recurrence did not remain contiguous")
        levels.append(current)
    return tuple(levels)


def decode_leaf_index(leaf_index: int, depth: int) -> tuple[int, ...]:
    """Recover the unique root-to-leaf bits, exposing parity at every step."""

    if depth < 0:
        raise ValueError("depth must be non-negative")
    if not 0 <= leaf_index < (1 << depth):
        raise ValueError(f"leaf index must lie in [0, 2**{depth})")
    index = leaf_index
    leaf_to_root: list[int] = []
    for _ in range(depth):
        parent, path_bit = divmod(index, 2)
        leaf_to_root.append(path_bit)
        index = parent
    if index != 0:
        raise AssertionError("decoded path did not terminate at root index zero")
    return tuple(reversed(leaf_to_root))


def index_certificate(
    depth: int = MERKLE_PATH_DEPTH,
    modulus: int = M31_MODULUS,
) -> IndexCertificate:
    """Build the all-path index certificate for root index zero."""

    weights = binary_weights(depth)
    final = reachable_intervals(depth)[-1]
    # Every integer parent is congruent to 0 or 1 modulo two, so these four
    # cases exhaust the parity identity for both possible path bits.
    parity_is_path_bit = all(
        (2 * parent_residue + bit) % 2 == bit
        for parent_residue in (0, 1)
        for bit in (0, 1)
    )
    certificate = IndexCertificate(
        root_index=0,
        path_depth=depth,
        binary_weights=weights,
        minimum_leaf_index=final.minimum,
        maximum_leaf_index=final.maximum,
        reachable_leaf_indices=final.count,
        field_modulus=modulus,
        canonical_without_wrap=final.maximum < modulus,
        parity_is_path_bit=parity_is_path_bit,
    )
    if not certificate.canonical_without_wrap:
        raise AssertionError(
            f"depth-{depth} paths can wrap modulus {modulus}; "
            f"maximum index is {final.maximum}"
        )
    if not certificate.parity_is_path_bit:
        raise AssertionError("child parity is not the selected path bit")
    return certificate


def additive_order(step: int, modulus: int) -> int:
    """Return the additive order of ``step`` in the integers modulo modulus."""

    if modulus <= 1:
        raise ValueError("modulus must be greater than one")
    return modulus // math.gcd(step % modulus, modulus)


def depth_after_rows(start_depth: int, n_rows: int, modulus: int) -> int:
    """Apply the production depth decrement for ``n_rows`` active rows."""

    if n_rows < 0:
        raise ValueError("row count must be non-negative")
    if modulus <= 1:
        raise ValueError("modulus must be greater than one")
    return (start_depth - n_rows) % modulus


def depth_cycle_certificate(
    modulus: int = M31_MODULUS,
    statement_row_limit_exclusive: int = M31_MODULUS,
) -> DepthCycleCertificate:
    """Certify the minimum detached cycle and compare it with admission.

    Two positions ``a < b`` in a depth walk collide exactly when
    ``(b - a) * (-1) == 0 mod p``.  The smallest positive difference is the
    additive order of ``-1``.  Consequently all depths before that first
    return are distinct.  A row carries one depth and a cycle has one active
    row per edge, so p distinct depths require at least p active rows.
    """

    step = -1
    divisor = math.gcd(step % modulus, modulus)
    order = additive_order(step, modulus)
    certificate = DepthCycleCertificate(
        field_modulus=modulus,
        depth_step=step,
        step_modulus_gcd=divisor,
        minimum_positive_cycle_rows=order,
        distinct_depths_before_repeat=order,
        statement_row_limit_exclusive=statement_row_limit_exclusive,
        maximum_admitted_rows=statement_row_limit_exclusive - 1,
        detached_cycle_excluded=(statement_row_limit_exclusive - 1) < order,
    )
    if depth_after_rows(0, order, modulus) != 0:
        raise AssertionError("computed additive order does not close the depth walk")
    if not certificate.detached_cycle_excluded:
        raise AssertionError("statement row bound does not exclude a depth cycle")
    return certificate


def _compact(source: str) -> str:
    return " ".join(source.split())


def check_production_contract(repo_root: Path) -> ProductionContract:
    """Bind the arithmetic certificate to the exact shipped Zig recurrences."""

    m31_path = repo_root / "src/core/fields/m31.zig"
    merkle_path = (
        repo_root
        / "src/frontends/riscv/air/memory_commitment/merkle_node.zig"
    )
    admission_path = (
        repo_root / "src/frontends/riscv/prover/statement_validation.zig"
    )
    m31_source = m31_path.read_text(encoding="utf-8")
    merkle_source = _compact(merkle_path.read_text(encoding="utf-8"))
    admission_source = _compact(admission_path.read_text(encoding="utf-8"))

    match = re.search(
        r"pub const Modulus:\s*u32\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)\s*;",
        m31_source,
    )
    if match is None:
        raise AssertionError("could not locate the production M31 modulus")
    source_modulus = int(match.group(1), 0)
    if source_modulus != M31_MODULUS:
        raise AssertionError(
            f"checker modulus {M31_MODULUS} != source modulus {source_modulus}"
        )

    inverse_match = re.search(
        (
            r"const INV2: QM31 = "
            r"QM31\.fromBase\(M31\.fromU64\(([0-9]+)\)\);"
        ),
        merkle_source,
    )
    if inverse_match is None:
        raise AssertionError("could not locate the production inverse of two")
    source_inverse_two = int(inverse_match.group(1))
    if 2 * source_inverse_two % source_modulus != 1:
        raise AssertionError("production INV2 is not the M31 inverse of two")

    required_merkle_fragments = (
        "append(&list, .merkle, main[6], .{ index, depth, lhs, root });",
        "append(&list, .merkle, main[7], .{ index.add(one), depth, rhs, root });",
        (
            "append(&list, .merkle, main[8].neg(), "
            ".{ index.mul(INV2), depth.sub(one), cur, root });"
        ),
    )
    for fragment in required_merkle_fragments:
        if fragment not in merkle_source:
            raise AssertionError(f"production Merkle recurrence changed: {fragment}")

    admission_guard = (
        "if (n_rows >= m31.Modulus) "
        "return types.ProverError.InvalidStatement;"
    )
    if admission_guard not in admission_source:
        raise AssertionError("production Merkle row admission guard changed")
    admission_call = "try validateMerkleRowsFieldCycle(merkle_desc.n_rows);"
    if admission_call not in admission_source:
        raise AssertionError("Merkle descriptor is not checked by the row guard")

    return ProductionContract(
        m31_source=str(m31_path.relative_to(repo_root)),
        merkle_relation_source=str(merkle_path.relative_to(repo_root)),
        admission_source=str(admission_path.relative_to(repo_root)),
        source_modulus=source_modulus,
        source_inverse_two=source_inverse_two,
        child_recurrence="child = 2 * parent + bit",
        depth_recurrence="parent_depth = child_depth - 1 (mod p)",
        admission_rule="merkle n_rows < M31 modulus",
    )


def build_report(repo_root: Path) -> dict[str, object]:
    """Return a JSON-ready certificate, failing if any obligation is false."""

    index = index_certificate()
    cycle = depth_cycle_certificate()
    production = check_production_contract(repo_root)
    return {
        "schema": "stwo-riscv-merkle-recurrence-v1",
        "index_recurrence": dataclasses.asdict(index),
        "depth_cycle": dataclasses.asdict(cycle),
        "production_contract": dataclasses.asdict(production),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root whose production Zig sources are checked",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = build_report(args.repo_root.resolve())
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
