"""Preprocessed lookup-table membership, per relation domain.

Transcribed from `src/frontends/riscv/air/lookups/tables/schema.zig` (`Kind`,
`logSize`, `arity`, `tupleAt`) and from `air/lookups/entry.zig` (`Domain`,
`expectedArity`).  Those files stay the source of truth: the widths here are a
restatement for a different toolchain, and `test_air_uniqueness.py` cross-checks
them against the Zig so the restatement cannot drift silently.

Three classes of domain, and the classification is the single most important
thing a reviewer must agree with:

  BOX     a fixed preprocessed table whose rows are exactly the tuples inside a
          product of bit-width boxes.  A live request means each component lies
          in its box.  Encodable per row.
  BITWISE the 2^18-row (lhs, rhs, value, op) table.  Membership is the box on
          (lhs, rhs, op) plus a functional definition of `value`.
  BUS     not a table at all -- registers/memory/program/Poseidon2 relations are
          multiset buses closed across rows and components.  A per-row query
          learns nothing from them and asserts nothing.
"""

from __future__ import annotations

# domain -> per-component bit width, in tuple order.
BOX_TABLES: dict[str, tuple[int, ...]] = {
    "range_check_20": (20,),
    "range_check_8_11": (8, 11),
    "range_check_8_8_4": (8, 8, 4),
    "range_check_8_8": (8, 8),
    # logSize 15 = 8 + 7.  Row 2^15-1 is the all-zero sentinel, which is already
    # inside the box, so the box is exact.
    "range_check_m31": (8, 7),
}

BITWISE_DOMAIN = "bitwise"
BITWISE_WIDTHS = (8, 8, 8, 2)
# Operation ids, from `schema.zig` `tupleAt(.bitwise, ..)`.
BITWISE_OPS = {0: "and", 1: "or", 2: "xor", 3: "zero"}

BUS_DOMAINS: frozenset[str] = frozenset(
    {
        "registers_state",
        "memory_access",
        "program_access",
        "merkle",
        "poseidon2",
        "poseidon2_io",
    }
)

ARITIES: dict[str, int] = {
    **{name: len(widths) for name, widths in BOX_TABLES.items()},
    BITWISE_DOMAIN: 4,
    "registers_state": 2,
    "memory_access": 7,
    "program_access": 5,
    "merkle": 4,
    "poseidon2": 16,
    "poseidon2_io": 32,
}


class DomainError(ValueError):
    """Unknown relation domain, or a tuple of the wrong arity for it."""


def check_arity(domain: str, arity: int) -> None:
    expected = ARITIES.get(domain)
    if expected is None:
        raise DomainError(f"unknown relation domain {domain!r}")
    if arity != expected:
        raise DomainError(
            f"domain {domain} expects arity {expected}, request has {arity}"
        )


def is_constraining(domain: str) -> bool:
    """Whether a live request in this domain constrains the row on its own."""
    return domain in BOX_TABLES or domain == BITWISE_DOMAIN
