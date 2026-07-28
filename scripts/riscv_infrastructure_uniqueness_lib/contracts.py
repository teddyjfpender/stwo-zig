"""Shared field, relation, counterexample, and radix theorem contracts."""

from __future__ import annotations

import dataclasses
import math
from collections.abc import Iterable

try:
    from air_satisfaction_lib import infrastructure
except ModuleNotFoundError:  # Imported through scripts.* in tests.
    from scripts.air_satisfaction_lib import infrastructure


P = infrastructure.P
INV2 = infrastructure.INV2
PROGRAM_LOW_BASE = 1 << 20
PROGRAM_HIGH_BOUND = 1 << 8
PROGRAM_ADDRESS_BOUND = 1 << 30
# The production binding and recurrence certificate both fail closed if this
# reviewed depth changes.
MERKLE_DEPTH = 30
CLOCK_LOW_BASE = 1 << 20
CLOCK_HIGH_BOUND = 1 << 6
CLOCK_PREDECESSOR_BOUND = CLOCK_LOW_BASE * CLOCK_HIGH_BOUND
MAX_CLOCK_DIFF = infrastructure.MAX_CLOCK_DIFF


@dataclasses.dataclass(frozen=True)
class RelationRequest:
    """One signed relation term, before challenge combination."""

    domain: str
    numerator: int
    values: tuple[int, ...]


@dataclasses.dataclass(frozen=True)
class TwoRowCounterexample:
    """Two locally admissible rows refuting an intentionally stronger claim."""

    claim_refuted: str
    missing_premise: str
    differing_fields: tuple[str, ...]
    left: tuple[tuple[str, object], ...]
    right: tuple[tuple[str, object], ...]
    both_row_local_admissible: bool


@dataclasses.dataclass(frozen=True)
class RadixCertificate:
    radix: int
    high_bound_exclusive: int
    multiplier: int
    field_modulus: int
    represented_values: int
    represented_values_below_field: bool
    multiplier_invertible: bool
    decomposition_injective_mod_field: bool
    maximum_integer_recomposition: int
    integer_recomposition_does_not_wrap: bool


@dataclasses.dataclass(frozen=True)
class RadixExhaustion:
    radix: int
    high_bound_exclusive: int
    multiplier: int
    modulus: int
    residues_checked: int
    represented_pairs: int
    maximum_decompositions_per_residue: int
    unique: bool


@dataclasses.dataclass(frozen=True)
class FieldCoefficientWrapCounterexample:
    """A zero field coefficient whose ordinary integer coefficient is nonzero."""

    field_modulus: int
    maximum_row_coefficient: int
    coefficient_two_rows: int
    coefficient_one_rows: int
    active_rows: int
    ordinary_coefficient: int
    field_coefficient: int
    admitted_by_rows_less_than_modulus: bool
    admitted_by_production_node_guard: bool
    locally_admissible_multiplicities: bool
    depth_cycle_present: bool
    consequence: str


def row_snapshot(row: object) -> tuple[tuple[str, object], ...]:
    return tuple(
        (field.name, getattr(row, field.name))
        for field in dataclasses.fields(row)
    )


def request(
    domain: str,
    numerator: int,
    values: Iterable[int],
    modulus: int = P,
) -> RelationRequest:
    return RelationRequest(
        domain=domain,
        numerator=numerator % modulus,
        values=tuple(value % modulus for value in values),
    )


def canonical_violations(
    fields: Iterable[tuple[str, int]],
    modulus: int = P,
) -> list[str]:
    return [
        f"{name}={value} is not a canonical field element"
        for name, value in fields
        if not 0 <= value < modulus
    ]


def radix_certificate(
    radix: int,
    high_bound_exclusive: int,
    multiplier: int,
    modulus: int,
) -> RadixCertificate:
    """Prove uniqueness of ``multiplier * (low + radix * high) mod p``.

    ``low`` ranges over ``[0, radix)`` and ``high`` over the stated bound. If
    the mixed-radix integer is below p and the multiplier is invertible mod p,
    equality of two field residues first gives equality modulo p, then equality
    as ordinary integers, then uniqueness of quotient and remainder.
    """
    if min(radix, high_bound_exclusive, multiplier) <= 0 or modulus <= 1:
        raise ValueError("radix, bound, multiplier, and modulus must be positive")
    represented_values = radix * high_bound_exclusive
    maximum_recomposition = multiplier * (represented_values - 1)
    certificate = RadixCertificate(
        radix=radix,
        high_bound_exclusive=high_bound_exclusive,
        multiplier=multiplier,
        field_modulus=modulus,
        represented_values=represented_values,
        represented_values_below_field=represented_values <= modulus,
        multiplier_invertible=math.gcd(multiplier, modulus) == 1,
        decomposition_injective_mod_field=(
            represented_values <= modulus
            and math.gcd(multiplier, modulus) == 1
        ),
        maximum_integer_recomposition=maximum_recomposition,
        integer_recomposition_does_not_wrap=maximum_recomposition < modulus,
    )
    if not certificate.decomposition_injective_mod_field:
        raise AssertionError("mixed-radix decomposition is not injective in the field")
    return certificate


def radix_decompositions(
    residue: int,
    *,
    radix: int,
    high_bound_exclusive: int,
    multiplier: int,
    modulus: int,
) -> tuple[tuple[int, int], ...]:
    """Enumerate the bounded decompositions of one canonical field residue."""
    if not 0 <= residue < modulus:
        raise ValueError("residue must be canonical")
    return tuple(
        (low, high)
        for high in range(high_bound_exclusive)
        for low in range(radix)
        if multiplier * (low + radix * high) % modulus == residue
    )


def exhaust_radix_uniqueness(
    *,
    radix: int,
    high_bound_exclusive: int,
    multiplier: int,
    modulus: int,
) -> RadixExhaustion:
    """Exhaust a small analogue of the production mixed-radix theorem."""
    maximum = 0
    represented_pairs = 0
    for residue in range(modulus):
        count = len(
            radix_decompositions(
                residue,
                radix=radix,
                high_bound_exclusive=high_bound_exclusive,
                multiplier=multiplier,
                modulus=modulus,
            )
        )
        maximum = max(maximum, count)
        represented_pairs += count
    certificate = RadixExhaustion(
        radix=radix,
        high_bound_exclusive=high_bound_exclusive,
        multiplier=multiplier,
        modulus=modulus,
        residues_checked=modulus,
        represented_pairs=represented_pairs,
        maximum_decompositions_per_residue=maximum,
        unique=maximum <= 1,
    )
    if not certificate.unique:
        raise AssertionError("small mixed-radix analogue has a collision")
    return certificate
