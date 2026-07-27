#!/usr/bin/env python3
"""Machine-check the conditional uniqueness claims of RISC-V AIR infrastructure.

The four infrastructure rows covered here are not fully unique in isolation.
Their direct constraints deliberately leave some fields to LogUp relations:

* a program row does not locally determine its multiplicity or Merkle root;
* an RW-boundary row does not locally choose initial versus final, or its root;
* a Merkle row does not locally force an even index, root, hash output, or
  edge multiplicities; and
* a clock-update row does not locally range-check address space, address, or
  value bytes.

This checker therefore proves conditional, reviewable statements instead of
silently promoting bus closure to a row-local fact:

* the exact relation requests emitted by a fixed row are deterministic;
* the program address and clock-predecessor decompositions are unique;
* exact ``program_access`` closure binds fetches to a canonical program-leaf
  map, conditional on the Merkle commitment assumption;
* exact ``memory_access`` closure plus ordinary increasing clocks makes a
  finite RW-memory component one source-to-sink path, while closure alone
  admits a detached cycle;
* a root-connected depth-30 Merkle path has the unique binary index/parity
  recurrence and carries one root, while a detached component would require
  at least p rows; and
* a clock-update row preserves the memory key/value and advances the clock by
  exactly ``2**20 - 1`` inside the committed predecessor window.

Known counterexamples to stronger claims are emitted in the JSON report.  The
production-source contract pins every premise to the shipped Zig row
constraints and relation declarations, so source drift fails closed.

Run from the repository root:

    python3 -m scripts.riscv_infrastructure_uniqueness
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import math
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from pathlib import Path

from scripts import riscv_merkle_recurrence
from scripts import riscv_state_chain_recurrence
from scripts.air_satisfaction_lib import infrastructure


P = infrastructure.P
INV2 = infrastructure.INV2
PROGRAM_LOW_BASE = 1 << 20
PROGRAM_HIGH_BOUND = 1 << 8
PROGRAM_ADDRESS_BOUND = 1 << 30
MERKLE_DEPTH = riscv_merkle_recurrence.MERKLE_PATH_DEPTH
CLOCK_LOW_BASE = 1 << 20
CLOCK_HIGH_BOUND = 1 << 4
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


def _row_snapshot(row: object) -> tuple[tuple[str, object], ...]:
    return tuple(
        (field.name, getattr(row, field.name))
        for field in dataclasses.fields(row)
    )


def _request(
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


def _canonical_violations(fields: Iterable[tuple[str, int]], modulus: int = P) -> list[str]:
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

    ``low`` ranges over ``[0, radix)`` and ``high`` over the stated bound.  If
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


# ---------------------------------------------------------------------------
# Program commitment row and conditional program binding.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class ProgramTuple:
    addr: int
    values: tuple[int, int, int, int]


@dataclasses.dataclass(frozen=True)
class ProgramRow:
    addr: int
    values: tuple[int, int, int, int]
    multiplicity: int
    root: int
    low20: int
    high8: int

    @classmethod
    def from_word(
        cls,
        addr: int,
        values: tuple[int, int, int, int],
        multiplicity: int,
        root: int,
    ) -> ProgramRow:
        word_address, remainder = divmod(addr, 4)
        if remainder:
            raise ValueError("program byte address must be word-aligned")
        high8, low20 = divmod(word_address, PROGRAM_LOW_BASE)
        return cls(addr, values, multiplicity, root, low20, high8)

    def program_tuple(self) -> ProgramTuple:
        return ProgramTuple(self.addr, self.values)


def program_row_violations(row: ProgramRow) -> tuple[str, ...]:
    """Decide the direct constraints and preprocessed lookups of one active row."""

    violations = _canonical_violations(
        (
            ("addr", row.addr),
            ("multiplicity", row.multiplicity),
            ("root", row.root),
            ("low20", row.low20),
            ("high8", row.high8),
            *((f"value[{index}]", value) for index, value in enumerate(row.values)),
        )
    )
    if len(row.values) != 4:
        violations.append("program row must carry four decoded values")
        return tuple(violations)
    if not 0 <= row.low20 < PROGRAM_LOW_BASE:
        violations.append("low20 is outside range_check_20")
    if not 0 <= row.high8 < PROGRAM_HIGH_BOUND:
        violations.append("high8 is outside range_check_8_8(_, 0)")
    word_address = row.low20 + PROGRAM_LOW_BASE * row.high8
    if row.addr % P != 4 * word_address % P:
        violations.append("byte address does not equal four times the decomposed word address")
    return tuple(violations)


def program_requests(row: ProgramRow) -> tuple[RelationRequest, ...]:
    """The exact active-row requests declared by ``program/interaction.zig``."""

    return (
        _request("program_access", row.multiplicity, (row.addr, *row.values)),
        *(
            _request("merkle", -1, (row.addr + limb, MERKLE_DEPTH, value, row.root))
            for limb, value in enumerate(row.values)
        ),
        _request("range_check_20", -1, (row.low20,)),
        _request("range_check_8_8", -1, (row.high8, 0)),
    )


def program_address_certificate() -> RadixCertificate:
    certificate = radix_certificate(
        PROGRAM_LOW_BASE,
        PROGRAM_HIGH_BOUND,
        4,
        P,
    )
    if certificate.represented_values != 1 << 28:
        raise AssertionError("program word-address domain changed")
    if certificate.maximum_integer_recomposition != PROGRAM_ADDRESS_BOUND - 4:
        raise AssertionError("program byte-address endpoint changed")
    return certificate


@dataclasses.dataclass(frozen=True)
class ProgramBindingCheck:
    valid: bool
    reason: str
    commitment_rows: int
    fetches: int
    distinct_leaf_addresses: int
    exact_program_multiset: bool
    common_public_root: bool
    canonical_leaf_map: bool


def verify_program_binding(
    rows: Sequence[ProgramRow],
    fetches: Sequence[ProgramTuple],
    *,
    public_root: int,
) -> ProgramBindingCheck:
    """Check the non-cryptographic part of the program-binding lemma.

    This function assumes that one canonical leaf map is the leaf opening of
    ``public_root``.  Establishing that assumption from a root is the Merkle
    collision-resistance claim, not an AIR row-local uniqueness theorem.
    """

    for index, row in enumerate(rows):
        violations = program_row_violations(row)
        if violations:
            return ProgramBindingCheck(
                False,
                f"row {index}: {violations[0]}",
                len(rows),
                len(fetches),
                0,
                False,
                False,
                False,
            )

    common_root = all(row.root == public_root for row in rows)
    leaf_values: dict[int, int] = {}
    canonical_leaf_map = True
    for row in rows:
        for limb, value in enumerate(row.values):
            address = row.addr + limb
            if address in leaf_values:
                canonical_leaf_map = False
            else:
                leaf_values[address] = value

    supplied: Counter[ProgramTuple] = Counter()
    for row in rows:
        supplied[row.program_tuple()] += row.multiplicity
    demanded = Counter(fetches)
    exact_multiset = supplied == demanded
    valid = common_root and canonical_leaf_map and exact_multiset and bool(rows)
    if not rows:
        reason = "program commitment is empty"
    elif not common_root:
        reason = "a row root differs from the public program root"
    elif not canonical_leaf_map:
        reason = "two program rows claim the same leaf address"
    elif not exact_multiset:
        reason = "program_access supply does not equal the fetch multiset"
    else:
        reason = (
            "every fetch is an exact committed tuple, conditional on exact "
            "program_access equality and the canonical Merkle leaf map"
        )
    return ProgramBindingCheck(
        valid,
        reason,
        len(rows),
        len(fetches),
        len(leaf_values),
        exact_multiset,
        common_root,
        canonical_leaf_map,
    )


def program_counterexamples() -> tuple[TwoRowCounterexample, ...]:
    base = ProgramRow.from_word(0x1000, (10, 11, 12, 13), 1, 99)
    different_root = dataclasses.replace(base, root=100)
    different_multiplicity = dataclasses.replace(base, multiplicity=2)
    return (
        TwoRowCounterexample(
            claim_refuted="program_access tuple determines the Merkle root row-locally",
            missing_premise="Merkle-bus closure to the public program root",
            differing_fields=("root",),
            left=_row_snapshot(base),
            right=_row_snapshot(different_root),
            both_row_local_admissible=(
                not program_row_violations(base)
                and not program_row_violations(different_root)
            ),
        ),
        TwoRowCounterexample(
            claim_refuted="active program-row constraints determine fetch multiplicity",
            missing_premise="global program_access multiset equality",
            differing_fields=("multiplicity",),
            left=_row_snapshot(base),
            right=_row_snapshot(different_multiplicity),
            both_row_local_admissible=(
                not program_row_violations(base)
                and not program_row_violations(different_multiplicity)
            ),
        ),
    )


# ---------------------------------------------------------------------------
# RW-memory boundary row and offline-memory chain lemma.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class MemoryBoundaryRow:
    addr: int
    clock: int
    values: tuple[int, int, int, int]
    sign: int
    root: int


def memory_boundary_row_violations(row: MemoryBoundaryRow) -> tuple[str, ...]:
    """Decide the active memory-boundary AIR, excluding host-only validation."""

    violations = _canonical_violations(
        (
            ("addr", row.addr),
            ("clock", row.clock),
            ("root", row.root),
            *((f"value[{index}]", value) for index, value in enumerate(row.values)),
        )
    )
    if len(row.values) != 4:
        violations.append("memory boundary row must carry four values")
        return tuple(violations)
    if row.sign not in (-1, 1):
        violations.append("signed multiplicity is not -1 or +1 on an active row")
    for index, value in enumerate(row.values):
        if not 0 <= value < 256:
            violations.append(f"value[{index}] is outside its byte lookup")
    return tuple(violations)


def memory_boundary_requests(row: MemoryBoundaryRow) -> tuple[RelationRequest, ...]:
    return (
        _request("range_check_8_8", -1, row.values[0:2]),
        _request("range_check_8_8", -1, row.values[2:4]),
        _request("memory_access", row.sign, (1, row.addr, row.clock, *row.values)),
        *(
            _request("merkle", -1, (row.addr + limb, MERKLE_DEPTH, value, row.root))
            for limb, value in enumerate(row.values)
        ),
    )


def memory_boundary_counterexamples() -> tuple[TwoRowCounterexample, ...]:
    initial = MemoryBoundaryRow(0x1000, 0, (1, 2, 3, 4), 1, 91)
    final_sign = dataclasses.replace(initial, sign=-1)
    different_root = dataclasses.replace(initial, root=92)
    return (
        TwoRowCounterexample(
            claim_refuted="the active memory AIR chooses initial versus final",
            missing_premise="signed memory_access boundary balance and public boundary policy",
            differing_fields=("sign",),
            left=_row_snapshot(initial),
            right=_row_snapshot(final_sign),
            both_row_local_admissible=(
                not memory_boundary_row_violations(initial)
                and not memory_boundary_row_violations(final_sign)
            ),
        ),
        TwoRowCounterexample(
            claim_refuted="a memory boundary row determines its Merkle root locally",
            missing_premise="Merkle-bus closure to the selected initial/final public root",
            differing_fields=("root",),
            left=_row_snapshot(initial),
            right=_row_snapshot(different_root),
            both_row_local_admissible=(
                not memory_boundary_row_violations(initial)
                and not memory_boundary_row_violations(different_root)
            ),
        ),
    )


@dataclasses.dataclass(frozen=True, order=True)
class MemoryState:
    addr_space: int
    addr: int
    clock: int
    values: tuple[int, int, int, int]

    def key(self) -> tuple[int, int]:
        return self.addr_space, self.addr


@dataclasses.dataclass(frozen=True)
class MemoryTransition:
    previous: MemoryState
    next: MemoryState
    kind: str = "opcode"


@dataclasses.dataclass(frozen=True)
class MemoryChainCheck:
    valid: bool
    reason: str
    transitions: int
    exact_relation_balance: bool
    ordinary_strict_clock_order: bool
    connected_source_to_sink: bool
    ordered_clocks: tuple[int, ...]
    ordered_values: tuple[tuple[int, int, int, int], ...]


def memory_relation_balance(
    initial: MemoryState,
    final: MemoryState,
    transitions: Sequence[MemoryTransition],
) -> Counter[MemoryState]:
    """Return exact tuple coefficients: source + edges - sink."""

    balance: Counter[MemoryState] = Counter()
    balance[initial] += 1
    balance[final] -= 1
    for transition in transitions:
        balance[transition.previous] -= 1
        balance[transition.next] += 1
    return balance


def _nonzero_balance(
    initial: MemoryState,
    final: MemoryState,
    transitions: Sequence[MemoryTransition],
) -> dict[MemoryState, int]:
    balance: Counter[MemoryState] = Counter()
    balance[initial] += 1
    balance[final] -= 1
    for transition in transitions:
        balance[transition.previous] -= 1
        balance[transition.next] += 1
    return {state: coefficient for state, coefficient in balance.items() if coefficient}


def verify_offline_memory_chain(
    initial: MemoryState,
    final: MemoryState,
    transitions: Sequence[MemoryTransition],
) -> MemoryChainCheck:
    """Check one finite exact offline-memory component.

    Exact tuple balance supplies value continuity.  Strict ordinary clock
    increase makes the graph acyclic.  A finite positive integral flow with one
    unit source and one unit sink can then neither branch nor contain a
    detached component, so it is one path.
    """

    expected_key = initial.key()
    states = [initial, final]
    for transition in transitions:
        states.extend((transition.previous, transition.next))
    if any(state.key() != expected_key for state in states):
        return MemoryChainCheck(
            False,
            "a transition changes address space or address",
            len(transitions),
            False,
            False,
            False,
            (),
            (),
        )
    strict = all(
        transition.previous.clock < transition.next.clock
        for transition in transitions
    )
    if not strict:
        return MemoryChainCheck(
            False,
            "a transition is not strictly increasing in the ordinary clock order",
            len(transitions),
            not _nonzero_balance(initial, final, transitions),
            False,
            False,
            (),
            (),
        )
    imbalance = _nonzero_balance(initial, final, transitions)
    if imbalance:
        state, coefficient = next(iter(imbalance.items()))
        return MemoryChainCheck(
            False,
            f"memory_access tuple {state} has net coefficient {coefficient}",
            len(transitions),
            False,
            True,
            False,
            (),
            (),
        )

    remaining = list(transitions)
    current = initial
    ordered = [current]
    while current != final:
        candidates = [
            index
            for index, transition in enumerate(remaining)
            if transition.previous == current
        ]
        if len(candidates) != 1:
            return MemoryChainCheck(
                False,
                f"path state {current} has {len(candidates)} outgoing transitions",
                len(transitions),
                True,
                True,
                False,
                tuple(state.clock for state in ordered),
                tuple(state.values for state in ordered),
            )
        transition = remaining.pop(candidates[0])
        current = transition.next
        ordered.append(current)
    if remaining:
        return MemoryChainCheck(
            False,
            f"{len(remaining)} balanced transitions are detached from the boundary path",
            len(transitions),
            True,
            True,
            False,
            tuple(state.clock for state in ordered),
            tuple(state.values for state in ordered),
        )
    return MemoryChainCheck(
        True,
        (
            "exact tuple balance and strict clocks force one value-continuous "
            "source-to-sink path"
        ),
        len(transitions),
        True,
        True,
        True,
        tuple(state.clock for state in ordered),
        tuple(state.values for state in ordered),
    )


@dataclasses.dataclass(frozen=True)
class OfflineMemoryExhaustion:
    clocks: int
    values_per_clock: int
    candidate_edges: int
    edge_subsets_per_final: int
    final_states: int
    cases_checked: int
    exactly_balanced_cases: int
    balanced_cases_rejected_by_path_lemma: int


def exhaustive_offline_memory_analogue() -> OfflineMemoryExhaustion:
    """Exhaust every simple strict edge set on a three-clock/two-value graph."""

    values = ((0, 0, 0, 0), (1, 0, 0, 0))
    nodes = {
        (clock, value): MemoryState(1, 7, clock, value)
        for clock in range(3)
        for value in values
    }
    edges = tuple(
        MemoryTransition(nodes[(left_clock, left)], nodes[(right_clock, right)])
        for left_clock in range(3)
        for right_clock in range(left_clock + 1, 3)
        for left in values
        for right in values
    )
    initial = nodes[(0, values[0])]
    balanced = 0
    rejected = 0
    cases = 0
    for final_value in values:
        final = nodes[(2, final_value)]
        for mask in range(1 << len(edges)):
            cases += 1
            selected = tuple(
                edge for index, edge in enumerate(edges) if mask & (1 << index)
            )
            if _nonzero_balance(initial, final, selected):
                continue
            balanced += 1
            if not verify_offline_memory_chain(initial, final, selected).valid:
                rejected += 1
    certificate = OfflineMemoryExhaustion(
        clocks=3,
        values_per_clock=2,
        candidate_edges=len(edges),
        edge_subsets_per_final=1 << len(edges),
        final_states=len(values),
        cases_checked=cases,
        exactly_balanced_cases=balanced,
        balanced_cases_rejected_by_path_lemma=rejected,
    )
    if rejected:
        raise AssertionError("a balanced strict small-graph flow was not one path")
    return certificate


@dataclasses.dataclass(frozen=True)
class DetachedMemoryCycle:
    initial: MemoryState
    final: MemoryState
    transitions: tuple[MemoryTransition, ...]
    exact_relation_balance: bool
    rejected_by_strict_clock_lemma: bool


def detached_memory_cycle_counterexample() -> DetachedMemoryCycle:
    """Exhibit why exact multiset closure without clock order is insufficient."""

    initial = MemoryState(1, 0x1000, 0, (1, 0, 0, 0))
    final = MemoryState(1, 0x1000, 3, (2, 0, 0, 0))
    left = MemoryState(1, 0x1000, 1, (7, 0, 0, 0))
    right = MemoryState(1, 0x1000, 2, (8, 0, 0, 0))
    transitions = (
        MemoryTransition(initial, final),
        MemoryTransition(left, right, "detached"),
        MemoryTransition(right, left, "detached"),
    )
    result = DetachedMemoryCycle(
        initial=initial,
        final=final,
        transitions=transitions,
        exact_relation_balance=not _nonzero_balance(initial, final, transitions),
        rejected_by_strict_clock_lemma=not verify_offline_memory_chain(
            initial, final, transitions
        ).valid,
    )
    if not result.exact_relation_balance or not result.rejected_by_strict_clock_lemma:
        raise AssertionError("detached memory cycle counterexample is malformed")
    return result


@dataclasses.dataclass(frozen=True)
class SameClockAliasCounterexample:
    """A second aliased register source can be an arbitrary self-loop."""

    architectural_scenario: str
    initial: MemoryState
    honest_at_instruction_clock: MemoryState
    forged_second_source: MemoryState
    transitions: tuple[MemoryTransition, ...]
    exact_relation_balance: bool
    forged_value_differs_from_honest_value: bool
    second_source_term_is_identically_zero: bool
    rejected_by_strict_clock_lemma: bool
    consequence: str


def same_clock_alias_counterexample() -> SameClockAliasCounterexample:
    """Model ``ADD x3, x1, x1`` with a forged second x1 source.

    The first source advances the honest x1 chain from clock zero to the
    instruction clock with value A.  The second source claims previous value B
    at that same clock and emits B at that same clock.  Its
    ``-1/(x1,t,B) + 1/(x1,t,B)`` contribution vanishes for every relation
    challenge, so exact ``memory_access`` closure cannot distinguish B from A.
    """

    honest_value = (5, 0, 0, 0)
    forged_value = (9, 0, 0, 0)
    initial = MemoryState(0, 1, 0, honest_value)
    honest_at_clock = MemoryState(0, 1, 7, honest_value)
    forged_at_clock = MemoryState(0, 1, 7, forged_value)
    transitions = (
        MemoryTransition(initial, honest_at_clock, "first x1 source"),
        MemoryTransition(
            forged_at_clock,
            forged_at_clock,
            "second aliased x1 source",
        ),
    )
    result = SameClockAliasCounterexample(
        architectural_scenario="ADD x3, x1, x1",
        initial=initial,
        honest_at_instruction_clock=honest_at_clock,
        forged_second_source=forged_at_clock,
        transitions=transitions,
        exact_relation_balance=not _nonzero_balance(
            initial, honest_at_clock, transitions
        ),
        forged_value_differs_from_honest_value=(
            forged_at_clock.values != honest_at_clock.values
        ),
        second_source_term_is_identically_zero=(
            transitions[1].previous == transitions[1].next
        ),
        rejected_by_strict_clock_lemma=not verify_offline_memory_chain(
            initial, honest_at_clock, transitions
        ).valid,
        consequence=(
            "memory_access closure alone permits the opcode row to use A + B "
            "instead of A + A unless same-clock aliased sources are bound "
            "row-locally or by an additional ordering rule"
        ),
    )
    if not all(
        (
            result.exact_relation_balance,
            result.forged_value_differs_from_honest_value,
            result.second_source_term_is_identically_zero,
            result.rejected_by_strict_clock_lemma,
        )
    ):
        raise AssertionError("same-clock alias counterexample is malformed")
    return result


# ---------------------------------------------------------------------------
# Merkle-node row and global index/root recurrence.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class MerkleNodeRow:
    index: int
    depth: int
    lhs: int
    rhs: int
    current: int
    lhs_multiplicity: int
    rhs_multiplicity: int
    current_multiplicity: int
    root: int


def merkle_row_violations(row: MerkleNodeRow) -> tuple[str, ...]:
    violations = _canonical_violations(
        (
            ("index", row.index),
            ("depth", row.depth),
            ("lhs", row.lhs),
            ("rhs", row.rhs),
            ("current", row.current),
            ("root", row.root),
            ("lhs_multiplicity", row.lhs_multiplicity),
            ("rhs_multiplicity", row.rhs_multiplicity),
            ("current_multiplicity", row.current_multiplicity),
        )
    )
    for name, value in (
        ("lhs_multiplicity", row.lhs_multiplicity),
        ("rhs_multiplicity", row.rhs_multiplicity),
        ("current_multiplicity", row.current_multiplicity),
    ):
        if value not in (0, 1, 2):
            violations.append(f"{name} is not in {{0, 1, 2}}")
    return tuple(violations)


def merkle_requests(row: MerkleNodeRow) -> tuple[RelationRequest, ...]:
    poseidon_input = (row.lhs, row.rhs, *([0] * 14))
    poseidon_output = (row.current, *([0] * 15))
    return (
        _request(
            "merkle",
            row.lhs_multiplicity,
            (row.index, row.depth, row.lhs, row.root),
        ),
        _request(
            "merkle",
            row.rhs_multiplicity,
            (row.index + 1, row.depth, row.rhs, row.root),
        ),
        _request(
            "merkle",
            -row.current_multiplicity,
            (row.index * INV2, row.depth - 1, row.current, row.root),
        ),
        _request("poseidon2", 1, poseidon_input),
        _request("poseidon2", -1, poseidon_output),
    )


@dataclasses.dataclass(frozen=True)
class MerkleRowCertificate:
    index: int
    field_parent_index: int
    left_index: int
    right_index: int
    child_depth: int
    parent_depth: int
    root_copied_to_every_merkle_tuple: bool
    field_left_recurrence: bool
    field_right_recurrence: bool
    canonical_even_base_index: bool
    integer_parent_is_floor_half: bool
    left_parity_zero: bool
    right_parity_one: bool


def merkle_row_certificate(row: MerkleNodeRow) -> MerkleRowCertificate:
    if merkle_row_violations(row):
        raise ValueError("Merkle row is not locally admissible")
    parent = row.index * INV2 % P
    certificate = MerkleRowCertificate(
        index=row.index,
        field_parent_index=parent,
        left_index=row.index,
        right_index=(row.index + 1) % P,
        child_depth=row.depth,
        parent_depth=(row.depth - 1) % P,
        root_copied_to_every_merkle_tuple=True,
        field_left_recurrence=2 * parent % P == row.index,
        field_right_recurrence=(2 * parent + 1) % P == (row.index + 1) % P,
        canonical_even_base_index=(row.index & 1) == 0,
        integer_parent_is_floor_half=(
            (row.index & 1) == 0 and parent == row.index // 2
        ),
        left_parity_zero=(row.index & 1) == 0,
        right_parity_one=((row.index + 1) & 1) == 1,
    )
    if not certificate.field_left_recurrence or not certificate.field_right_recurrence:
        raise AssertionError("production INV2 does not implement the child recurrence")
    return certificate


@dataclasses.dataclass(frozen=True)
class MerkleConnectivityCertificate:
    field_modulus: int
    path_depth: int
    exhaustive_prefix_depth: int
    exhaustive_paths_checked: int
    exhaustive_edges_checked: int
    maximum_leaf_index: int
    every_connected_base_index_even: bool
    every_leaf_index_is_unique_binary_path: bool
    every_connected_path_keeps_one_root: bool
    minimum_detached_depth_cycle_rows: int
    maximum_admitted_merkle_rows: int
    detached_cycle_excluded: bool
    conditional_on_exact_merkle_multiset_equality: bool


def merkle_connectivity_certificate(
    exhaustive_prefix_depth: int = 12,
) -> MerkleConnectivityCertificate:
    """Combine the all-depth induction with an exhaustive finite prefix."""

    index = riscv_merkle_recurrence.index_certificate()
    cycle = riscv_merkle_recurrence.depth_cycle_certificate()
    paths = 1 << exhaustive_prefix_depth
    edges_checked = 0
    every_even = True
    for leaf in range(paths):
        bits = riscv_merkle_recurrence.decode_leaf_index(
            leaf, exhaustive_prefix_depth
        )
        parent = 0
        for bit in bits:
            base_index = 2 * parent
            every_even &= base_index % 2 == 0
            parent = base_index + bit
            edges_checked += 1
        if parent != leaf:
            raise AssertionError("exhaustive Merkle prefix did not reach its leaf")
    certificate = MerkleConnectivityCertificate(
        field_modulus=P,
        path_depth=index.path_depth,
        exhaustive_prefix_depth=exhaustive_prefix_depth,
        exhaustive_paths_checked=paths,
        exhaustive_edges_checked=edges_checked,
        maximum_leaf_index=index.maximum_leaf_index,
        every_connected_base_index_even=every_even,
        every_leaf_index_is_unique_binary_path=(
            index.canonical_without_wrap and index.parity_is_path_bit
        ),
        every_connected_path_keeps_one_root=True,
        minimum_detached_depth_cycle_rows=cycle.minimum_positive_cycle_rows,
        maximum_admitted_merkle_rows=cycle.maximum_admitted_rows,
        detached_cycle_excluded=cycle.detached_cycle_excluded,
        conditional_on_exact_merkle_multiset_equality=True,
    )
    if not all(
        (
            certificate.every_connected_base_index_even,
            certificate.every_leaf_index_is_unique_binary_path,
            certificate.detached_cycle_excluded,
        )
    ):
        raise AssertionError("Merkle connectivity certificate failed")
    return certificate


def merkle_counterexamples() -> tuple[TwoRowCounterexample, ...]:
    base = MerkleNodeRow(2, 9, 10, 11, 12, 1, 1, 1, 77)
    odd_index = dataclasses.replace(base, index=3)
    different_current = dataclasses.replace(base, current=13)
    different_root = dataclasses.replace(base, root=78)
    return (
        TwoRowCounterexample(
            claim_refuted="Merkle direct constraints force an even base index",
            missing_premise="root-connected Merkle multiset flow and the depth recurrence",
            differing_fields=("index",),
            left=_row_snapshot(base),
            right=_row_snapshot(odd_index),
            both_row_local_admissible=(
                not merkle_row_violations(base)
                and not merkle_row_violations(odd_index)
            ),
        ),
        TwoRowCounterexample(
            claim_refuted="Merkle direct constraints determine the parent hash",
            missing_premise="poseidon2 relation closure to a constrained permutation row",
            differing_fields=("current",),
            left=_row_snapshot(base),
            right=_row_snapshot(different_current),
            both_row_local_admissible=(
                not merkle_row_violations(base)
                and not merkle_row_violations(different_current)
            ),
        ),
        TwoRowCounterexample(
            claim_refuted="Merkle direct constraints determine the tree root",
            missing_premise="Merkle relation connectivity to a public root tuple",
            differing_fields=("root",),
            left=_row_snapshot(base),
            right=_row_snapshot(different_root),
            both_row_local_admissible=(
                not merkle_row_violations(base)
                and not merkle_row_violations(different_root)
            ),
        ),
    )


# ---------------------------------------------------------------------------
# Clock-update row and clock-gap recurrence.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class ClockUpdateRow:
    addr_space: int
    addr: int
    previous_clock: int
    values: tuple[int, int, int, int]
    low20: int
    high4: int

    @classmethod
    def from_previous(
        cls,
        addr_space: int,
        addr: int,
        previous_clock: int,
        values: tuple[int, int, int, int],
    ) -> ClockUpdateRow:
        high4, low20 = divmod(previous_clock, CLOCK_LOW_BASE)
        return cls(addr_space, addr, previous_clock, values, low20, high4)


def clock_update_row_violations(row: ClockUpdateRow) -> tuple[str, ...]:
    """Decide the direct active clock AIR and its two range requests."""

    violations = _canonical_violations(
        (
            ("addr_space", row.addr_space),
            ("addr", row.addr),
            ("previous_clock", row.previous_clock),
            ("low20", row.low20),
            ("high4", row.high4),
            *((f"value[{index}]", value) for index, value in enumerate(row.values)),
        )
    )
    if len(row.values) != 4:
        violations.append("clock row must carry four values")
        return tuple(violations)
    if not 0 <= row.low20 < CLOCK_LOW_BASE:
        violations.append("low20 is outside range_check_20")
    if not 0 <= row.high4 < CLOCK_HIGH_BOUND:
        violations.append("high4 is outside range_check_8_8_4")
    if row.previous_clock % P != (row.low20 + CLOCK_LOW_BASE * row.high4) % P:
        violations.append("clock predecessor decomposition does not recompose")
    return tuple(violations)


def clock_update_requests(row: ClockUpdateRow) -> tuple[RelationRequest, ...]:
    return (
        _request(
            "memory_access",
            -1,
            (row.addr_space, row.addr, row.previous_clock, *row.values),
        ),
        _request(
            "memory_access",
            1,
            (
                row.addr_space,
                row.addr,
                row.previous_clock + MAX_CLOCK_DIFF,
                *row.values,
            ),
        ),
        _request("range_check_20", -1, (row.low20,)),
        _request("range_check_8_8_4", -1, (0, 0, row.high4)),
    )


@dataclasses.dataclass(frozen=True)
class ClockRowCertificate:
    field_modulus: int
    predecessor_bound_exclusive: int
    maximum_predecessor: int
    maximum_output_clock: int
    fixed_clock_step: int
    predecessor_decomposition_unique: bool
    output_does_not_wrap_field: bool
    address_and_value_preserved: bool


def clock_row_certificate() -> ClockRowCertificate:
    radix = radix_certificate(CLOCK_LOW_BASE, CLOCK_HIGH_BOUND, 1, P)
    maximum_predecessor = CLOCK_PREDECESSOR_BOUND - 1
    maximum_output = maximum_predecessor + MAX_CLOCK_DIFF
    certificate = ClockRowCertificate(
        field_modulus=P,
        predecessor_bound_exclusive=CLOCK_PREDECESSOR_BOUND,
        maximum_predecessor=maximum_predecessor,
        maximum_output_clock=maximum_output,
        fixed_clock_step=MAX_CLOCK_DIFF,
        predecessor_decomposition_unique=radix.decomposition_injective_mod_field,
        output_does_not_wrap_field=maximum_output < P,
        address_and_value_preserved=True,
    )
    if (
        not certificate.predecessor_decomposition_unique
        or not certificate.output_does_not_wrap_field
    ):
        raise AssertionError("clock row is not uniquely bounded")
    return certificate


def clock_counterexamples() -> tuple[TwoRowCounterexample, ...]:
    base = ClockUpdateRow.from_previous(2, 7, 9, (300, 2, 3, 4))
    other_space = dataclasses.replace(base, addr_space=3)
    other_value = dataclasses.replace(base, values=(301, 2, 3, 4))
    return (
        TwoRowCounterexample(
            claim_refuted="clock-update direct constraints make address space boolean",
            missing_premise="memory_access closure to register/memory tuples",
            differing_fields=("addr_space",),
            left=_row_snapshot(base),
            right=_row_snapshot(other_space),
            both_row_local_admissible=(
                not clock_update_row_violations(base)
                and not clock_update_row_violations(other_space)
            ),
        ),
        TwoRowCounterexample(
            claim_refuted="clock-update direct constraints byte-range the carried value",
            missing_premise="memory_access closure to byte-ranged access/boundary rows",
            differing_fields=("values",),
            left=_row_snapshot(base),
            right=_row_snapshot(other_value),
            both_row_local_admissible=(
                not clock_update_row_violations(base)
                and not clock_update_row_violations(other_value)
            ),
        ),
    )


# ---------------------------------------------------------------------------
# Fail-closed production-source binding.
# ---------------------------------------------------------------------------


PROGRAM_INTERACTION_PATH = Path("src/frontends/riscv/air/program/interaction.zig")
PROGRAM_COMMITMENT_PATH = Path("src/frontends/riscv/air/program/commitment.zig")
MEMORY_INTERACTION_PATH = Path(
    "src/frontends/riscv/air/memory_commitment/interaction.zig"
)
MEMORY_BOUNDARY_PATH = Path(
    "src/frontends/riscv/air/memory_commitment/boundary.zig"
)
MEMORY_LOGUP_PATH = Path("src/frontends/riscv/air/memory_logup.zig")
MERKLE_NODE_PATH = Path(
    "src/frontends/riscv/air/memory_commitment/merkle_node.zig"
)
SPARSE_MERKLE_PATH = Path(
    "src/frontends/riscv/air/memory_commitment/sparse_merkle.zig"
)
CLOCK_INTERACTION_PATH = Path(
    "src/frontends/riscv/air/clock_update_interaction.zig"
)
CLOCK_COMPONENT_PATH = Path(
    "src/frontends/riscv/air/clock_update_component.zig"
)
CLOCK_TRACE_PATH = Path("src/frontends/riscv/infra_trace/clock_update.zig")
STATE_CHAIN_PATH = Path("src/frontends/riscv/runner/state_chain.zig")
PUBLIC_LOGUP_PATH = Path("src/frontends/riscv/air/public_logup.zig")
M31_PATH = Path("src/core/fields/m31.zig")
STATE_COMMON_PATH = Path("src/frontends/riscv/air/semantics/common.zig")
LOOKUP_ENTRY_PATH = Path("src/frontends/riscv/air/lookups/entry.zig")
STATEMENT_PATH = Path("src/frontends/riscv/air/statement.zig")
STATEMENT_VALIDATION_PATH = Path(
    "src/frontends/riscv/prover/statement_validation.zig"
)

PRODUCTION_PATHS = (
    M31_PATH,
    PROGRAM_INTERACTION_PATH,
    PROGRAM_COMMITMENT_PATH,
    MEMORY_INTERACTION_PATH,
    MEMORY_BOUNDARY_PATH,
    MEMORY_LOGUP_PATH,
    MERKLE_NODE_PATH,
    SPARSE_MERKLE_PATH,
    CLOCK_INTERACTION_PATH,
    CLOCK_COMPONENT_PATH,
    CLOCK_TRACE_PATH,
    STATE_CHAIN_PATH,
    PUBLIC_LOGUP_PATH,
    STATE_COMMON_PATH,
    LOOKUP_ENTRY_PATH,
    STATEMENT_PATH,
    STATEMENT_VALIDATION_PATH,
)


def _compact(source: str) -> str:
    return " ".join(source.split())


SOURCE_BINDINGS: tuple[tuple[str, Path, str], ...] = (
    (
        "program active selector",
        PROGRAM_INTERACTION_PATH,
        "result[N_SUMS] = main[0].sub(is_active);",
    ),
    (
        "program padding multiplicity",
        PROGRAM_INTERACTION_PATH,
        "result[N_SUMS + 1] = main[6].mul(QM31.one().sub(is_active));",
    ),
    (
        "program address radix",
        PROGRAM_INTERACTION_PATH,
        "const word_address = main[8].add(main[9].mul(base(@as(u32, 1) << 20)));",
    ),
    (
        "program address recomposition",
        PROGRAM_INTERACTION_PATH,
        "main[1].sub(word_address.mul(base(4)))",
    ),
    (
        "program tuple emission",
        PROGRAM_INTERACTION_PATH,
        "append(&list, .program_access, main[6], .{ addr, values[0], values[1], values[2], values[3] });",
    ),
    (
        "program first Merkle leaf",
        PROGRAM_INTERACTION_PATH,
        "append(&list, .merkle, enabler.neg(), .{ addr, depth, values[0], root });",
    ),
    (
        "program fourth Merkle leaf",
        PROGRAM_INTERACTION_PATH,
        "append(&list, .merkle, enabler.neg(), .{ addr.add(base(3)), depth, values[3], root });",
    ),
    (
        "program low address range",
        PROGRAM_INTERACTION_PATH,
        "append(&list, .range_check_20, enabler.neg(), .{main[8]});",
    ),
    (
        "program high address range",
        PROGRAM_INTERACTION_PATH,
        "append(&list, .range_check_8_8, enabler.neg(), .{ main[9], QM31.zero() });",
    ),
    (
        "program builder common root",
        PROGRAM_COMMITMENT_PATH,
        "if (row.root != self.tree.root) return error.InvalidProgramCommitment;",
    ),
    (
        "program builder leaf binding",
        PROGRAM_COMMITMENT_PATH,
        "if (leaf.index != row.addr + limb or leaf.value != value) return error.InvalidProgramCommitment;",
    ),
    (
        "memory multiplicity square definition",
        MEMORY_INTERACTION_PATH,
        "const multiplicity_squared = multiplicity.square();",
    ),
    (
        "memory signed multiplicity polynomial",
        MEMORY_INTERACTION_PATH,
        "result[N_SUMS] = multiplicity.mul(multiplicity_squared.sub(QM31.one()));",
    ),
    (
        "memory active multiplicity square",
        MEMORY_INTERACTION_PATH,
        "result[N_SUMS + 1] = multiplicity_squared.sub(is_active);",
    ),
    (
        "memory tuple boundary",
        MEMORY_INTERACTION_PATH,
        "append(&list, .memory_access, multiplicity, .{ QM31.one(), addr, clock, values[0], values[1], values[2], values[3], });",
    ),
    (
        "memory byte ranges",
        MEMORY_INTERACTION_PATH,
        "append(&list, .range_check_8_8, enabler.neg(), .{ values[0], values[1] });",
    ),
    (
        "memory fourth Merkle leaf",
        MEMORY_INTERACTION_PATH,
        "append(&list, .merkle, enabler.neg(), .{ addr.add(base(3)), depth, values[3], root });",
    ),
    (
        "memory host initial sign",
        MEMORY_BOUNDARY_PATH,
        "const is_initial = row.multiplicity.eql(M31.one());",
    ),
    (
        "memory host final sign",
        MEMORY_BOUNDARY_PATH,
        "const is_final = row.multiplicity.eql(M31.one().neg());",
    ),
    (
        "memory host initial clock",
        MEMORY_BOUNDARY_PATH,
        "if (is_initial and row.clock != 0) return error.InvalidBoundary;",
    ),
    (
        "memory host root binding",
        MEMORY_BOUNDARY_PATH,
        "if (row.root != tree.root) return error.InvalidBoundary;",
    ),
    (
        "offline memory previous tuple",
        MEMORY_LOGUP_PATH,
        "self.addr_space, self.addr, self.previous_clock, self.previous[0], self.previous[1], self.previous[2], self.previous[3],",
    ),
    (
        "offline memory next tuple",
        MEMORY_LOGUP_PATH,
        "self.addr_space, self.addr, self.clock, self.next[0], self.next[1], self.next[2], self.next[3],",
    ),
    (
        "offline memory transition signs",
        MEMORY_LOGUP_PATH,
        "const expected_numerator = pair.enabler.neg().mul(pair.next_denominator) .add(pair.enabler.mul(pair.previous_denominator));",
    ),
    (
        "Merkle left child",
        MERKLE_NODE_PATH,
        "append(&list, .merkle, main[6], .{ index, depth, lhs, root });",
    ),
    (
        "Merkle right child",
        MERKLE_NODE_PATH,
        "append(&list, .merkle, main[7], .{ index.add(one), depth, rhs, root });",
    ),
    (
        "Merkle parent",
        MERKLE_NODE_PATH,
        "append(&list, .merkle, main[8].neg(), .{ index.mul(INV2), depth.sub(one), cur, root });",
    ),
    (
        "Merkle Poseidon input",
        MERKLE_NODE_PATH,
        "append(&list, .poseidon2, enabler, poseidon_input);",
    ),
    (
        "Merkle Poseidon output",
        MERKLE_NODE_PATH,
        "append(&list, .poseidon2, enabler.neg(), poseidon_output);",
    ),
    (
        "sparse Merkle parent index",
        SPARSE_MERKLE_PATH,
        "try next.put(left_index / 2, parent);",
    ),
    (
        "clock previous tuple",
        CLOCK_INTERACTION_PATH,
        "entry.memory(&result, row.enabler.neg(), memoryTuple(row, row.clock_prev));",
    ),
    (
        "clock next tuple",
        CLOCK_INTERACTION_PATH,
        "memoryTuple(row, row.clock_prev.add(q(state_chain.MAX_CLOCK_DIFF)))",
    ),
    (
        "clock low range",
        CLOCK_INTERACTION_PATH,
        "entry.range20(&result, row.enabler.neg(), row.clock_prev_low20);",
    ),
    (
        "clock high range",
        CLOCK_INTERACTION_PATH,
        ".{ QM31.zero(), QM31.zero(), row.clock_prev_high4 },",
    ),
    (
        "clock direct recomposition",
        CLOCK_COMPONENT_PATH,
        "row.clock_prev_low20.add( row.clock_prev_high4.mul(",
    ),
    (
        "clock committed low decomposition",
        CLOCK_TRACE_PATH,
        "update.clk_prev & ((@as(u32, 1) << state_chain.CLOCK_PREV_LOW_BITS) - 1)",
    ),
    (
        "clock committed high decomposition",
        CLOCK_TRACE_PATH,
        "M31.fromCanonical(update.clk_prev >> state_chain.CLOCK_PREV_LOW_BITS)",
    ),
    (
        "clock bridge recurrence",
        STATE_CHAIN_PATH,
        "while (clk -| current > MAX_CLOCK_DIFF) { const next = current + MAX_CLOCK_DIFF;",
    ),
    (
        "public Merkle root tuple",
        PUBLIC_LOGUP_PATH,
        "M31.zero(), M31.zero(), base(root), base(root),",
    ),
)


@dataclasses.dataclass(frozen=True)
class ProductionContract:
    sources: tuple[str, ...]
    bindings_checked: int
    source_modulus: int
    source_inverse_two: int
    source_merkle_depth: int
    source_clock_low_bits: int
    source_clock_high_bits: int
    merkle_admission_rule: str
    state_recurrence: str
    opcode_gap_table: str
    clock_predecessor_range: str
    program_relation: str
    memory_relation: str
    merkle_relation: str
    clock_relation: str


def _decimal_constant(source: str, name: str) -> int:
    match = re.search(
        rf"(?:pub )?const {re.escape(name)}(?:: [^=]+)?\s*=\s*([0-9]+)\s*;",
        source,
    )
    if match is None:
        raise AssertionError(f"could not locate production constant {name}")
    return int(match.group(1))


def check_production_contract(repo_root: Path) -> ProductionContract:
    """Fail closed unless every machine-checked premise is still shipped."""

    sources = {
        path: (repo_root / path).read_text(encoding="utf-8")
        for path in PRODUCTION_PATHS
    }
    compact = {path: _compact(source) for path, source in sources.items()}
    modulus_match = re.search(
        r"pub const Modulus:\s*u32\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)\s*;",
        sources[M31_PATH],
    )
    if modulus_match is None:
        raise AssertionError("could not locate the production M31 modulus")
    source_modulus = int(modulus_match.group(1), 0)
    inverse_match = re.search(
        r"const INV2: QM31 = QM31\.fromBase\(M31\.fromU64\(([0-9]+)\)\);",
        compact[MERKLE_NODE_PATH],
    )
    if inverse_match is None:
        raise AssertionError("could not locate the production Merkle INV2")
    source_inverse_two = int(inverse_match.group(1))
    source_merkle_depth = _decimal_constant(
        sources[SPARSE_MERKLE_PATH], "LEAF_DEPTH"
    )
    source_clock_low_bits = _decimal_constant(
        sources[STATE_CHAIN_PATH], "CLOCK_PREV_LOW_BITS"
    )
    source_clock_high_bits = _decimal_constant(
        sources[STATE_CHAIN_PATH], "CLOCK_PREV_HIGH_BITS"
    )
    if source_modulus != P:
        raise AssertionError("infrastructure checker modulus drifted from production")
    if source_inverse_two != INV2 or 2 * source_inverse_two % P != 1:
        raise AssertionError("infrastructure checker INV2 drifted from production")
    if source_merkle_depth != MERKLE_DEPTH:
        raise AssertionError("infrastructure checker Merkle depth drifted")
    if (source_clock_low_bits, source_clock_high_bits) != (20, 4):
        raise AssertionError("infrastructure checker clock radix drifted")
    max_clock_fragment = "pub const MAX_CLOCK_DIFF: u32 = (1 << 20) - 1;"
    if max_clock_fragment not in compact[STATE_CHAIN_PATH]:
        raise AssertionError("production contract changed: maximum clock gap")

    for label, path, fragment in SOURCE_BINDINGS:
        if fragment not in compact[path]:
            raise AssertionError(f"production contract changed: {label}")
    merkle_contract = riscv_merkle_recurrence.check_production_contract(repo_root)
    clock_contract = riscv_state_chain_recurrence.check_production_contract(repo_root)
    return ProductionContract(
        sources=tuple(str(path) for path in PRODUCTION_PATHS),
        bindings_checked=len(SOURCE_BINDINGS),
        source_modulus=source_modulus,
        source_inverse_two=source_inverse_two,
        source_merkle_depth=source_merkle_depth,
        source_clock_low_bits=source_clock_low_bits,
        source_clock_high_bits=source_clock_high_bits,
        merkle_admission_rule=merkle_contract.admission_rule,
        state_recurrence=clock_contract.state_recurrence,
        opcode_gap_table=clock_contract.opcode_gap_table,
        clock_predecessor_range=clock_contract.clock_predecessor_range,
        program_relation=(
            "fixed row -> program tuple plus four same-root depth-30 leaves; "
            "bounded address limbs are unique"
        ),
        memory_relation=(
            "fixed signed boundary row -> one memory tuple plus four same-root leaves"
        ),
        merkle_relation=(
            "fixed row -> consecutive children, field-half/depth-1 parent, "
            "and one Poseidon2 call"
        ),
        clock_relation=(
            "fixed predecessor tuple -> same key/value at clock + (2^20 - 1); "
            "bounded predecessor limbs are unique"
        ),
    )


# ---------------------------------------------------------------------------
# Reviewable aggregate report.
# ---------------------------------------------------------------------------


def _sample_program_binding() -> ProgramBindingCheck:
    rows = (
        ProgramRow.from_word(0x1000, (1, 2, 3, 4), 2, 123),
        ProgramRow.from_word(0x1004, (5, 6, 7, 8), 1, 123),
    )
    fetches = (
        rows[0].program_tuple(),
        rows[1].program_tuple(),
        rows[0].program_tuple(),
    )
    result = verify_program_binding(rows, fetches, public_root=123)
    if not result.valid:
        raise AssertionError(result.reason)
    return result


def _sample_memory_chain() -> MemoryChainCheck:
    initial = MemoryState(1, 0x1000, 0, (1, 2, 3, 4))
    middle = MemoryState(1, 0x1000, 7, (1, 2, 3, 4))
    final = MemoryState(1, 0x1000, 9, (5, 6, 7, 8))
    result = verify_offline_memory_chain(
        initial,
        final,
        (
            MemoryTransition(initial, middle, "clock_update"),
            MemoryTransition(middle, final, "opcode"),
        ),
    )
    if not result.valid:
        raise AssertionError(result.reason)
    return result


def build_report(repo_root: Path) -> dict[str, object]:
    """Return the complete Tier-2/Tier-3 certificate as JSON-ready data."""

    small_program_radix = exhaust_radix_uniqueness(
        radix=4,
        high_bound_exclusive=3,
        multiplier=4,
        modulus=17,
    )
    small_clock_radix = exhaust_radix_uniqueness(
        radix=4,
        high_bound_exclusive=3,
        multiplier=1,
        modulus=17,
    )
    return {
        "schema": "stwo-riscv-infrastructure-uniqueness-v1",
        "tier_2_row_local": {
            "program": {
                "claim": (
                    "conditioned on the program tuple, multiplicity, and root, "
                    "all requests and the bounded address limbs are unique"
                ),
                "address": dataclasses.asdict(program_address_certificate()),
                "small_radix_exhaustion": dataclasses.asdict(small_program_radix),
                "counterexamples_to_stronger_claims": [
                    dataclasses.asdict(item) for item in program_counterexamples()
                ],
            },
            "memory_boundary": {
                "claim": (
                    "conditioned on sign, memory tuple, and root, the boundary "
                    "requests are unique; the active AIR only forces sign in {+1,-1}"
                ),
                "counterexamples_to_stronger_claims": [
                    dataclasses.asdict(item)
                    for item in memory_boundary_counterexamples()
                ],
            },
            "merkle_node": {
                "claim": (
                    "conditioned on all row fields, child/parent/Poseidon terms "
                    "are exact; parity, current, and root need global premises"
                ),
                "even_row_example": dataclasses.asdict(
                    merkle_row_certificate(
                        MerkleNodeRow(18, 9, 1, 2, 3, 1, 1, 1, 44)
                    )
                ),
                "counterexamples_to_stronger_claims": [
                    dataclasses.asdict(item) for item in merkle_counterexamples()
                ],
            },
            "clock_update": {
                "claim": (
                    "conditioned on the predecessor tuple, the successor tuple "
                    "and bounded predecessor decomposition are unique"
                ),
                "row": dataclasses.asdict(clock_row_certificate()),
                "small_radix_exhaustion": dataclasses.asdict(small_clock_radix),
                "counterexamples_to_stronger_claims": [
                    dataclasses.asdict(item) for item in clock_counterexamples()
                ],
            },
        },
        "tier_3_cross_row": {
            "program_binding": dataclasses.asdict(_sample_program_binding()),
            "offline_memory_path": dataclasses.asdict(_sample_memory_chain()),
            "offline_memory_exhaustion": dataclasses.asdict(
                exhaustive_offline_memory_analogue()
            ),
            "closure_only_counterexample": dataclasses.asdict(
                detached_memory_cycle_counterexample()
            ),
            "same_clock_alias_counterexample": dataclasses.asdict(
                same_clock_alias_counterexample()
            ),
            "merkle_connectivity": dataclasses.asdict(
                merkle_connectivity_certificate()
            ),
            "clock_window": dataclasses.asdict(
                riscv_state_chain_recurrence.clock_window_certificate()
            ),
            "old_wrapped_clock_counterexample": dataclasses.asdict(
                riscv_state_chain_recurrence.old_wrapped_cycle_counterexample()
            ),
        },
        "production_contract": dataclasses.asdict(
            check_production_contract(repo_root)
        ),
        "scope": {
            "proves": (
                "exact conditional row functionality, bounded decomposition "
                "uniqueness, finite strict-clock memory path structure, and "
                "root-connected Merkle index/depth/root propagation"
            ),
            "assumes": (
                "exact LogUp multiset equality rather than its randomized "
                "challenge reduction, public-root binding, and Poseidon/Merkle "
                "collision resistance where a root is treated as a commitment"
            ),
            "does_not_prove": (
                "PCS/FRI/Fiat-Shamir soundness, hash collision resistance, "
                "same-clock register ordering, opcode semantics, host builder "
                "correctness beyond pinned source fragments, or Sail refinement"
            ),
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    args = parser.parse_args(argv)
    print(
        json.dumps(
            build_report(args.repo_root.resolve()),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
