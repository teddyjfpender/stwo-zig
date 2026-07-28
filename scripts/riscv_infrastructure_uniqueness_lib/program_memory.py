"""Program commitment and offline-memory uniqueness certificates."""

from __future__ import annotations

import dataclasses
from collections import Counter
from collections.abc import Sequence

from .contracts import (
    MERKLE_DEPTH,
    P,
    PROGRAM_ADDRESS_BOUND,
    PROGRAM_HIGH_BOUND,
    PROGRAM_LOW_BASE,
    RadixCertificate,
    RelationRequest,
    TwoRowCounterexample,
    canonical_violations as _canonical_violations,
    radix_certificate,
    request as _request,
    row_snapshot as _row_snapshot,
)


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
    field_coefficient_lift_safe: bool


def verify_program_binding(
    rows: Sequence[ProgramRow],
    fetches: Sequence[ProgramTuple],
    *,
    public_root: int,
) -> ProgramBindingCheck:
    """Check the non-cryptographic part of the program-binding lemma.

    This function assumes that one canonical leaf map is the leaf opening of
    ``public_root``. Establishing that assumption from a root is the Merkle
    collision-resistance claim, not an AIR row-local uniqueness theorem. The
    comparison below is deliberately over ordinary integer multiplicities,
    not merely M31 residues. For production fetches the admitted execution
    bound is below p; together with one canonical row per tuple, that is the
    coefficient-lift premise which makes field equality imply this comparison.
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
    coefficient_lift_safe = canonical_leaf_map and len(fetches) < P
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
        coefficient_lift_safe,
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


def memory_state_violations(state: MemoryState) -> tuple[str, ...]:
    """Require the Python graph nodes to denote canonical relation tuples."""
    violations = _canonical_violations(
        (
            ("addr_space", state.addr_space),
            ("addr", state.addr),
            ("clock", state.clock),
            *((f"value[{index}]", value) for index, value in enumerate(state.values)),
        )
    )
    if len(state.values) != 4:
        violations.append("memory state must carry four values")
    return tuple(violations)


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

    Exact *integer* tuple balance supplies value continuity. Strict ordinary
    clock increase makes the graph acyclic. A finite positive integral flow
    with one unit source and one unit sink can then neither branch nor contain
    a detached component, so it is one path. Equality of M31 coefficients is
    not enough unless a separate row/count bound lifts every coefficient to
    its ordinary integer representative.
    """
    expected_key = initial.key()
    states = [initial, final]
    for transition in transitions:
        states.extend((transition.previous, transition.next))
    for index, state in enumerate(states):
        violations = memory_state_violations(state)
        if violations:
            return MemoryChainCheck(
                False,
                f"state {index}: {violations[0]}",
                len(transitions),
                False,
                False,
                False,
                (),
                (),
            )
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
    """The legacy shared-clock alias forgery versus derived subclocks."""

    architectural_scenario: str
    initial: MemoryState
    honest_first_source: MemoryState
    honest_final_source: MemoryState
    forged_shared_clock_source: MemoryState
    legacy_transitions: tuple[MemoryTransition, ...]
    derived_subclock_transitions: tuple[MemoryTransition, ...]
    legacy_exact_relation_balance: bool
    derived_subclock_exact_relation_balance: bool
    forged_value_differs_from_honest_value: bool
    legacy_second_source_term_is_identically_zero: bool
    derived_second_source_term_is_identically_zero: bool
    derived_forgery_rejected: bool
    consequence: str


def same_clock_alias_counterexample() -> SameClockAliasCounterexample:
    """Show that strict derived subclocks reject the old aliased-source attack.

    The first source advances the honest x1 chain from clock zero to the
    instruction's first access clock with value A. Under the legacy protocol,
    the second source could claim previous value B and emit B at that same
    clock. Its ``-1/(x1,t,B) + 1/(x1,t,B)`` contribution vanishes for every
    relation challenge. Under the shipped protocol the second source emits at
    ``t+1``: the forged B edge is no longer a self-loop and leaves four
    unmatched tuples against the honest A boundary.
    """
    honest_value = (5, 0, 0, 0)
    forged_value = (9, 0, 0, 0)
    initial = MemoryState(0, 1, 0, honest_value)
    honest_first = MemoryState(0, 1, 5, honest_value)
    honest_final = MemoryState(0, 1, 6, honest_value)
    forged_shared = MemoryState(0, 1, 5, forged_value)
    forged_next = MemoryState(0, 1, 6, forged_value)
    legacy_transitions = (
        MemoryTransition(initial, honest_first, "first x1 source"),
        MemoryTransition(
            forged_shared,
            forged_shared,
            "legacy second aliased x1 source",
        ),
    )
    derived_transitions = (
        MemoryTransition(initial, honest_first, "first x1 source"),
        MemoryTransition(
            forged_shared,
            forged_next,
            "derived-clock second aliased x1 source",
        ),
    )
    result = SameClockAliasCounterexample(
        architectural_scenario="ADD x3, x1, x1",
        initial=initial,
        honest_first_source=honest_first,
        honest_final_source=honest_final,
        forged_shared_clock_source=forged_shared,
        legacy_transitions=legacy_transitions,
        derived_subclock_transitions=derived_transitions,
        legacy_exact_relation_balance=not _nonzero_balance(
            initial, honest_first, legacy_transitions
        ),
        derived_subclock_exact_relation_balance=not _nonzero_balance(
            initial, honest_final, derived_transitions
        ),
        forged_value_differs_from_honest_value=(
            forged_shared.values != honest_first.values
        ),
        legacy_second_source_term_is_identically_zero=(
            legacy_transitions[1].previous == legacy_transitions[1].next
        ),
        derived_second_source_term_is_identically_zero=(
            derived_transitions[1].previous == derived_transitions[1].next
        ),
        derived_forgery_rejected=bool(
            _nonzero_balance(initial, honest_final, derived_transitions)
        ),
        consequence=(
            "the old A + B forgery no longer balances memory_access: the "
            "second aliased source must continue the A chain from the first "
            "derived access clock to the second"
        ),
    )
    if not all(
        (
            result.legacy_exact_relation_balance,
            not result.derived_subclock_exact_relation_balance,
            result.forged_value_differs_from_honest_value,
            result.legacy_second_source_term_is_identically_zero,
            not result.derived_second_source_term_is_identically_zero,
            result.derived_forgery_rejected,
        )
    ):
        raise AssertionError("same-clock alias counterexample is malformed")
    return result
