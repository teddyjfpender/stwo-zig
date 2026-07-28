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
* exact integer ``program_access`` balance binds fetches to a canonical
  program-leaf map, conditional on the Merkle commitment assumption;
* exact integer ``memory_access`` balance plus ordinary increasing clocks
  makes a finite RW-memory component one source-to-sink path, while field
  balance without a coefficient bound admits additional forgeries; the
  production statement now bounds every memory-relation coefficient side
  below p and therefore supplies that lift;
* a root-connected depth-30 Merkle path has the unique binary index/parity
  recurrence and carries one root; the production all-source bound lifts
  every Merkle coefficient side and excludes detached components under exact
  tuple balance; and
* a clock-update row preserves the memory key/value and advances the clock by
  exactly ``2**20 - 1`` inside the committed predecessor window.

Known counterexamples to stronger claims are emitted in the JSON report.  In
particular, the report distinguishes exact field balance from the stronger
integer-multiset premise needed by graph arguments.  The production-source
contract pins every claimed row layout and recurrence to the shipped Zig
constraints and relation declarations, so relevant source drift fails closed.

Run from the repository root:

    python3 -m scripts.riscv_infrastructure_uniqueness
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
from collections.abc import Sequence
from pathlib import Path

from scripts import riscv_merkle_recurrence
from scripts import riscv_state_chain_recurrence
from scripts.riscv_infrastructure_uniqueness_lib.contracts import (
    CLOCK_HIGH_BOUND,
    CLOCK_LOW_BASE,
    CLOCK_PREDECESSOR_BOUND,
    INV2,
    MAX_CLOCK_DIFF,
    MERKLE_DEPTH,
    P,
    PROGRAM_ADDRESS_BOUND,
    PROGRAM_HIGH_BOUND,
    PROGRAM_LOW_BASE,
    FieldCoefficientWrapCounterexample,
    RadixCertificate,
    RadixExhaustion,
    RelationRequest,
    TwoRowCounterexample,
    canonical_violations as _canonical_violations,
    exhaust_radix_uniqueness,
    radix_certificate,
    radix_decompositions,
    request as _request,
    row_snapshot as _row_snapshot,
)
from scripts.riscv_infrastructure_uniqueness_lib.production import (
    ProductionContract,
    check_production_contract as _check_production_contract,
    compact as _compact,
)
from scripts.riscv_infrastructure_uniqueness_lib.production_bindings import (
    ACCESS_CLOCK_PATH,
    CLOCK_COMPONENT_PATH,
    CLOCK_INTERACTION_PATH,
    CLOCK_TRACE_PATH,
    LOOKUP_ENTRY_PATH,
    M31_PATH,
    MEMORY_BOUNDARY_PATH,
    MEMORY_INTERACTION_PATH,
    MEMORY_LOGUP_PATH,
    MERKLE_NODE_PATH,
    PRODUCTION_PATHS,
    PROGRAM_COMMITMENT_PATH,
    PROGRAM_INTERACTION_PATH,
    PUBLIC_LOGUP_PATH,
    SOURCE_BINDINGS,
    SPARSE_MERKLE_PATH,
    STATE_CHAIN_PATH,
    STATE_COMMON_PATH,
    STATEMENT_PATH,
    STATEMENT_VALIDATION_PATH,
)
from scripts.riscv_infrastructure_uniqueness_lib.program_memory import (
    DetachedMemoryCycle,
    MemoryBoundaryRow,
    MemoryChainCheck,
    MemoryState,
    MemoryTransition,
    OfflineMemoryExhaustion,
    ProgramBindingCheck,
    ProgramRow,
    ProgramTuple,
    SameClockAliasCounterexample,
    detached_memory_cycle_counterexample,
    exhaustive_offline_memory_analogue,
    memory_boundary_counterexamples,
    memory_boundary_requests,
    memory_boundary_row_violations,
    memory_relation_balance,
    memory_state_violations,
    program_address_certificate,
    program_counterexamples,
    program_requests,
    program_row_violations,
    same_clock_alias_counterexample,
    verify_offline_memory_chain,
    verify_program_binding,
)


def check_production_contract(repo_root: Path) -> ProductionContract:
    return _check_production_contract(
        repo_root,
        merkle_contract_checker=riscv_merkle_recurrence.check_production_contract,
        clock_contract_checker=riscv_state_chain_recurrence.check_production_contract,
    )


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
    detached_depth_cycle_excluded: bool
    maximum_all_source_side_coefficient: int
    maximum_public_root_coefficient: int
    every_coefficient_side_below_field: bool
    field_balance_lifts_to_integer_balance: bool
    all_detached_components_excluded: bool
    conditional_on_exact_merkle_multiset_equality: bool
    conditional_on_integer_coefficient_lift: bool


def merkle_field_coefficient_wrap_counterexample(
    modulus: int = P,
) -> FieldCoefficientWrapCounterexample:
    """Retain the witness that motivated the stronger production node guard.

    Take ``(p - 1) / 2`` identical active Merkle rows with only parent
    multiplicity two, and one with only parent multiplicity one.  All edge
    multiplicities are locally admissible, the ordinary coefficient of that
    parent tuple is p, and its M31 coefficient is therefore zero.  Matching
    Poseidon rows can cancel each row's hash call one-for-one, so no depth
    cycle is involved.  The construction uses ``(p + 1) / 2 < p`` rows and is
    consequently admitted by the legacy ``n_rows < p`` depth-cycle guard, but
    rejected by the current ``2 * n_rows < p`` production guard.
    """

    if modulus <= 2 or modulus % 2 == 0:
        raise ValueError("counterexample needs an odd modulus greater than two")
    coefficient_two_rows = (modulus - 1) // 2
    coefficient_one_rows = 1
    active_rows = coefficient_two_rows + coefficient_one_rows
    ordinary_coefficient = 2 * coefficient_two_rows + coefficient_one_rows
    multiplicity_two = MerkleNodeRow(0, 1, 1, 2, 3, 0, 0, 2, 7)
    multiplicity_one = dataclasses.replace(
        multiplicity_two,
        current_multiplicity=1,
    )
    locally_admissible = (
        not merkle_row_violations(multiplicity_two)
        and not merkle_row_violations(multiplicity_one)
    )
    result = FieldCoefficientWrapCounterexample(
        field_modulus=modulus,
        maximum_row_coefficient=2,
        coefficient_two_rows=coefficient_two_rows,
        coefficient_one_rows=coefficient_one_rows,
        active_rows=active_rows,
        ordinary_coefficient=ordinary_coefficient,
        field_coefficient=ordinary_coefficient % modulus,
        admitted_by_rows_less_than_modulus=active_rows < modulus,
        admitted_by_production_node_guard=(
            active_rows <= (modulus - 1) // 2
        ),
        locally_admissible_multiplicities=locally_admissible,
        depth_cycle_present=False,
        consequence=(
            "the legacy n_rows < p guard excluded depth cycles but admitted "
            "this wrapped aggregate; the production 2 * n_rows < p guard "
            "rejects it and supplies the node-side integer lift"
        ),
    )
    if (
        result.field_coefficient != 0
        or not result.admitted_by_rows_less_than_modulus
        or result.admitted_by_production_node_guard
        or not result.locally_admissible_multiplicities
        or result.ordinary_coefficient == 0
    ):
        raise AssertionError("field-coefficient wrap counterexample is malformed")
    return result


def merkle_connectivity_certificate(
    exhaustive_prefix_depth: int = 12,
) -> MerkleConnectivityCertificate:
    """Combine path induction, production coefficient bounds, and a prefix.

    The production all-source guard bounds the combined coefficient from
    node, program, memory, and up to three public-root terms on either side by
    ``p - 1``.  Exact M31 equality therefore lifts side-by-side to integer
    equality.  The depth recurrence is acyclic below p rows, so a finite
    detached balanced component would have a source or sink and is impossible.
    """

    index = riscv_merkle_recurrence.index_certificate()
    cycle = riscv_merkle_recurrence.depth_cycle_certificate()
    field_wrap = merkle_field_coefficient_wrap_counterexample()
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
        detached_depth_cycle_excluded=cycle.detached_cycle_excluded,
        maximum_all_source_side_coefficient=P - 1,
        maximum_public_root_coefficient=3,
        every_coefficient_side_below_field=P - 1 < P,
        field_balance_lifts_to_integer_balance=(
            cycle.aggregate_coefficient_below_field
            and not field_wrap.admitted_by_production_node_guard
            and P - 1 < P
        ),
        all_detached_components_excluded=(
            cycle.detached_cycle_excluded
            and cycle.aggregate_coefficient_below_field
            and not field_wrap.admitted_by_production_node_guard
        ),
        conditional_on_exact_merkle_multiset_equality=True,
        conditional_on_integer_coefficient_lift=True,
    )
    if not all(
        (
            certificate.every_connected_base_index_even,
            certificate.every_leaf_index_is_unique_binary_path,
            certificate.detached_depth_cycle_excluded,
            certificate.every_coefficient_side_below_field,
            certificate.field_balance_lifts_to_integer_balance,
            certificate.all_detached_components_excluded,
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
    high6: int

    @classmethod
    def from_previous(
        cls,
        addr_space: int,
        addr: int,
        previous_clock: int,
        values: tuple[int, int, int, int],
    ) -> ClockUpdateRow:
        high6, low20 = divmod(previous_clock, CLOCK_LOW_BASE)
        return cls(addr_space, addr, previous_clock, values, low20, high6)


def clock_update_row_violations(row: ClockUpdateRow) -> tuple[str, ...]:
    """Decide the direct active clock AIR and its two range requests."""

    violations = _canonical_violations(
        (
            ("addr_space", row.addr_space),
            ("addr", row.addr),
            ("previous_clock", row.previous_clock),
            ("low20", row.low20),
            ("high6", row.high6),
            *((f"value[{index}]", value) for index, value in enumerate(row.values)),
        )
    )
    if len(row.values) != 4:
        violations.append("clock row must carry four values")
        return tuple(violations)
    if not 0 <= row.low20 < CLOCK_LOW_BASE:
        violations.append("low20 is outside range_check_20")
    if not 0 <= row.high6 < (1 << 8) or not 0 <= 4 * row.high6 < (1 << 8):
        violations.append("high6 or 4*high6 is outside range_check_8_8")
    if row.previous_clock % P != (row.low20 + CLOCK_LOW_BASE * row.high6) % P:
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
        _request("range_check_8_8", -1, (row.high6, 4 * row.high6)),
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
            "merkle_field_coefficient_wrap_counterexample": dataclasses.asdict(
                merkle_field_coefficient_wrap_counterexample()
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
                "uniqueness, finite strict-clock memory path structure under "
                "exact field tuple balance plus the production coefficient "
                "bounds, strict derived ordering of aliased instruction "
                "accesses, root-connected Merkle index/depth/root propagation, "
                "field-to-integer lifts for the memory and Merkle buses, and "
                "exclusion of detached Merkle components"
            ),
            "assumes": (
                "exact tuple-wise relation balance rather than its randomized "
                "LogUp challenge reduction; production admission of the "
                "source-bound coefficient guards; public-root binding; and "
                "Poseidon/Merkle collision resistance where a root is treated "
                "as a commitment"
            ),
            "does_not_prove": (
                "PCS/FRI/Fiat-Shamir soundness, hash collision resistance, "
                "Merkle root connectivity without exact tuple balance and the "
                "production all-source guards, "
                "opcode semantics, host builder correctness beyond pinned "
                "source fragments, or Sail refinement"
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
