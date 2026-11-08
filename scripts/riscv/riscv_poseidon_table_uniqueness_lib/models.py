"""Typed results shared by the Poseidon2 and lookup-table audits."""

from dataclasses import dataclass


class AuditError(RuntimeError):
    """The claimed certificate could not be established."""


@dataclass(frozen=True)
class PoseidonAudit:
    main_columns: int
    inputs: int
    materialized_cells: int
    permutation_constraints: int
    generic_direct_constraints: int
    component_direct_constraints: int
    component_interaction_constraints: int
    component_total_constraints: int
    nonvacuity_rows: int
    rejected_cell_mutations: int
    inactive_counterexample: bool
    theorem: str


@dataclass(frozen=True)
class TableAudit:
    kind: str
    log_size: int
    arity: int
    rows: int
    semantic_digest: str
    dummy_zero_denominators: int
    nonzero_transcript_control: bool
    is_first_deterministic: bool
    row_to_tuple_deterministic: bool
    tuple_to_row_injective: bool


@dataclass(frozen=True)
class AuditReport:
    source_files: int
    poseidon2: PoseidonAudit
    tables: tuple[TableAudit, ...]
    total_table_rows: int
    zero_denominator_counterexample: bool
    exclusions: tuple[str, ...]
