#!/usr/bin/env python3
"""Tier-2 row-local rigidity checks for RISC-V Poseidon2 and lookup tables.

This checker proves two deliberately narrow statements.

* Poseidon2: on an active, narrow-mode row, the 16 input cells determine all
  426 materialized cells.  Together with the selector and narrow-mode shell,
  they determine the complete 445-cell main row.  The proof is a mechanical
  triangularity check over the independently transcribed constraint schedule.
* Lookup tables: a natural row index determines the exact preprocessed tuple
  for each of the six tables.  Given that tuple, the signed multiplicity, the
  previous cumulative value, is_first, the claim, and relation challenges, the
  singleton LogUp equation determines the current cumulative value whenever
  its denominator is nonzero.

The checker binds those transcriptions and derivations to exact SHA-256 digests
of the production Zig sources.  Any source drift fails closed until the
derivation is reviewed and the binding is deliberately refreshed.

This is not a proof verifier.  It does not read a proof, open a commitment,
check FRI/PCS/OODS, validate Fiat-Shamir sampling, establish global LogUp
closure, or prove a cross-row property.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence

try:
    from air_satisfaction_lib import infrastructure, poseidon2
    from air_satisfaction_lib.field import P, QM31, QM31_ONE, QM31_ZERO
except ModuleNotFoundError:  # Imported as scripts.riscv_poseidon_table_uniqueness.
    from scripts.air_satisfaction_lib import infrastructure, poseidon2
    from scripts.air_satisfaction_lib.field import P, QM31, QM31_ONE, QM31_ZERO


ROOT = Path(__file__).resolve().parents[1]

# These bindings cover the production AIR adapters, the constraint schedules,
# the fixed-table generator and placement, the singleton LogUp identity, and
# the independent Python transcriptions used by the constructive proof.
SOURCE_BINDINGS: dict[str, str] = {
    "src/frontends/riscv/air/memory_commitment/poseidon2_air.zig":
        "2187d5204b5e8b077a0e5d780b5311db99059099d2f3e61c8abec068d2c6723b",
    "src/frontends/riscv/air/memory_commitment/poseidon2_constants.zig":
        "d02b32f2f5302d21a440fbace2112d3232603e759cd0b24691c32e81d2bd4cfd",
    "src/frontends/riscv/air/memory_commitment/hash_component.zig":
        "fdbc208d5fec83f6b84f297a7c0d9bca4cdd452854a47853223e3831ea6a564b",
    "src/frontends/riscv/air/lookups/tables/schema.zig":
        "8ab73ea534acd89deb9ceb8fad83b1d9e775bf96aeb5a1e7344a0e1551bc3cef",
    "src/frontends/riscv/air/lookups/tables/interaction.zig":
        "429b3385c1352f2a86b1e968fdf6cf143b3916607b29bc41a540bdcef05eac2a",
    "src/frontends/riscv/air/lookups/tables/component.zig":
        "27678848907a62f3c3710ba44d0d6e2f098873d1f1a2a8b442f5f1e289eac7c0",
    "src/frontends/riscv/air/lookups/tables/counter.zig":
        "c371e5a5146fa1cc6efeca71210b51f2b9635b2af48850352e256f28f79c6d19",
    "src/frontends/riscv/air/logup.zig":
        "b1d18803eb05c44cc6546e8122c2c4f6e634796fef7df39cfed895c42e61c7f8",
    "src/frontends/riscv/prover/preprocessed.zig":
        "ac8c57ce3b164b4254d4f5d8570a929dcbf4f618993e12af85b16189330662dd",
    "src/frontends/riscv/prover/opcode_trace.zig":
        "4659a43c81cc442a14403fab0b85b2cdb28cba04ae39454143355ce676bd4d65",
    "src/frontends/riscv/infra_trace/permutation.zig":
        "2e6551f2c758b18f4a620d166b908a269297e9f1a74308c2ebd769dd8a474b98",
    "scripts/air_satisfaction_lib/poseidon2.py":
        "13e6e97035652e250859e2dfa77c20ff373dda47d1cc44b093e8725f64f0ede3",
    "scripts/air_satisfaction_lib/infrastructure.py":
        "b85e9e24a8e8f7796ef476fd7788ba3addac43e0d924776578ab6ef7491f44a8",
    "scripts/air_satisfaction_lib/field.py":
        "84402a223ddb4622fdeab073186ba9e3614dd5d9887d8b4c8e339e866571daf9",
}

TABLE_ORDER = (
    "bitwise",
    "range_check_20",
    "range_check_8_11",
    "range_check_8_8_4",
    "range_check_8_8",
    "range_check_m31",
)

# SHA-256 over, for every natural row, little-endian
# (natural_row, committed_row, tuple[0], tuple[1], tuple[2], tuple[3]).
# Missing tuple limbs are zero.  This pins both the tuple function and the
# circle-domain placement without storing roughly three million rows.
TABLE_SEMANTIC_DIGESTS = {
    "bitwise": "0e19d78e512562e5dd59ecb49acfd08eeec1b920568bdc48d44aa80bbccd7d54",
    "range_check_20": "ec6ae9336fc3923a3ef7607f248fac5c62e19019cfef04ac003cca36a3140235",
    "range_check_8_11": "113a078514116f8ccdb7c83df36740072517dab6ab1e1d98694774449c8aa62d",
    "range_check_8_8_4": "1ccfc1980bd3add53d310c584793fd8760f3706bb6540730c2ff447c4c8e8d68",
    "range_check_8_8": "2a0721cb88559eb416241bbc330dbf22fb9d57d7283b33b8de4b65ab7e77decf",
    "range_check_m31": "b4ab54610d360a6a28db6829844901646d9c66fac5566444d00aafaaaa80aaef",
}

EXPLANATION = """\
Exact theorem scope
===================

Poseidon2
---------
For two active RISC-V Poseidon2 rows in narrow mode, if their sixteen M31 input
cells agree and all 433 direct component constraints vanish, then all 445 main
cells agree.  The count splits as 427 permutation constraints (the enabler
boolean plus 426 materialization constraints), three generic flag constraints,
and three RISC-V shell constraints (active placement, wide=0, io=0).

The proof checks that, after the shell pins enabler=1, materialization constraint
i is affine with coefficient one in cell 17+i and depends otherwise only on the
inputs and already-determined cells.  This is an induction certificate, not
random testing.  Honest filled rows establish existence.  An explicit inactive
counterexample is retained: with is_active=enabler=0, two rows can agree on all
inputs and differ in an output cell while every direct constraint still
vanishes.  Padding-row uniqueness is therefore not claimed.

The production adapter reports 435 constraints in total: the 433 direct
constraints above plus two LogUp transition constraints.  The latter constrain
interaction columns using predecessor values, claims, and transcript
challenges; they are not inputs to the main-row triangular proof.

Six preprocessed lookup tables
------------------------------
For each natural row, the checker exhaustively compares the production-bound
table transcription with an independent formula and pins the committed-order
semantic digest.  The relation is row -> preprocessed tuple.  It is not always
invertible: range_check_m31 rows 0 and 32767 both contain (0, 0), while
(255, 127) is deliberately absent.

For a lookup-table transcript row, fix the preprocessed tuple, signed
multiplicity, previous cumulative QM31 value, is_first, claimed sum, and
relation challenges.  If D(tuple) != 0, the singleton LogUp equation has the
unique solution

    current = previous - is_first * claim - signed_multiplicity / D(tuple).

The nonzero-denominator premise is necessary.  If D(tuple)=0 and multiplicity
is zero, every current value satisfies the row equation; the checker constructs
this counterexample.  Signed multiplicities are derived from all source rows
globally and are inputs to this local functional theorem, not outputs it proves.

Not covered
-----------
No proof wire, PCS commitment, Merkle opening, FRI, OODS/composition check,
Fiat-Shamir sampling argument, global LogUp cancellation, bus closure, source
counter correctness, or cross-row transition is proved here.  Exact source
digests make the local derivation fail closed on production drift; they do not
turn it into independent proof-wire verification.
"""


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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_source_bindings(root: Path = ROOT) -> dict[str, str]:
    """Fail closed unless every reviewed production/transcription source matches."""
    actual: dict[str, str] = {}
    for relative, expected in SOURCE_BINDINGS.items():
        path = root / relative
        if not path.is_file():
            raise AuditError(f"bound source is missing: {relative}")
        digest = _sha256(path)
        actual[relative] = digest
        if digest != expected:
            raise AuditError(
                f"bound source digest changed: {relative}: "
                f"expected {expected}, got {digest}"
            )
    return actual


def _compact_zig(text: str) -> str:
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"\s+", "", text)


def _require_anchor(compact: str, anchor: str, source: str) -> None:
    if anchor not in compact:
        raise AuditError(f"reviewed semantic anchor disappeared from {source}: {anchor}")


def _production_semantic_anchors(root: Path) -> None:
    poseidon_source = "src/frontends/riscv/air/memory_commitment/poseidon2_air.zig"
    poseidon = _compact_zig((root / poseidon_source).read_text(encoding="utf-8"))
    for anchor in (
        "pubconstN_TEMPORARIES:usize=426;",
        "pubconstN_MAIN_COLUMNS:usize=1+WIDTH+N_TEMPORARIES+2;",
        "pubconstN_MATERIALIZATION_CONSTRAINTS:usize=N_TEMPORARIES;",
        "pubconstN_PERMUTATION_CONSTRAINTS:usize=1+N_MATERIALIZATION_CONSTRAINTS;",
        "pubconstN_FLAG_CONSTRAINTS:usize=3;",
        "result[0]=enabler.mul(one.sub(enabler));",
        "return.{main[WIDE_COLUMN],main[IO_COLUMN]};",
    ):
        _require_anchor(poseidon, anchor, poseidon_source)

    shell_source = "src/frontends/riscv/air/memory_commitment/hash_component.zig"
    shell = _compact_zig((root / shell_source).read_text(encoding="utf-8"))
    for anchor in (
        "constraints[poseidon2_air.N_CONSTRAINTS]=main[0].sub(is_active);",
        "constnarrow_mode=poseidon2_air.narrowModeConstraints(main);",
        "poseidon2_air.N_CONSTRAINTS+N_POSEIDON_SHELL_CONSTRAINTS+poseidon2_air.N_SUMS",
    ):
        _require_anchor(shell, anchor, shell_source)

    schema_source = "src/frontends/riscv/air/lookups/tables/schema.zig"
    schema = _compact_zig((root / schema_source).read_text(encoding="utf-8"))
    for anchor in (
        "pubconstKind=enum(u8){bitwise,range_check_20,range_check_8_11,"
        "range_check_8_8_4,range_check_8_8,range_check_m31,};",
        "if(row==size(kind)-1)return.{.len=2};",
        "constdst=table.map(row);",
    ):
        _require_anchor(schema, anchor, schema_source)

    table_interaction_source = "src/frontends/riscv/air/lookups/tables/interaction.zig"
    table_interaction = _compact_zig(
        (root / table_interaction_source).read_text(encoding="utf-8")
    )
    for anchor in (
        ".numerator=QM31.fromBase(signed_multiplicity).neg(),",
        "returnlogup.RowPair.single(relation_entry.numerator,"
        "tryrelation_entry.denominator(relations));",
        "returnlogup.pairConstraint(current,previous,is_first,claim,"
        "logup.RowPair.single(relation_entry.numerator,"
        "tryrelation_entry.denominator(relations)),);",
    ):
        _require_anchor(table_interaction, anchor, table_interaction_source)

    table_component_source = "src/frontends/riscv/air/lookups/tables/component.zig"
    table_component = _compact_zig(
        (root / table_component_source).read_text(encoding="utf-8")
    )
    for anchor in (
        "pubfnnConstraints(_:*const@This())usize{return1;}",
        "result[0]=self.is_first_col_idx;",
        "@memcpy(result[1..],self.tuple_col_indices[0..schema.arity(self.kind)]);",
        "returninteraction.evaluate(self.kind,tuple,signed_multiplicity,current,"
        "previous,is_first,self.claim,self.relations,);",
    ):
        _require_anchor(table_component, anchor, table_component_source)

    counter_source = "src/frontends/riscv/air/lookups/tables/counter.zig"
    counter = _compact_zig((root / counter_source).read_text(encoding="utf-8"))
    for anchor in (
        "self.values[row]=self.values[row].add(numerator);",
        "for(self.values,0..)|value,row|result[table.map(row)]=value;",
    ):
        _require_anchor(counter, anchor, counter_source)

    logup_source = "src/frontends/riscv/air/logup.zig"
    logup = _compact_zig((root / logup_source).read_text(encoding="utf-8"))
    for anchor in (
        "constdelta=s.sub(s_prev).add(is_first.mul(claimed));",
        "returndelta.mul(pair.d1).mul(pair.d2)"
        ".sub(pair.n1.mul(pair.d2)).sub(pair.n2.mul(pair.d1));",
    ):
        _require_anchor(logup, anchor, logup_source)

    preprocessed_source = "src/frontends/riscv/prover/preprocessed.zig"
    preprocessed = _compact_zig(
        (root / preprocessed_source).read_text(encoding="utf-8")
    )
    _require_anchor(
        preprocessed,
        "vartuples=trytable_schema.generatePreprocessed(allocator,kind);",
        preprocessed_source,
    )

    selectors_source = "src/frontends/riscv/prover/opcode_trace.zig"
    selectors = _compact_zig(
        (root / selectors_source).read_text(encoding="utf-8")
    )
    for anchor in (
        "@memset(values,M31.zero());",
        "values[placement.map(0)]=M31.one();",
        "for(0..n_rows)|row|values[placement.map(row)]=M31.one();",
    ):
        _require_anchor(selectors, anchor, selectors_source)

    permutation_source = "src/frontends/riscv/infra_trace/permutation.zig"
    permutation = _compact_zig(
        (root / permutation_source).read_text(encoding="utf-8")
    )
    _require_anchor(
        permutation,
        "destination.*=utils.bitReverseIndex("
        "utils.cosetIndexToCircleDomainIndex(row,log_size),log_size,);",
        permutation_source,
    )


def _zig_array(text: str, name: str) -> tuple[int, ...]:
    match = re.search(
        rf"pub\s+const\s+{re.escape(name)}\s*:[^=]+=\s*\.\{{(.*?)\n\}};",
        text,
        flags=re.DOTALL,
    )
    if match is None:
        raise AuditError(f"cannot locate production constant array {name}")
    return tuple(int(value) for value in re.findall(r"\b[0-9]+\b", match.group(1)))


def _verify_poseidon_constants(root: Path) -> None:
    source = (
        root
        / "src/frontends/riscv/air/memory_commitment/poseidon2_constants.zig"
    ).read_text(encoding="utf-8")
    external = _zig_array(source, "EXTERNAL_ROUND")
    internal = _zig_array(source, "INTERNAL_ROUND")
    matrix = _zig_array(source, "INTERNAL_MATRIX")
    python_external = tuple(value for row in poseidon2.EXTERNAL_ROUNDS for value in row)
    if external != python_external:
        raise AuditError("Python Poseidon2 external-round constants differ from production")
    if internal != poseidon2.INTERNAL_ROUNDS:
        raise AuditError("Python Poseidon2 internal-round constants differ from production")
    if matrix != poseidon2.INTERNAL_MATRIX:
        raise AuditError("Python Poseidon2 internal-matrix constants differ from production")


class _Expr:
    """Tiny field-expression DAG used only for the triangularity certificate."""

    __slots__ = ("op", "args", "deps")

    def __init__(
        self,
        op: str,
        args: tuple[object, ...],
        deps: frozenset[str],
    ) -> None:
        self.op = op
        self.args = args
        self.deps = deps

    @staticmethod
    def constant(value: int) -> "_Expr":
        return _Expr("const", (value % P,), frozenset())

    @staticmethod
    def atom(name: str) -> "_Expr":
        return _Expr("atom", (name,), frozenset((name,)))

    def constant_value(self) -> int | None:
        return int(self.args[0]) if self.op == "const" else None

    def __add__(self, other: object) -> "_Expr":
        return _binary("add", self, _coerce(other))

    def __radd__(self, other: object) -> "_Expr":
        return _binary("add", _coerce(other), self)

    def __sub__(self, other: object) -> "_Expr":
        return _binary("sub", self, _coerce(other))

    def __rsub__(self, other: object) -> "_Expr":
        return _binary("sub", _coerce(other), self)

    def __mul__(self, other: object) -> "_Expr":
        return _binary("mul", self, _coerce(other))

    def __rmul__(self, other: object) -> "_Expr":
        return _binary("mul", _coerce(other), self)

    def __mod__(self, modulus: int) -> "_Expr":
        if modulus != P:
            raise AuditError(f"symbolic Poseidon2 used unexpected modulus {modulus}")
        return self


def _coerce(value: object) -> _Expr:
    if isinstance(value, _Expr):
        return value
    if isinstance(value, int):
        return _Expr.constant(value)
    raise TypeError(f"cannot coerce {type(value).__name__} into a field expression")


def _binary(op: str, lhs: _Expr, rhs: _Expr) -> _Expr:
    left = lhs.constant_value()
    right = rhs.constant_value()
    if left is not None and right is not None:
        if op == "add":
            return _Expr.constant(left + right)
        if op == "sub":
            return _Expr.constant(left - right)
        if op == "mul":
            return _Expr.constant(left * right)
    if op == "add":
        if left == 0:
            return rhs
        if right == 0:
            return lhs
    elif op == "sub":
        if right == 0:
            return lhs
    elif op == "mul":
        if left == 0 or right == 0:
            return _Expr.constant(0)
        if left == 1:
            return rhs
        if right == 1:
            return lhs
    return _Expr(op, (lhs, rhs), lhs.deps | rhs.deps)


def _coefficient(expression: _Expr, target: str) -> _Expr:
    """Return the affine coefficient of target, rejecting nonlinear use."""
    if target not in expression.deps:
        return _Expr.constant(0)
    if expression.op == "atom":
        if expression.args[0] != target:
            raise AuditError("expression dependency metadata is inconsistent")
        return _Expr.constant(1)
    if expression.op == "const":
        raise AuditError("constant unexpectedly depends on a column")
    lhs, rhs = expression.args
    assert isinstance(lhs, _Expr) and isinstance(rhs, _Expr)
    if expression.op == "add":
        return _coefficient(lhs, target) + _coefficient(rhs, target)
    if expression.op == "sub":
        return _coefficient(lhs, target) - _coefficient(rhs, target)
    if expression.op == "mul":
        in_lhs = target in lhs.deps
        in_rhs = target in rhs.deps
        if in_lhs and in_rhs:
            raise AuditError(f"{target} occurs nonlinearly in its determining equation")
        if in_lhs:
            return _coefficient(lhs, target) * rhs
        return lhs * _coefficient(rhs, target)
    raise AuditError(f"unknown symbolic operation {expression.op}")


def _is_zero(expression: _Expr) -> bool:
    return expression.constant_value() == 0


def _poseidon_symbolic_residuals(
    *,
    active_shell: bool,
) -> tuple[tuple[_Expr, ...], tuple[_Expr, ...]]:
    generic_row = [_Expr.atom(f"main_{column}") for column in range(poseidon2.N_MAIN_COLUMNS)]
    generic = tuple(poseidon2.residuals(generic_row, _Expr.constant(1)))

    active_row: list[_Expr] = [_Expr.constant(0)] * poseidon2.N_MAIN_COLUMNS
    active_row[0] = _Expr.constant(1)
    for column in range(poseidon2.INPUT_START, poseidon2.TEMP_START):
        active_row[column] = _Expr.atom(f"main_{column}")
    for column in range(poseidon2.TEMP_START, poseidon2.WIDE_COLUMN):
        active_row[column] = _Expr.atom(f"main_{column}")
    active_row[poseidon2.WIDE_COLUMN] = _Expr.constant(0 if active_shell else 1)
    active_row[poseidon2.IO_COLUMN] = _Expr.constant(0)
    active = tuple(poseidon2.residuals(active_row, _Expr.constant(1)))
    return generic, active


def _audit_poseidon_schedule(
    mutate_residuals: Callable[[list[_Expr]], None] | None = None,
) -> None:
    if (
        poseidon2.WIDTH != 16
        or poseidon2.N_TEMPORARIES != 426
        or poseidon2.N_MAIN_COLUMNS != 445
        or poseidon2.TEMP_START != 17
        or poseidon2.WIDE_COLUMN != 443
        or poseidon2.IO_COLUMN != 444
    ):
        raise AuditError("Poseidon2 transcription geometry drifted")

    generic, active_tuple = _poseidon_symbolic_residuals(active_shell=True)
    if len(generic) != 433 or len(active_tuple) != 433:
        raise AuditError("Poseidon2 component-direct constraint count is not 433")

    # The production wrapper's shell must actually pin the values assumed by
    # the triangular induction.
    shell_targets = (
        (430, "main_0"),
        (431, f"main_{poseidon2.WIDE_COLUMN}"),
        (432, f"main_{poseidon2.IO_COLUMN}"),
    )
    for index, target in shell_targets:
        residual = generic[index]
        if residual.deps != frozenset((target,)):
            raise AuditError(
                f"Poseidon2 shell residual {index} does not isolate {target}"
            )
        coefficient = _coefficient(residual, target)
        if coefficient.constant_value() != 1:
            raise AuditError(
                f"Poseidon2 shell residual {index} has non-unit {target} coefficient"
            )

    active = list(active_tuple)
    if mutate_residuals is not None:
        mutate_residuals(active)
    if len(active) != 433:
        raise AuditError("Poseidon2 residual mutation changed the reviewed count")

    for index in (0, 427, 428, 429, 430, 431, 432):
        if not _is_zero(active[index]):
            raise AuditError(
                f"active narrow Poseidon2 shell residual {index} is not identically zero"
            )

    inputs = {
        f"main_{column}"
        for column in range(poseidon2.INPUT_START, poseidon2.TEMP_START)
    }
    determined: set[str] = set()
    for ordinal, column in enumerate(
        range(poseidon2.TEMP_START, poseidon2.WIDE_COLUMN)
    ):
        constraint_index = 1 + ordinal
        target = f"main_{column}"
        residual = active[constraint_index]
        if target not in residual.deps:
            raise AuditError(
                f"Poseidon2 constraint {constraint_index} does not determine {target}"
            )
        coefficient = _coefficient(residual, target)
        if coefficient.constant_value() != 1:
            raise AuditError(
                f"Poseidon2 constraint {constraint_index} has non-unit "
                f"coefficient for {target}"
            )
        unexpected = residual.deps - inputs - determined - {target}
        if unexpected:
            raise AuditError(
                f"Poseidon2 constraint {constraint_index} depends on future cells: "
                f"{sorted(unexpected)}"
            )
        determined.add(target)
    if len(determined) != poseidon2.N_TEMPORARIES:
        raise AuditError("Poseidon2 induction did not cover every materialized cell")


def _poseidon_nonvacuity_and_mutations() -> tuple[int, int]:
    vectors = (
        (0,) * poseidon2.WIDTH,
        (1, 2) + (0,) * (poseidon2.WIDTH - 2),
        tuple(range(poseidon2.WIDTH)),
        (P - 1,) * poseidon2.WIDTH,
    )
    for vector in vectors:
        row = poseidon2.fill(vector)
        residuals = poseidon2.residuals(row, 1)
        if len(residuals) != 433 or any(residuals):
            raise AuditError(f"honest Poseidon2 row is unsatisfied for input {vector}")

    baseline = poseidon2.fill(vectors[1])
    rejected = 0
    for column in range(poseidon2.TEMP_START, poseidon2.WIDE_COLUMN):
        mutation = list(baseline)
        mutation[column] = (mutation[column] + 1) % P
        if not any(poseidon2.residuals(mutation, 1)):
            raise AuditError(f"Poseidon2 cell mutation escaped at column {column}")
        rejected += 1
    for column in (0, poseidon2.WIDE_COLUMN, poseidon2.IO_COLUMN):
        mutation = list(baseline)
        mutation[column] = (mutation[column] + 1) % P
        if not any(poseidon2.residuals(mutation, 1)):
            raise AuditError(f"Poseidon2 shell mutation escaped at column {column}")
        rejected += 1
    return len(vectors), rejected


def _poseidon_inactive_counterexample() -> bool:
    first = [0] * poseidon2.N_MAIN_COLUMNS
    second = first.copy()
    second[poseidon2.OUTPUT_START] = 1
    if first[poseidon2.INPUT_START : poseidon2.TEMP_START] != second[
        poseidon2.INPUT_START : poseidon2.TEMP_START
    ]:
        raise AuditError("inactive Poseidon2 counterexample inputs unexpectedly differ")
    return (
        not any(poseidon2.residuals(first, 0))
        and not any(poseidon2.residuals(second, 0))
        and first[poseidon2.OUTPUT_START] != second[poseidon2.OUTPUT_START]
    )


def audit_poseidon2(root: Path = ROOT) -> PoseidonAudit:
    _verify_poseidon_constants(root)
    _audit_poseidon_schedule()
    nonvacuity, rejected = _poseidon_nonvacuity_and_mutations()
    inactive = _poseidon_inactive_counterexample()
    if not inactive:
        raise AuditError("expected inactive Poseidon2 non-uniqueness disappeared")
    return PoseidonAudit(
        main_columns=poseidon2.N_MAIN_COLUMNS,
        inputs=poseidon2.WIDTH,
        materialized_cells=poseidon2.N_TEMPORARIES,
        permutation_constraints=1 + poseidon2.N_TEMPORARIES,
        generic_direct_constraints=1 + poseidon2.N_TEMPORARIES + 3,
        component_direct_constraints=433,
        component_interaction_constraints=2,
        component_total_constraints=435,
        nonvacuity_rows=nonvacuity,
        rejected_cell_mutations=rejected,
        inactive_counterexample=True,
        theorem=(
            "active narrow rows agreeing on 16 inputs agree on all 445 main cells"
        ),
    )


def _table_formula(kind: str, row: int) -> tuple[int, ...]:
    size = 1 << infrastructure.TABLE_LOG_SIZES[kind]
    if not 0 <= row < size:
        raise ValueError(f"{kind} row {row} outside domain")
    low8 = row & 0xFF
    if kind == "bitwise":
        high8 = (row >> 8) & 0xFF
        operation = (row >> 16) & 0x3
        output = (
            low8 & high8,
            low8 | high8,
            low8 ^ high8,
            0,
        )[operation]
        return low8, high8, output, operation
    if kind == "range_check_20":
        return (row,)
    if kind == "range_check_8_11":
        return low8, row >> 8
    if kind == "range_check_8_8_4":
        return low8, (row >> 8) & 0xFF, row >> 16
    if kind == "range_check_8_8":
        return low8, row >> 8
    if kind == "range_check_m31":
        return (0, 0) if row == size - 1 else (low8, row >> 8)
    raise ValueError(f"unknown table {kind}")


def _table_index(kind: str, values: Sequence[int]) -> int:
    expected_arity = infrastructure.TABLE_ARITIES[kind]
    if len(values) != expected_arity:
        raise ValueError("invalid tuple arity")
    if kind == "bitwise":
        lhs, rhs, output, operation = values
        if lhs >= 256 or rhs >= 256 or output >= 256 or operation >= 4:
            raise ValueError("bitwise tuple outside boxes")
        expected = (lhs & rhs, lhs | rhs, lhs ^ rhs, 0)[operation]
        if output != expected:
            raise ValueError("invalid bitwise result")
        return lhs | (rhs << 8) | (operation << 16)
    widths = {
        "range_check_20": (20,),
        "range_check_8_11": (8, 11),
        "range_check_8_8_4": (8, 8, 4),
        "range_check_8_8": (8, 8),
        "range_check_m31": (8, 7),
    }[kind]
    if any(value < 0 or value >= 1 << width for value, width in zip(values, widths)):
        raise ValueError("range tuple outside boxes")
    if kind == "range_check_m31" and tuple(values) == (255, 127):
        raise ValueError("forbidden range-M31 tuple")
    row = values[0]
    for value, shift in zip(values[1:], (8, 16)):
        row |= value << shift
    return row


def _bit_reverse(index: int, bits: int) -> int:
    result = 0
    for _ in range(bits):
        result = (result << 1) | (index & 1)
        index >>= 1
    return result


def _committed_index(row: int, log_size: int) -> int:
    circle = row // 2 if row % 2 == 0 else ((2 << log_size) - row) // 2
    return _bit_reverse(circle, log_size)


def _dummy_powers() -> tuple[tuple[int, int, int, int], ...]:
    alpha = QM31(4, 3, 2, 1)
    powers = [QM31_ONE]
    for _ in range(infrastructure.TABLE_ARITIES["bitwise"] - 1):
        powers.append(powers[-1] * alpha)
    return tuple(power.as_tuple() for power in powers)


def _dummy_denominator_coordinates(
    values: Sequence[int],
    powers: Sequence[tuple[int, int, int, int]],
) -> tuple[int, int, int, int]:
    coordinates = [-1, -2, -3, -4]
    for value, power in zip(values, powers):
        for coordinate in range(4):
            coordinates[coordinate] += value * power[coordinate]
    return tuple(value % P for value in coordinates)  # type: ignore[return-value]


def _dummy_denominator(values: Sequence[int]) -> QM31:
    return QM31(*_dummy_denominator_coordinates(values, _dummy_powers()))


def _transition_residual(
    *,
    signed_multiplicity: int,
    current: QM31,
    previous: QM31,
    is_first: int,
    claim: QM31,
    denominator: QM31,
) -> QM31:
    numerator = -QM31.from_base(signed_multiplicity)
    delta = current - previous + claim.mul_base(is_first)
    return delta * denominator - numerator


def _nonzero_transcript_control(kind: str) -> bool:
    """Construct a full-domain trace with one nonzero multiplicity at row 17."""
    row = 17
    denominator = _dummy_denominator(_table_formula(kind, row))
    if denominator.is_zero():
        return False
    increment = denominator.inv()  # signed multiplicity -1 => table numerator +1.
    zero = QM31_ZERO

    # These are all distinct row shapes in the piecewise full-domain trace:
    # row 0 wraps from the final claim, rows before 17 stay at zero, row 17
    # adds the one term, and every later row stays at the claim.
    checks = (
        _transition_residual(
            signed_multiplicity=0,
            current=zero,
            previous=increment,
            is_first=1,
            claim=increment,
            denominator=_dummy_denominator(_table_formula(kind, 0)),
        ),
        _transition_residual(
            signed_multiplicity=0,
            current=zero,
            previous=zero,
            is_first=0,
            claim=increment,
            denominator=_dummy_denominator(_table_formula(kind, row - 1)),
        ),
        _transition_residual(
            signed_multiplicity=P - 1,
            current=increment,
            previous=zero,
            is_first=0,
            claim=increment,
            denominator=denominator,
        ),
        _transition_residual(
            signed_multiplicity=0,
            current=increment,
            previous=increment,
            is_first=0,
            claim=increment,
            denominator=_dummy_denominator(_table_formula(kind, row + 1)),
        ),
        _transition_residual(
            signed_multiplicity=0,
            current=increment,
            previous=increment,
            is_first=0,
            claim=increment,
            denominator=_dummy_denominator(
                _table_formula(kind, (1 << infrastructure.TABLE_LOG_SIZES[kind]) - 1)
            ),
        ),
    )
    if any(not value.is_zero() for value in checks):
        return False

    # The row equation reacts to either copy changing its purported output.
    mutated = _transition_residual(
        signed_multiplicity=P - 1,
        current=increment + QM31_ONE,
        previous=zero,
        is_first=0,
        claim=increment,
        denominator=denominator,
    )
    return mutated == denominator and not mutated.is_zero()


def _zero_denominator_counterexample() -> bool:
    common = dict(
        signed_multiplicity=0,
        previous=QM31_ZERO,
        is_first=0,
        claim=QM31_ZERO,
        denominator=QM31_ZERO,
    )
    first = _transition_residual(current=QM31_ZERO, **common)
    second = _transition_residual(current=QM31_ONE, **common)
    return first.is_zero() and second.is_zero()


def audit_tables(
    tuple_function: Callable[[str, int], tuple[int, ...]] = infrastructure.table_tuple,
) -> tuple[TableAudit, ...]:
    if tuple(infrastructure.TABLE_LOG_SIZES) != TABLE_ORDER:
        raise AuditError("lookup table order drifted from the transcript order")
    if set(infrastructure.TABLE_ARITIES) != set(TABLE_ORDER):
        raise AuditError("lookup table arity set drifted")

    powers = _dummy_powers()
    results: list[TableAudit] = []
    for kind in TABLE_ORDER:
        log_size = infrastructure.TABLE_LOG_SIZES[kind]
        arity = infrastructure.TABLE_ARITIES[kind]
        size = 1 << log_size
        digest = hashlib.sha256()
        zero_denominators = 0
        for row in range(size):
            actual = tuple_function(kind, row)
            expected = _table_formula(kind, row)
            if actual != expected:
                raise AuditError(
                    f"{kind} row {row} is {actual}, expected deterministic {expected}"
                )
            if len(actual) != arity or any(not 0 <= value < P for value in actual):
                raise AuditError(f"{kind} row {row} is not a canonical arity-{arity} tuple")
            inverse = _table_index(kind, actual)
            if kind == "range_check_m31" and row == size - 1:
                if inverse != 0 or actual != (0, 0):
                    raise AuditError("range-M31 duplicate-row contract drifted")
            elif inverse != row:
                raise AuditError(f"{kind} row {row} does not roundtrip through its tuple")
            padded = actual + (0,) * (4 - len(actual))
            digest.update(
                struct.pack(
                    "<II4I",
                    row,
                    _committed_index(row, log_size),
                    *padded,
                )
            )
            if _dummy_denominator_coordinates(actual, powers) == (0, 0, 0, 0):
                zero_denominators += 1

        semantic_digest = digest.hexdigest()
        if semantic_digest != TABLE_SEMANTIC_DIGESTS[kind]:
            raise AuditError(
                f"{kind} semantic digest changed: expected "
                f"{TABLE_SEMANTIC_DIGESTS[kind]}, got {semantic_digest}"
            )
        control = _nonzero_transcript_control(kind)
        if not control:
            raise AuditError(f"{kind} nonzero transcript non-vacuity control failed")
        if zero_denominators:
            raise AuditError(
                f"{kind} dummy relation has {zero_denominators} zero denominators"
            )
        results.append(
            TableAudit(
                kind=kind,
                log_size=log_size,
                arity=arity,
                rows=size,
                semantic_digest=semantic_digest,
                dummy_zero_denominators=zero_denominators,
                nonzero_transcript_control=control,
                is_first_deterministic=True,
                row_to_tuple_deterministic=True,
                tuple_to_row_injective=kind != "range_check_m31",
            )
        )

    try:
        _table_index("range_check_m31", (255, 127))
    except ValueError:
        pass
    else:
        raise AuditError("forbidden range-M31 tuple became addressable")
    return tuple(results)


def run_audit(root: Path = ROOT) -> AuditReport:
    sources = verify_source_bindings(root)
    _production_semantic_anchors(root)
    poseidon = audit_poseidon2(root)
    tables = audit_tables()
    zero_counterexample = _zero_denominator_counterexample()
    if not zero_counterexample:
        raise AuditError("zero-denominator transcript counterexample disappeared")
    return AuditReport(
        source_files=len(sources),
        poseidon2=poseidon,
        tables=tables,
        total_table_rows=sum(table.rows for table in tables),
        zero_denominator_counterexample=True,
        exclusions=(
            "inactive/padding Poseidon2 row uniqueness",
            "Poseidon2 interaction-column and bus-closure uniqueness",
            "unconditioned zero-denominator transcript uniqueness",
            "lookup signed-multiplicity source correctness",
            "cross-row and global LogUp closure",
            "proof-wire PCS/FRI/OODS/Fiat-Shamir verification",
        ),
    )


def _print_report(report: AuditReport) -> None:
    poseidon = report.poseidon2
    print(f"SOURCE BINDING: {report.source_files}/{report.source_files} exact SHA-256")
    print(
        "POSEIDON2: "
        f"{poseidon.main_columns} main columns, {poseidon.materialized_cells} "
        f"materializations, {poseidon.permutation_constraints} permutation / "
        f"{poseidon.generic_direct_constraints} generic direct / "
        f"{poseidon.component_direct_constraints} active-narrow component direct + "
        f"{poseidon.component_interaction_constraints} interaction = "
        f"{poseidon.component_total_constraints} total constraints"
    )
    print(f"  UNIQUE: {poseidon.theorem}")
    print(
        f"  NON-VACUOUS: {poseidon.nonvacuity_rows} honest rows; "
        f"{poseidon.rejected_cell_mutations} one-cell mutations rejected"
    )
    print(
        "  EXPECTED COUNTEREXAMPLE: inactive rows can agree on inputs and differ "
        "in output while all direct constraints vanish"
    )
    print("LOOKUP TABLES:")
    for table in report.tables:
        injective = "injective" if table.tuple_to_row_injective else "not injective"
        print(
            f"  {table.kind}: log={table.log_size} arity={table.arity} "
            f"rows={table.rows} is_first/row->tuple deterministic, "
            f"tuple->row {injective}, "
            f"dummy zero denominators={table.dummy_zero_denominators}"
        )
    print(
        f"  DETERMINISTIC: {report.total_table_rows} rows exhaustively checked in "
        "natural and committed placement"
    )
    print(
        "  CONDITIONAL UNIQUE: with tuple, multiplicity, predecessor, is_first, "
        "claim, and challenges fixed, D(tuple) != 0 uniquely determines current"
    )
    print(
        "  EXPECTED COUNTEREXAMPLES: range_check_m31 rows 0 and 32767 both map "
        "to (0, 0); D=0 with zero multiplicity leaves current unconstrained"
    )
    print("EXCLUDED: " + "; ".join(report.exclusions))
    print("VERDICT: PASS (row-local theorem only; not proof-wire verification)")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("explain", help="print exact theorem and exclusions")
    check = subparsers.add_parser("check", help="run the fail-closed certificate")
    check.add_argument("--root", type=Path, default=ROOT)
    check.add_argument("--json", type=Path, help="write the structured report")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "explain":
        print(EXPLANATION)
        return 0
    try:
        report = run_audit(args.root.resolve())
    except (AuditError, OSError, ValueError) as error:
        print(f"VERDICT: FAIL: {error}", file=sys.stderr)
        return 1
    _print_report(report)
    if args.json is not None:
        args.json.write_text(json.dumps(asdict(report), indent=2) + "\n", encoding="utf-8")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
