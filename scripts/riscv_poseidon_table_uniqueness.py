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
of the reviewed production Zig sources.  Any bound-source drift fails closed
until the derivation is reviewed and the binding is deliberately refreshed.

This is not a proof verifier.  It does not read a proof, open a commitment,
check FRI/PCS/OODS, validate Fiat-Shamir sampling, establish global LogUp
closure, or prove a cross-row property.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Callable, Sequence

try:
    from air_satisfaction_lib import infrastructure, poseidon2
    from air_satisfaction_lib.field import P, QM31, QM31_ONE, QM31_ZERO
    from riscv_poseidon_table_uniqueness_lib.models import (
        AuditError,
        AuditReport,
        PoseidonAudit,
        TableAudit,
    )
    from riscv_poseidon_table_uniqueness_lib.tables import (
        TABLE_ORDER,
        TABLE_SEMANTIC_DIGESTS,
        audit_tables,
        committed_index as _committed_index,
        dummy_denominator as _dummy_denominator,
        table_formula as _table_formula,
        table_index as _table_index,
        transition_residual as _transition_residual,
        zero_denominator_counterexample as _zero_denominator_counterexample,
    )
except ModuleNotFoundError:  # Imported as scripts.riscv_poseidon_table_uniqueness.
    from scripts.air_satisfaction_lib import infrastructure, poseidon2
    from scripts.air_satisfaction_lib.field import P, QM31, QM31_ONE, QM31_ZERO
    from scripts.riscv_poseidon_table_uniqueness_lib.models import (
        AuditError,
        AuditReport,
        PoseidonAudit,
        TableAudit,
    )
    from scripts.riscv_poseidon_table_uniqueness_lib.tables import (
        TABLE_ORDER,
        TABLE_SEMANTIC_DIGESTS,
        audit_tables,
        committed_index as _committed_index,
        dummy_denominator as _dummy_denominator,
        table_formula as _table_formula,
        table_index as _table_index,
        transition_residual as _transition_residual,
        zero_denominator_counterexample as _zero_denominator_counterexample,
    )


ROOT = Path(__file__).resolve().parents[1]

# These bindings cover field and relation-challenge algebra, the production AIR
# adapters and constraint schedules, the fixed-table generator and placement,
# the singleton LogUp identity, and the independent Python transcriptions used
# by the constructive proof.
SOURCE_BINDINGS: dict[str, str] = {
    "src/core/fields/m31.zig":
        "4fc330e004420a64dab38d35a04db0b3fc3ab0c4e53f8088ad5ff1fe13b42789",
    "src/core/fields/cm31.zig":
        "4b7a14c91fba7c467f92e924ce90c7230a22d08329591e3d5b8874d862b31288",
    "src/core/fields/qm31.zig":
        "a60c2a5a6f10bf91b1bfab41a526e41b589d0d1d83275e0516cf68b7228be931",
    "src/core/utils.zig":
        "e6a4427e8cca5a83e0d2accd5c05cc08d9ac167238833fc225155dfd36f2fd18",
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
    "src/frontends/riscv/air/lookups/entry.zig":
        "499e9cf1660243e85c0e1163ac078af29ddc75d4791f9719d4b930b2c10aaaf7",
    "src/frontends/riscv/air/logup.zig":
        "b1d18803eb05c44cc6546e8122c2c4f6e634796fef7df39cfed895c42e61c7f8",
    "src/frontends/riscv/air/relation_challenges.zig":
        "72929411eef7fd4bf13811db52275fe31dc357187de69344cd46053e839327df",
    "src/frontends/riscv/prover/preprocessed.zig":
        "ac8c57ce3b164b4254d4f5d8570a929dcbf4f618993e12af85b16189330662dd",
    "src/frontends/riscv/prover/opcode_trace.zig":
        "4659a43c81cc442a14403fab0b85b2cdb28cba04ae39454143355ce676bd4d65",
    "src/frontends/riscv/infra_trace/permutation.zig":
        "2e6551f2c758b18f4a620d166b908a269297e9f1a74308c2ebd769dd8a474b98",
    "scripts/air_satisfaction_lib/poseidon2.py":
        "13e6e97035652e250859e2dfa77c20ff373dda47d1cc44b093e8725f64f0ede3",
    "scripts/air_satisfaction_lib/infrastructure.py":
        "dc2df08d61cc4d5e9b2e9c995d55df20e8489edd0b6b5b45246455033a0791f7",
    "scripts/air_satisfaction_lib/field.py":
        "84402a223ddb4622fdeab073186ba9e3614dd5d9887d8b4c8e339e866571daf9",
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
digests make the local derivation fail closed on reviewed-source drift; they do
not turn it into independent proof-wire verification.
"""


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
    m31_source = "src/core/fields/m31.zig"
    m31 = _compact_zig((root / m31_source).read_text(encoding="utf-8"))
    _require_anchor(m31, "pubconstModulus:u32=0x7fffffff;", m31_source)

    qm31_source = "src/core/fields/qm31.zig"
    qm31 = _compact_zig((root / qm31_source).read_text(encoding="utf-8"))
    for anchor in (
        "pubconstR:CM31=CM31.fromU32Unchecked(2,1);",
        "return.{self.c0.a,self.c0.b,self.c1.a,self.c1.b};",
    ):
        _require_anchor(qm31, anchor, qm31_source)

    utils_source = "src/core/utils.zig"
    utils = _compact_zig((root / utils_source).read_text(encoding="utf-8"))
    _require_anchor(
        utils,
        "pubfncosetIndexToCircleDomainIndex(coset_index:usize,"
        "log_domain_size:u32)usize{if((coset_index&1)==0){"
        "returncoset_index/2;}return((@as(usize,2)<<"
        "@intCast(log_domain_size))-coset_index)/2;}",
        utils_source,
    )

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

    entry_source = "src/frontends/riscv/air/lookups/entry.zig"
    entry = _compact_zig((root / entry_source).read_text(encoding="utf-8"))
    for anchor in (
        ".bitwise=>relations.bitwise.combineSecure(self.values[0..4].*),",
        ".range_check_20=>relations.range_check_20.combineSecure("
        "self.values[0..1].*),",
        ".range_check_8_11=>relations.range_check_8_11.combineSecure("
        "self.values[0..2].*),",
        ".range_check_8_8_4=>relations.range_check_8_8_4.combineSecure("
        "self.values[0..3].*),",
        ".range_check_8_8=>relations.range_check_8_8.combineSecure("
        "self.values[0..2].*),",
        ".range_check_m31=>relations.range_check_m31.combineSecure("
        "self.values[0..2].*),",
    ):
        _require_anchor(entry, anchor, entry_source)

    relations_source = "src/frontends/riscv/air/relation_challenges.zig"
    relations = _compact_zig((root / relations_source).read_text(encoding="utf-8"))
    for anchor in (
        "returninit(QM31.fromU32Unchecked(1,2,3,4),"
        "QM31.fromU32Unchecked(4,3,2,1),);",
        "for(values,self.alpha_powers)|value,power|{"
        "result=result.add(power.mul(value));}returnresult.sub(self.z);",
        ".bitwise=pair(4,values,6),",
        ".range_check_m31=pair(2,values,11),",
    ):
        _require_anchor(relations, anchor, relations_source)

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
