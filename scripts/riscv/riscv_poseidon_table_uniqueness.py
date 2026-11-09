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

if __package__ in (None, ""):  # run as a file: make `scripts.*` importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.riscv.air_satisfaction_lib import infrastructure, poseidon2
from scripts.riscv.air_satisfaction_lib.field import P, QM31, QM31_ONE, QM31_ZERO
from scripts.riscv.riscv_poseidon_table_uniqueness_lib.models import (
    AuditError,
    AuditReport,
    PoseidonAudit,
    TableAudit,
)
from scripts.riscv.riscv_poseidon_table_uniqueness_lib.tables import (
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


ROOT = Path(__file__).resolve().parents[2]

# These bindings cover field and relation-challenge algebra, the production AIR
# adapters and constraint schedules, the fixed-table generator and placement,
# the singleton LogUp identity, and the independent Python transcriptions used
# by the constructive proof.
SOURCE_BINDINGS: dict[str, str] = {
    "src/waist/core/fields/m31.zig":
        "a5d47cc1a8c57a858b943c25e63eb1561b9f994fdff36ea38517bc166ea66d73",
    "src/waist/core/fields/cm31.zig":
        "a69ebf43415c9682d81a6f873217c1b006a28152f5a35fa6e917a6d50d9a70cf",
    "src/waist/core/fields/qm31.zig":
        "916275ccc46e2b9d13c1d591a405dfa071018634ef652b053ee8e5414ba3c71e",
    "src/waist/core/utils.zig":
        "e6a4427e8cca5a83e0d2accd5c05cc08d9ac167238833fc225155dfd36f2fd18",
    "src/frontends/riscv/air/memory_commitment/poseidon2_air.zig":
        "7c462d05324a01597f08cbf5c1b42baea1e7cb07df33176dd94ed380d26769c3",
    "src/frontends/riscv/air/memory_commitment/poseidon2_constants.zig":
        "d02b32f2f5302d21a440fbace2112d3232603e759cd0b24691c32e81d2bd4cfd",
    "src/frontends/riscv/air/memory_commitment/hash_component.zig":
        "f10bf62978d6310f4af0c4fccf0445273fd451c8695868c08c375ce53d71ba35",
    "src/frontends/riscv/air/lookups/tables/schema.zig":
        "788273e0c240763e24423fa141c6218ef40aa6495bab8c5dc1182e747e1f197a",
    "src/frontends/riscv/air/lookups/tables/interaction.zig":
        "987837845fb8aba423896a69e899bbfbc9e71a07a4fb11c3cf967a654e8e73aa",
    "src/frontends/riscv/air/lookups/tables/component.zig":
        "89f0f1d77f827085ad8f2ace072265f75a08173e22599ae9d07b819764234f61",
    "src/frontends/riscv/air/lookups/tables/counter.zig":
        "689536aefa2a65e1f4c858e5bfc25f362793c3f0d9301f9f9808276748fecf29",
    "src/frontends/riscv/air/lookups/entry.zig":
        "925623683f3b962b429aebcc172ba9b11e1f6b0528135652afc2ee80ec7265a8",
    "src/frontends/riscv/air/logup.zig":
        "cf748de1f764155e9d5cb6d4e55b3553ab62f0eb3464cecdc2d3e84a7e5edc12",
    "src/frontends/riscv/air/relation_challenges.zig":
        "4b9d027cb18013c8a5434fc7c5f4b6f4fe870db547db52432d991894f2303dd3",
    "src/frontends/riscv/prover/preprocessed.zig":
        "005473b815ca576773bf7aac28deaaa03b6b671beb2e9787a59db2d730ccdd7c",
    "src/frontends/riscv/prover/opcode_trace.zig":
        "186eafc961fc0745aa80a032277d7c8397b5e861596ed86c064a4d01fde5d2be",
    "src/frontends/riscv/infra_trace/permutation.zig":
        "2e6551f2c758b18f4a620d166b908a269297e9f1a74308c2ebd769dd8a474b98",
    "scripts/riscv/air_satisfaction_lib/poseidon2.py":
        "13e6e97035652e250859e2dfa77c20ff373dda47d1cc44b093e8725f64f0ede3",
    "scripts/riscv/air_satisfaction_lib/infrastructure.py":
        "dc2df08d61cc4d5e9b2e9c995d55df20e8489edd0b6b5b45246455033a0791f7",
    "scripts/riscv/air_satisfaction_lib/field.py":
        "84dfc43c22e083065dc64b45d700a8d7ba11f889a675ee6b6df3362193f9de64",
    "src/frontends/riscv/air/memory_commitment/poseidon2_layout.zig":
        "f51c0964fcfb04f393f0bb747a968c9e267bd08ca393fc35a2b4053cfc106c3b",
    "src/frontends/riscv/air/memory_commitment/poseidon2_wide_equations.zig":
        "462fff23439ad1563481842fc8e15aae9b28ce6b5849342fcb6f100b6b7fdec0",
    "src/frontends/riscv/air/memory_commitment/poseidon2_wide_equation_kernel.zig":
        "4a1d1d5cb670b08c208e15628be76f59959bcee1af3f9cee439df67e68a73930",
    "src/frontends/riscv/air/lookups/tables/schema_definition.zig":
        "849f56ef92e42a579537bd39651871fe02424068beaf1a65d4a7cc4e4e2e9bb9",
    "src/frontends/riscv/air/lookups/tables/equations.zig":
        "d1a1b3ebfd21ee8ec6e05845372da1dc3d8a9da957a79db07cadafe42ebd147f",
    "src/frontends/riscv/air/lookups/tables/verifier.zig":
        "f2168a09543586f75e93ab95ea15c05ad409b2586d9df0cf84b05d99e8b3a0e4",
    "src/frontends/riscv/air/lookups/tables/layout.zig":
        "f9d870043d47dc548dd94be873b18b3ade73e02b8a670aefe455816d4be667b6",
    "src/frontends/riscv/air/logup_equations.zig":
        "d8524316007e5e0b842616210d064cc4dfd76d485d0bfa010672229d805fcefd",
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


def _bound_compact(root: Path, *sources: str) -> str:
    if any(source not in SOURCE_BINDINGS for source in sources):
        raise AuditError("semantic anchor source has no exact digest binding")
    return "\n".join(
        _compact_zig((root / source).read_text(encoding="utf-8"))
        for source in sources
    )


def _require_anchor(compact: str, anchor: str, source: str) -> None:
    if anchor not in compact:
        raise AuditError(f"reviewed semantic anchor disappeared from {source}: {anchor}")


def _production_semantic_anchors(root: Path) -> None:
    m31_source = "src/waist/core/fields/m31.zig"
    m31 = _bound_compact(root, m31_source)
    _require_anchor(m31, "pubconstModulus:u32=0x7fffffff;", m31_source)

    qm31_source = "src/waist/core/fields/qm31.zig"
    qm31 = _bound_compact(root, qm31_source)
    for anchor in (
        "pubconstR:CM31=CM31.fromU32Unchecked(2,1);",
        "return.{self.c0.a,self.c0.b,self.c1.a,self.c1.b};",
    ):
        _require_anchor(qm31, anchor, qm31_source)

    utils_source = "src/waist/core/utils.zig"
    utils = _bound_compact(root, utils_source)
    _require_anchor(
        utils,
        "pubfncosetIndexToCircleDomainIndex(coset_index:usize,"
        "log_domain_size:u32)usize{if((coset_index&1)==0){"
        "returncoset_index/2;}return((@as(usize,2)<<"
        "@intCast(log_domain_size))-coset_index)/2;}",
        utils_source,
    )

    poseidon_source = "src/frontends/riscv/air/memory_commitment/poseidon2_air.zig"
    poseidon = _bound_compact(
        root,
        poseidon_source,
        "src/frontends/riscv/air/memory_commitment/poseidon2_layout.zig",
        "src/frontends/riscv/air/memory_commitment/poseidon2_wide_equations.zig",
        "src/frontends/riscv/air/memory_commitment/poseidon2_wide_equation_kernel.zig",
    )
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
    shell = _bound_compact(root, shell_source)
    for anchor in (
        "constraints[poseidon2_air.N_CONSTRAINTS]=main[0].sub(is_active);",
        "constnarrow_mode=poseidon2_air.narrowModeConstraintsGeneric(S,main);",
        "poseidon2_air.N_CONSTRAINTS+N_POSEIDON_SHELL_CONSTRAINTS+poseidon2_air.N_SUMS",
    ):
        _require_anchor(shell, anchor, shell_source)

    schema_source = "src/frontends/riscv/air/lookups/tables/schema.zig"
    schema = _bound_compact(
        root,
        schema_source,
        "src/frontends/riscv/air/lookups/tables/schema_definition.zig",
    )
    for anchor in (
        "pubconstKind=enum(u8){bitwise,range_check_20,range_check_8_11,"
        "range_check_8_8_4,range_check_8_8,range_check_m31,};",
        "if(row==size(kind)-1)return.{.len=2};",
        "constdst=table.map(row);",
    ):
        _require_anchor(schema, anchor, schema_source)

    table_interaction_source = "src/frontends/riscv/air/lookups/tables/interaction.zig"
    table_interaction = _bound_compact(
        root,
        table_interaction_source,
        "src/frontends/riscv/air/lookups/tables/equations.zig",
    )
    for anchor in (
        "returntableEntryGeneric(QM31,kind,values[0..tuple.len],QM31.fromBase(signed_multiplicity));",
        "dst.*=QM31.fromBase(value);",
        ".domain=schema.domain(kind),",
        ".numerator=signed_multiplicity.neg(),",
        ".arity=@intCast(tuple.len),",
        "@memcpy(result.values[0..tuple.len],tuple);",
        "returnlogup.RowPair.single(relation_entry.numerator,"
        "tryrelation_entry.denominator(relations));",
        "returnlogup.pairConstraintGeneric(S,current,previous,is_first,claim,"
        "logup.RowPairFor(S).single(relation_entry.numerator,"
        "tryrelation_entry.denominatorWith(relations),),);",
    ):
        _require_anchor(table_interaction, anchor, table_interaction_source)

    entry_source = "src/frontends/riscv/air/lookups/entry.zig"
    entry = _bound_compact(root, entry_source)
    for anchor in (
        ".bitwise=>Self.combineRelation(relations.bitwise,self.values[0..4].*),",
        ".range_check_20=>Self.combineRelation(relations.range_check_20,self.values[0..1].*),",
        ".range_check_8_11=>Self.combineRelation(relations.range_check_8_11,self.values[0..2].*),",
        ".range_check_8_8_4=>Self.combineRelation(relations.range_check_8_8_4,self.values[0..3].*),",
        ".range_check_8_8=>Self.combineRelation(relations.range_check_8_8,self.values[0..2].*),",
        ".range_check_m31=>Self.combineRelation(relations.range_check_m31,self.values[0..2].*),",
    ):
        _require_anchor(entry, anchor, entry_source)

    relations_source = "src/frontends/riscv/air/relation_challenges.zig"
    relations = _bound_compact(root, relations_source)
    for anchor in (
        "returninit(QM31.fromU32Unchecked(1,2,3,4),"
        "QM31.fromU32Unchecked(4,3,2,1),);",
        "for(values,powers)|value,power|{result=result.add(power.mul(value));}returnresult.sub(z);",
        ".bitwise=pair(4,values,6),",
        ".range_check_m31=pair(2,values,11),",
    ):
        _require_anchor(relations, anchor, relations_source)

    table_component_source = "src/frontends/riscv/air/lookups/tables/component.zig"
    table_component = _bound_compact(
        root,
        table_component_source,
        "src/frontends/riscv/air/lookups/tables/verifier.zig",
        "src/frontends/riscv/air/lookups/tables/layout.zig",
    )
    for anchor in (
        "pubfnnConstraints(_:*constSelf)usize{returnN_CONSTRAINTS;}",
        "result[0]=self.is_first_col_idx;",
        "@memcpy(result[1..],self.tuple_col_indices[0..schema.arity(self.kind)]);",
        "returninteraction.evaluate(self.kind,tuple,signed_multiplicity,current,"
        "previous,is_first,self.claim,self.relations,);",
    ):
        _require_anchor(table_component, anchor, table_component_source)

    counter_source = "src/frontends/riscv/air/lookups/tables/counter.zig"
    counter = _bound_compact(root, counter_source)
    for anchor in (
        "self.values[row]=self.values[row].add(numerator);",
        "for(self.values,0..)|value,row|result[table.map(row)]=value;",
    ):
        _require_anchor(counter, anchor, counter_source)

    logup_source = "src/frontends/riscv/air/logup.zig"
    logup = _bound_compact(root, logup_source, "src/frontends/riscv/air/logup_equations.zig")
    for anchor in (
        "constdelta=s.sub(s_prev).add(is_first.mul(claimed));",
        "returndelta.mul(pair.d1).mul(pair.d2)"
        ".sub(pair.n1.mul(pair.d2)).sub(pair.n2.mul(pair.d1));",
    ):
        _require_anchor(logup, anchor, logup_source)

    preprocessed_source = "src/frontends/riscv/prover/preprocessed.zig"
    preprocessed = _bound_compact(root, preprocessed_source)
    _require_anchor(
        preprocessed,
        "vartuples=trytable_schema.generatePreprocessed(allocator,kind);",
        preprocessed_source,
    )

    selectors_source = "src/frontends/riscv/prover/opcode_trace.zig"
    selectors = _bound_compact(root, selectors_source)
    for anchor in (
        "@memset(values,M31.zero());",
        "values[placement.map(0)]=M31.one();",
        "for(0..n_rows)|row|values[placement.map(row)]=M31.one();",
    ):
        _require_anchor(selectors, anchor, selectors_source)

    permutation_source = "src/frontends/riscv/infra_trace/permutation.zig"
    permutation = _bound_compact(root, permutation_source)
    _require_anchor(
        permutation,
        "destination.*=utils.bitReverseIndex("
        "utils.cosetIndexToCircleDomainIndex(row,log_size),log_size,);",
        permutation_source,
    )


    for source, anchors in {
        poseidon_source: (
            'constlayout=@import("poseidon2_layout.zig");',
            'pubconstN_MAIN_COLUMNS=layout.N_MAIN_COLUMNS;',
            'pubconstevaluateGeneric=@import("poseidon2_wide_equations.zig").evaluateGeneric;',
            'pubconstnarrowModeConstraintsGeneric=@import("poseidon2_wide_equations.zig").narrowModeConstraintsGeneric;',
        ),
        schema_source: (
            'constdefinition=@import("schema_definition.zig");',
            'pubconstKind=definition.Kind;',
            'pubconsttupleAt=definition.tupleAt;',
        ),
        table_interaction_source: (
            'pubconsttableEntry=@import("equations.zig").tableEntry;',
            'pubconstevaluateGeneric=@import("equations.zig").evaluateGeneric;',
        ),
        table_component_source: (
            'constverifier=@import("verifier.zig");',
            'constVerifierMethods=verifier.Methods(@This());',
            'pubconstnConstraints=VerifierMethods.nConstraints;',
        ),
        logup_source: (
            'pubconstpairConstraintGeneric=@import("logup_equations.zig").pairConstraintGeneric;',
        ),
        entry_source: (
            'constshipped=Builder(QM31);',
            'pubconstEntry=shipped.Entry;',
            'returnself.denominatorWith(relations);',
            'returnrelation.combine(values);',
        ),
        relations_source: (
            'returncombineGeneric(QM31,self.z,self.alpha_powers,values);',
        ),
    }.items():
        compact = _bound_compact(root, source)
        for anchor in anchors:
            _require_anchor(compact, anchor, source)


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
