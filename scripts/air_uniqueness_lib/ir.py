"""Serialisable constraint-system IR for one AIR family's per-row relation.

A family is described by: named columns carrying an architectural role and,
where the AIR around the row establishes one, a declared input domain; a
hash-consed DAG of polynomials over those columns; the subset of DAG nodes that
must vanish; and the lookup requests the row emits.  Nothing else -- no field
tower, no evaluation domain, no interaction index -- because per-row witness
uniqueness needs nothing else.

Why not reuse `src/core/constraint_framework/expr.zig` (`ExprArena`,
`BaseExpr`, `ConstraintProgram`)
-------------------------------------------------------------------------
That IR is a lowering target for a Zig evaluator, not a wire format, and the
mismatch is structural rather than cosmetic:

  * it has no serialiser, and giving it one means editing soundness-critical
    `src/core/` to revive a type whose only consumers were deleted;
  * it splits `BaseExpr`/`ExtExpr` and carries `secure_col`, an artefact of the
    QM31 tower.  Every polynomial in `air/semantics/` is base-field-valued with
    base-field constants, so both halves are noise here;
  * it carries an `inv` node.  There is no inversion anywhere in the constraint
    path -- that is precisely the property that makes SMT extraction viable --
    so accepting `inv` would mean accepting input this pipeline cannot encode;
  * it addresses columns as `(interaction, idx, offset)`.  A uniqueness
    counterexample has to be readable as "these two witnesses disagree on
    `src_msb`", which needs names, and `offset` encodes cross-row access that a
    per-row query is explicitly not sound over (`air_uniqueness.py explain`,
    section 5).

So: a leaner IR with six node kinds, named columns, and no field tower.  The
cost is a second expression type in the repo; the benefit is that the Zig side
of the next phase is a tracing shim with six methods, and this side never has
to reject an expression it structurally cannot handle.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

# p = 2^31 - 1.  The prover's field modulus; see `src/core/fields/m31.zig`.
MODULUS = (1 << 31) - 1

ROLES = ("input", "output", "witness")

BINARY_OPS = ("add", "sub", "mul")
LEAF_OPS = ("const", "col")


class IRError(ValueError):
    """Malformed IR: rejected before any solver work happens."""


@dataclass(frozen=True)
class Node:
    """One DAG node.  `args` index strictly earlier nodes in the arena."""

    op: str
    args: tuple[int, ...] = ()
    value: int | None = None
    name: str | None = None

    def key(self) -> tuple[Any, ...]:
        return (self.op, self.args, self.value, self.name)


@dataclass(frozen=True)
class Domain:
    """An input column's real range, imported from outside the row.

    The values are integers in [0, p): `lo <= value <= hi` and `value` is a
    multiple of `stride`.  This is an ASSUMPTION and it points the dangerous
    way -- it shrinks the admitted witness set, so it can turn a real `sat` into
    `unsat`.  `why` is the emitter's one-line justification and exists so the
    assumption set is auditable without reading the emitter.
    """

    lo: int
    hi: int
    stride: int
    why: str


@dataclass(frozen=True)
class Column:
    name: str
    role: str
    domain: Domain | None = None
    # Non-empty when the column is not committed: it names an architectural
    # output the AIR carries as an expression, and one constraint pins it to
    # that expression.  See `air_uniqueness.py explain`, section 7.
    alias: str = ""


@dataclass(frozen=True)
class Lookup:
    """One lookup request: `numerator != 0` obliges `tuple_` to be a table row.

    `numerator` is the LogUp numerator as it appears in the AIR (an activation
    flag, often negated).  Only its zero/non-zero status matters per row; the
    sign carries yield-vs-consume, which is a multiset property this query does
    not model.
    """

    domain: str
    numerator: int
    tuple_: tuple[int, ...]
    label: str = ""


class Arena:
    """Hash-consing node arena.  Interning gives DAG sharing for free, which
    matters because `derive()` results are reused across many constraints."""

    def __init__(self) -> None:
        self.nodes: list[Node] = []
        self._index: dict[tuple[Any, ...], int] = {}

    def intern(self, node: Node) -> int:
        key = node.key()
        existing = self._index.get(key)
        if existing is not None:
            return existing
        idx = len(self.nodes)
        self.nodes.append(node)
        self._index[key] = idx
        return idx

    def const(self, value: int) -> int:
        return self.intern(Node("const", value=value % MODULUS))

    def col(self, name: str) -> int:
        return self.intern(Node("col", name=name))

    def binary(self, op: str, lhs: int, rhs: int) -> int:
        return self.intern(Node(op, args=(lhs, rhs)))

    def neg(self, arg: int) -> int:
        return self.intern(Node("neg", args=(arg,)))


@dataclass
class System:
    """A family's per-row constraint system."""

    family: str
    columns: tuple[Column, ...]
    nodes: tuple[Node, ...]
    constraints: tuple[int, ...]
    lookups: tuple[Lookup, ...]
    notes: str = ""

    def column_names(self) -> tuple[str, ...]:
        return tuple(c.name for c in self.columns)

    def by_role(self, role: str) -> tuple[str, ...]:
        return tuple(c.name for c in self.columns if c.role == role)

    def declared_domains(self) -> dict[str, Domain]:
        return {c.name: c.domain for c in self.columns if c.domain is not None}

    def uniqueness_skip_reason(self) -> str | None:
        """Why a two-copy query would say nothing about this family, or None.

        A family with no `output` column has nothing to disagree about, so the
        negated conclusion is an empty disjunction and every verdict is an
        artefact of how the emitter spelt `false`.  Reporting that as `unsat`
        would be a lie and reporting it as an error hides the reason, so the
        board carries an explicit `skipped` instead.
        """
        if not self.by_role("output"):
            return (
                "no column carries role 'output': uniqueness has nothing to "
                "conclude about. Either the family writes nothing the machine "
                "observes, or an architectural output it does produce is an "
                "expression that no column aliases."
            )
        return None


# --- construction from JSON -------------------------------------------------
#
# Two input encodings normalise to the same arena.  `nodes` is the flat form a
# Zig tracing evaluator emits directly; `exprs` is a nested form so hand-written
# models stay reviewable -- a reviewer must be able to see that a toy model is
# what it claims to be.


def _build_nested(
    arena: Arena, expr: Any, path: str, named: dict[str, int] | None = None
) -> int:
    # A bare string is a back-reference to an earlier entry of `exprs`. Naming
    # a shared subexpression is how a hand-written model states sharing that a
    # tracing emitter would get from evaluating `derive()` once.
    if isinstance(expr, str):
        if named is None or expr not in named:
            raise IRError(f"{path}: unknown expression name {expr!r}")
        return named[expr]
    if not isinstance(expr, list) or not expr:
        raise IRError(f"{path}: expression must be a non-empty list or a name")
    op = expr[0]
    if op == "const":
        if len(expr) != 2 or not isinstance(expr[1], int):
            raise IRError(f"{path}: const takes one integer")
        return arena.const(expr[1])
    if op == "col":
        if len(expr) != 2 or not isinstance(expr[1], str):
            raise IRError(f"{path}: col takes one name")
        return arena.col(expr[1])
    if op in BINARY_OPS:
        if len(expr) != 3:
            raise IRError(f"{path}: {op} takes two operands")
        lhs = _build_nested(arena, expr[1], f"{path}.{op}.0", named)
        rhs = _build_nested(arena, expr[2], f"{path}.{op}.1", named)
        return arena.binary(op, lhs, rhs)
    if op == "neg":
        if len(expr) != 2:
            raise IRError(f"{path}: neg takes one operand")
        return arena.neg(_build_nested(arena, expr[1], f"{path}.neg", named))
    # Sugar.  `bit` is the `common.bit` idiom and appears in every family; the
    # n-ary forms only exist so limb sums stay on one line.
    if op == "bit":
        if len(expr) != 2:
            raise IRError(f"{path}: bit takes one operand")
        inner = _build_nested(arena, expr[1], f"{path}.bit", named)
        one = arena.const(1)
        return arena.binary("mul", inner, arena.binary("sub", one, inner))
    if op in ("sum", "prod"):
        if len(expr) < 2:
            raise IRError(f"{path}: {op} takes at least one operand")
        folded = _build_nested(arena, expr[1], f"{path}.{op}.0", named)
        binop = "add" if op == "sum" else "mul"
        for position, operand in enumerate(expr[2:], start=1):
            rhs = _build_nested(arena, operand, f"{path}.{op}.{position}", named)
            folded = arena.binary(binop, folded, rhs)
        return folded
    raise IRError(f"{path}: unknown operator {op!r}")


def _build_flat(arena: Arena, raw_nodes: Sequence[Any]) -> list[int]:
    """Rebuild a machine-emitted flat arena, re-interning so a producer that
    does not hash-cons still yields a shared DAG here."""
    mapped: list[int] = []
    for position, raw in enumerate(raw_nodes):
        if not isinstance(raw, dict) or "op" not in raw:
            raise IRError(f"nodes[{position}]: expected an object with 'op'")
        op = raw["op"]
        if op == "const":
            mapped.append(arena.const(int(raw["value"])))
            continue
        if op == "col":
            mapped.append(arena.col(str(raw["name"])))
            continue
        args = [int(a) for a in raw.get("args", ())]
        for arg in args:
            if not 0 <= arg < position:
                raise IRError(
                    f"nodes[{position}]: arg {arg} is not a strictly earlier node"
                )
        if op in BINARY_OPS:
            if len(args) != 2:
                raise IRError(f"nodes[{position}]: {op} takes two args")
            mapped.append(arena.binary(op, mapped[args[0]], mapped[args[1]]))
            continue
        if op == "neg":
            if len(args) != 1:
                raise IRError(f"nodes[{position}]: neg takes one arg")
            mapped.append(arena.neg(mapped[args[0]]))
            continue
        raise IRError(f"nodes[{position}]: unknown operator {op!r}")
    return mapped


def _build_domain(name: str, role: str, raw: Any) -> Domain | None:
    """Parse and police a declared domain.

    Only an `input` may carry one.  Bounding an output or a witness would delete
    forgeries the AIR really admits -- an out-of-range output limb is exactly the
    shape of counterexample this pipeline exists to find -- whereas bounding an
    input restricts the theorem to inputs the machine can actually present.
    """
    if raw is None:
        return None
    if role != "input":
        raise IRError(f"column {name}: only an input may declare a domain")
    lo, hi = int(raw["lo"]), int(raw["hi"])
    stride = int(raw.get("stride", 1))
    why = str(raw.get("why", ""))
    if not 0 <= lo <= hi < MODULUS:
        raise IRError(f"column {name}: domain [{lo}, {hi}] is not inside [0, p)")
    if stride < 1 or lo % stride or hi % stride:
        raise IRError(f"column {name}: stride {stride} does not divide its bounds")
    if not why:
        raise IRError(f"column {name}: a declared domain must justify itself")
    return Domain(lo, hi, stride, why)


def from_dict(payload: dict[str, Any]) -> System:
    modulus = payload.get("modulus", MODULUS)
    if modulus != MODULUS:
        raise IRError(f"modulus {modulus} is not the M31 modulus {MODULUS}")

    columns: list[Column] = []
    seen: set[str] = set()
    for raw in payload.get("columns", ()):
        name, role = str(raw["name"]), str(raw["role"])
        if role not in ROLES:
            raise IRError(f"column {name}: role {role!r} not in {ROLES}")
        if name in seen:
            raise IRError(f"duplicate column {name}")
        seen.add(name)
        columns.append(
            Column(
                name,
                role,
                _build_domain(name, role, raw.get("domain")),
                str(raw.get("alias", "")),
            )
        )
    if not columns:
        raise IRError("system declares no columns")

    arena = Arena()
    has_nodes, has_exprs = "nodes" in payload, "exprs" in payload
    if has_nodes == has_exprs:
        raise IRError("provide exactly one of 'nodes' (flat) or 'exprs' (nested)")

    if has_nodes:
        mapped = _build_flat(arena, payload["nodes"])

        def resolve(ref: Any, path: str) -> int:
            if not isinstance(ref, int) or not 0 <= ref < len(mapped):
                raise IRError(f"{path}: node reference {ref!r} out of range")
            return mapped[ref]
    else:
        named: dict[str, int] = {}
        for name, expr in payload["exprs"].items():
            named[name] = _build_nested(arena, expr, f"exprs.{name}", named)

        def resolve(ref: Any, path: str) -> int:
            return _build_nested(arena, ref, path, named)

    constraints = tuple(
        resolve(ref, f"constraints[{i}]")
        for i, ref in enumerate(payload.get("constraints", ()))
    )
    lookups = tuple(
        Lookup(
            domain=str(raw["domain"]),
            numerator=resolve(raw["numerator"], f"lookups[{i}].numerator"),
            tuple_=tuple(
                resolve(t, f"lookups[{i}].tuple[{j}]")
                for j, t in enumerate(raw["tuple"])
            ),
            label=str(raw.get("label", "")),
        )
        for i, raw in enumerate(payload.get("lookups", ()))
    )

    system = System(
        family=str(payload.get("family", "unnamed")),
        columns=tuple(columns),
        nodes=tuple(arena.nodes),
        constraints=constraints,
        lookups=lookups,
        notes=str(payload.get("notes", "")),
    )
    validate(system)
    return system


def load(path: str | Path) -> System:
    return from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def validate(system: System) -> None:
    """Reject anything the SMT encoding could only handle by guessing."""
    declared = set(system.column_names())
    for index, node in enumerate(system.nodes):
        for arg in node.args:
            if not 0 <= arg < index:
                raise IRError(f"node {index}: arg {arg} is not strictly earlier")
        if node.op == "col" and node.name not in declared:
            raise IRError(f"node {index}: undeclared column {node.name!r}")
        if node.op not in BINARY_OPS + LEAF_OPS + ("neg",):
            raise IRError(f"node {index}: unknown operator {node.op!r}")
    # A system with no output column is well formed; it is the *query* that is
    # vacuous, and `System.uniqueness_skip_reason` reports that as a verdict
    # rather than a load error.
    for ref in system.constraints:
        if not 0 <= ref < len(system.nodes):
            raise IRError(f"constraint node {ref} out of range")
