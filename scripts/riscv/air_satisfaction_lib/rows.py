"""Per-row evaluation of an extracted family system against a committed trace.

This is the half of the checker that re-decides, in Python, what the Zig
evaluator decided in Zig: every direct constraint vanishes on every committed
row, and every activated preprocessed-table request names a tuple the table
contains.

Two reuses, both deliberate.  `riscv_air_ir_lib.ir` parses the emitted IR, so
there is one IR parser in the repository rather than two that can disagree about
what a `sub` node means.  `riscv_air_ir_lib.tables` owns the table widths, and
`scripts/tests/test_air_uniqueness.py` already cross-checks those against
`air/lookups/tables/schema.zig`.  Neither module contains any evaluation: the
arithmetic below is this package's own.

Alias columns
-------------
The IR may declare columns that are NOT committed cells: an alias names an
architectural output the AIR carries only as an expression, and one added
constraint pins the alias to that expression.  For a uniqueness query that is
the point of the mechanism.  For a satisfaction check it is vacuous -- the
committed trace has no cell to disagree with the definition -- so `Prepared`
drops alias columns and the constraints that define them, and REFUSES the whole
family if an alias reaches any other constraint or any lookup, where dropping it
would quietly weaken the check.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dataclass_field

from .dump import Component
from .field import P

try:
    from riscv_air_ir_lib import ir, tables
except ModuleNotFoundError:  # Imported as scripts.air_satisfaction_lib in tests.
    from scripts.riscv_air_ir_lib import ir, tables


class LayoutMismatch(ValueError):
    """The emitted IR and the exported component do not describe one AIR."""


@dataclass(frozen=True)
class Violation:
    """One row-local failure, named the way a reader can act on it."""

    family: str
    component: int
    row: int
    kind: str
    detail: str

    def __str__(self) -> str:
        return f"{self.family}[{self.component}] row {self.row}: {self.kind} — {self.detail}"


@dataclass
class Counts:
    rows: int = 0
    constraints: int = 0
    skipped_constraints: int = 0
    box_requests: int = 0
    bitwise_requests: int = 0
    bus_requests: int = 0
    inactive_requests: int = 0


@dataclass
class Prepared:
    """One family system bound to one exported component's column layout.

    Everything that depends on the DAG alone is computed once here, so a row
    evaluation is a single forward pass with no per-row bookkeeping.
    """

    system: "ir.System"
    component: Component
    tainted: tuple[bool, ...]
    live_constraints: tuple[int, ...]
    skipped_constraints: tuple[int, ...]
    column_of_node: tuple[int, ...] = dataclass_field(default=())

    def evaluate(self, row: tuple[int, ...]) -> list[int]:
        """Value of every DAG node at `row`, as canonical residues in [0, p).

        One forward pass: `ir.validate` has already established that every
        argument indexes a strictly earlier node, so no node is visited before
        its operands.  Tainted nodes evaluate to zero and are never read.
        """
        values: list[int] = [0] * len(self.system.nodes)
        for position, node in enumerate(self.system.nodes):
            if self.tainted[position]:
                continue
            if node.op == "const":
                values[position] = node.value % P
            elif node.op == "col":
                values[position] = row[self.column_of_node[position]]
            elif node.op == "neg":
                values[position] = (-values[node.args[0]]) % P
            elif node.op == "add":
                values[position] = (values[node.args[0]] + values[node.args[1]]) % P
            elif node.op == "sub":
                values[position] = (values[node.args[0]] - values[node.args[1]]) % P
            elif node.op == "mul":
                values[position] = (values[node.args[0]] * values[node.args[1]]) % P
            else:  # `ir.validate` rejects anything else before this point.
                raise LayoutMismatch(f"node {position}: unsupported operator {node.op!r}")
        return values


def prepare(system: "ir.System", component: Component) -> Prepared:
    """Bind `system` to `component`, or refuse to evaluate at all.

    Positional identity is the whole binding between the two files: the IR names
    columns and the export numbers them, and both orders come from
    `witness_layout.LayoutFor`.  A silent length mismatch would evaluate the
    right polynomial over the wrong cells, so every discrepancy is an error and
    none is a warning.
    """
    if system.family != component.family:
        raise LayoutMismatch(f"IR is for {system.family}, component is {component.family}")

    committed = [
        position
        for position, column in enumerate(system.columns)
        if not getattr(column, "alias", "")
    ]
    if committed != list(range(component.n_columns)):
        raise LayoutMismatch(
            f"{component.family}: the IR's committed columns are at positions "
            f"{committed[:3]}...; the export carries {component.n_columns} columns "
            "in a contiguous prefix"
        )
    alias_names = {
        column.name for column in system.columns if getattr(column, "alias", "")
    }
    position_of = {column.name: position for position, column in enumerate(system.columns)}

    tainted = [False] * len(system.nodes)
    column_of_node = [0] * len(system.nodes)
    for position, node in enumerate(system.nodes):
        if node.op == "col":
            if node.name in alias_names:
                tainted[position] = True
            else:
                column_of_node[position] = position_of[node.name]
        else:
            tainted[position] = any(tainted[arg] for arg in node.args)

    for index, lookup in enumerate(system.lookups):
        reached = [lookup.numerator, *lookup.tuple_]
        if any(tainted[node] for node in reached):
            raise LayoutMismatch(
                f"{component.family}: lookup request {index} on {lookup.domain} reads "
                "an alias column, so dropping the alias would weaken the check"
            )

    live = tuple(node for node in system.constraints if not tainted[node])
    skipped = tuple(node for node in system.constraints if tainted[node])
    return Prepared(
        system=system,
        component=component,
        tainted=tuple(tainted),
        live_constraints=live,
        skipped_constraints=skipped,
        column_of_node=tuple(column_of_node),
    )


def _box_violation(domain: str, values: list[int]) -> str | None:
    widths = tables.BOX_TABLES[domain]
    for position, (value, width) in enumerate(zip(values, widths)):
        if value >= (1 << width):
            return f"component {position} = {value} exceeds its {width}-bit box"
    for excluded in tables.EXCLUDED_TUPLES.get(domain, ()):
        if tuple(values) == tuple(excluded):
            return (
                f"tuple {tuple(values)} is inside the box but absent from the "
                "preprocessed table"
            )
    return None


def _bitwise_violation(values: list[int]) -> str | None:
    lhs, rhs, value, operation = values
    for position, (component, width) in enumerate(zip(values, tables.BITWISE_WIDTHS)):
        if component >= (1 << width):
            return f"component {position} = {component} exceeds its {width}-bit box"
    expected = {0: lhs & rhs, 1: lhs | rhs, 2: lhs ^ rhs, 3: 0}[operation]
    if value != expected:
        return f"{lhs} {tables.BITWISE_OPS[operation]} {rhs} = {expected}, the row claims {value}"
    return None


def check_component(prepared: Prepared) -> tuple[list[Violation], Counts]:
    """Decide every real row of the bound component.

    Padding rows are out of scope, and that is a real limit rather than a
    convenience.  The emitted IR fixes the preprocessed `is_active` selector to
    one when it records the placement constraint, so the system here is the
    ACTIVE-row system; evaluating it on a padding row would test a relation the
    AIR does not impose there.  What the AIR requires of padding rows is decided
    in Zig, by the component's own domain evaluation.
    """
    component = prepared.component
    violations: list[Violation] = []
    counts = Counts(skipped_constraints=len(prepared.skipped_constraints))
    for row_index in range(component.n_rows):
        values = prepared.evaluate(component.rows[row_index])
        counts.rows += 1
        for position, node in enumerate(prepared.live_constraints):
            counts.constraints += 1
            if values[node] != 0:
                violations.append(
                    Violation(
                        component.family,
                        component.index,
                        row_index,
                        "constraint",
                        f"constraint {position} of {len(prepared.live_constraints)} "
                        f"evaluates to {values[node]}, not 0",
                    )
                )
        violations.extend(_check_lookups(prepared, row_index, values, counts))
    return violations, counts


def _check_lookups(
    prepared: Prepared,
    row_index: int,
    values: list[int],
    counts: Counts,
) -> list[Violation]:
    component = prepared.component
    violations: list[Violation] = []
    for position, lookup in enumerate(prepared.system.lookups):
        # A zero numerator switches the request off for this row; only its
        # zero/non-zero status matters, exactly as in `row_admissibility.zig`.
        if values[lookup.numerator] == 0:
            counts.inactive_requests += 1
            continue
        tables.check_arity(lookup.domain, len(lookup.tuple_))
        tuple_values = [values[node] for node in lookup.tuple_]
        if lookup.domain in tables.BOX_TABLES:
            counts.box_requests += 1
            detail = _box_violation(lookup.domain, tuple_values)
        elif lookup.domain == tables.BITWISE_DOMAIN:
            counts.bitwise_requests += 1
            detail = _bitwise_violation(tuple_values)
        else:
            # Bus relations are closed globally, not row-locally. Deciding them
            # here would be a claim this layer cannot support.
            counts.bus_requests += 1
            continue
        if detail is not None:
            violations.append(
                Violation(
                    component.family,
                    component.index,
                    row_index,
                    "lookup",
                    f"request {position} on {lookup.domain}: {detail}",
                )
            )
    return violations
