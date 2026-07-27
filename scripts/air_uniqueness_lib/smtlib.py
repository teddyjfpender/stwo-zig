"""IR + table membership -> an SMT-LIB2 two-copy witness-uniqueness query.

The query is the negation of

    for all witnesses A, B satisfying the constraints and every live lookup
    request, if A and B agree on all `input` columns then they agree on all
    `output` columns.

so `unsat` means the property holds and `sat` hands back a concrete pair of
witnesses that break it.

Encoding of the field
---------------------
Every column is an integer in [0, p).  Polynomials are built with *exact*
integer arithmetic and never reduced implicitly; a constraint is discharged as
`P = p * k` for a fresh integer `k` whose range follows from interval analysis.
No `mod` or `div` term appears anywhere.

That choice is not stylistic.  The AUIPC under-constraint existed because
2^32 = 2p + 2, so a byte decomposition had a second solution offset by p + 2.
An encoding that quietly treated limb arithmetic as unbounded-integer
arithmetic would have proved that family unique.  Reduction is explicit here
precisely so wraparound stays reachable to the solver.

A value only needs a canonical representative where the *integer* matters
rather than the field element: the components of a range-table tuple, and the
zero-test on a lookup numerator.  Those get an explicit reduced companion
`r in [0, p)` with `expr = r + p*q`.  Nodes already provably inside [0, p) --
bare columns, small constants -- are their own representative.

Two exact rewrites keep the query tractable (see `analysis.py` for why each is
implied).  Measured on the models in `scripts/tests/fixtures/air_uniqueness/`:
with neither, every unsat query times out at 60s; with either one alone they
finish under 0.4s; with both, under 20ms.  Only the unsat direction is
sensitive -- the sat models are found either way, which is the same asymmetry
the soundness argument has.

  * a constraint that is a product is discharged as a disjunction over its
    factors, since a product vanishes in a field iff a factor does.  `bit(x)`
    becomes `x = 0 or x = 1` instead of a quadratic diophantine equation;
  * quotient variables are dropped entirely wherever interval analysis already
    confines the polynomial to (-p, p), where the only multiple of p is zero.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import tables
from .analysis import factors, implied_column_bounds, node_bounds
from .ir import MODULUS, System

COPIES = ("a", "b")


def _lit(value: int) -> str:
    return f"(- {-value})" if value < 0 else str(value)


def _ceil_div(numerator: int, denominator: int) -> int:
    return -((-numerator) // denominator)


@dataclass
class Query:
    """Emitted query plus the names a decoder needs to read a model back."""

    text: str
    family: str
    columns: dict[str, str]  # column name -> role
    copies: tuple[str, ...] = COPIES
    skipped_bus_lookups: tuple[str, ...] = ()
    modelled_lookups: tuple[str, ...] = ()

    def var(self, column: str, copy: str) -> str:
        return f"{column}@{copy}"


class _Emitter:
    def __init__(self, system: System, refine: bool) -> None:
        self.system = system
        self.column_bounds = (
            implied_column_bounds(system)
            if refine
            else {c.name: (0, MODULUS - 1) for c in system.columns}
        )
        self.bounds = node_bounds(system, self.column_bounds)
        self.lines: list[str] = []
        self.fresh = 0
        self.skipped: list[str] = []
        self.modelled: list[str] = []

    # -- low level ---------------------------------------------------------

    def emit(self, line: str) -> None:
        self.lines.append(line)

    def declare(self, name: str, lo: int | None, hi: int | None) -> str:
        self.emit(f"(declare-const {name} Int)")
        if lo is not None:
            self.emit(f"(assert (<= {_lit(lo)} {name}))")
        if hi is not None:
            self.emit(f"(assert (<= {name} {_lit(hi)}))")
        return name

    def fresh_name(self, stem: str) -> str:
        self.fresh += 1
        return f"{stem}!{self.fresh}"

    # -- expressions -------------------------------------------------------

    def node_terms(self, copy: str) -> list[str]:
        """One SMT term per IR node.  Leaves inline; every interior node gets a
        defining constant so the emitted text stays linear in the DAG rather
        than exponential in its depth."""
        terms: list[str] = []
        for index, node in enumerate(self.system.nodes):
            if node.op == "const":
                assert node.value is not None
                terms.append(_lit(node.value))
                continue
            if node.op == "col":
                terms.append(f"{node.name}@{copy}")
                continue
            if node.op == "neg":
                body = f"(- {terms[node.args[0]]})"
            else:
                symbol = {"add": "+", "sub": "-", "mul": "*"}[node.op]
                lhs, rhs = terms[node.args[0]], terms[node.args[1]]
                body = f"({symbol} {lhs} {rhs})"
            lo, hi = self.bounds[index]
            name = self.declare(f"n{index}@{copy}", lo, hi)
            self.emit(f"(assert (= {name} {body}))")
            terms.append(name)
        return terms

    def vanishing(self, node: int, term: str, copy: str, stem: str) -> str:
        """Assertion body for "the field value of `node` is zero"."""
        lo, hi = self.bounds[node]
        if -MODULUS < lo and hi < MODULUS:
            # Zero is the only multiple of p in (-p, p), so no quotient is
            # needed and the constraint stays linear in the node term.
            return f"(= {term} 0)"
        quotient = self.declare(
            self.fresh_name(f"{stem}k@{copy}"),
            _ceil_div(lo, MODULUS),
            hi // MODULUS,
        )
        return f"(= {term} (* {MODULUS} {quotient}))"

    def reduced(self, node: int, term: str, copy: str, stem: str) -> str:
        """Canonical representative in [0, p) of the field value of `node`."""
        lo, hi = self.bounds[node]
        if 0 <= lo and hi < MODULUS:
            return term
        name = self.declare(self.fresh_name(f"{stem}@{copy}"), 0, MODULUS - 1)
        quotient = self.declare(
            self.fresh_name(f"{stem}q@{copy}"),
            _ceil_div(lo - MODULUS + 1, MODULUS),
            hi // MODULUS,
        )
        self.emit(f"(assert (= {term} (+ {name} (* {MODULUS} {quotient}))))")
        return name

    # -- obligations -------------------------------------------------------

    def emit_constraints(self, terms: list[str], copy: str) -> None:
        for position, node in enumerate(self.system.constraints):
            stem = f"c{position}"
            clauses = [
                self.vanishing(factor, terms[factor], copy, f"{stem}f{i}")
                for i, factor in enumerate(factors(self.system, node))
            ]
            body = clauses[0] if len(clauses) == 1 else f"(or {' '.join(clauses)})"
            self.emit(f"(assert {body})")

    def emit_lookups(self, terms: list[str], copy: str, record: bool) -> None:
        for position, lookup in enumerate(self.system.lookups):
            tables.check_arity(lookup.domain, len(lookup.tuple_))
            label = lookup.label or f"{lookup.domain}[{position}]"
            if not tables.is_constraining(lookup.domain):
                if record:
                    self.skipped.append(label)
                self.emit(f"; lookup {position} {label}: bus relation, not a table")
                continue
            if record:
                self.modelled.append(label)
            self.emit(f"; lookup {position} {label}")
            stem = f"lk{position}"
            live = self.reduced(lookup.numerator, terms[lookup.numerator], copy, stem)
            components = [
                self.reduced(node, terms[node], copy, f"{stem}t{j}")
                for j, node in enumerate(lookup.tuple_)
            ]
            widths = tables.BOX_TABLES.get(lookup.domain) or tables.BITWISE_WIDTHS
            clauses = [
                f"(< {component} {1 << width})"
                for component, width in zip(components, widths)
            ]
            if lookup.domain == tables.BITWISE_DOMAIN:
                clauses.append(self._bitwise_definition(components))
            body = clauses[0] if len(clauses) == 1 else f"(and {' '.join(clauses)})"
            self.emit(f"(assert (=> (not (= {live} 0)) {body}))")

    def _bitwise_definition(self, components: list[str]) -> str:
        """`value` as a function of `(lhs, rhs, op)`.

        The box clauses already pin the operands to 8 bits, so the 8-bit
        `int2bv` views are faithful and no `bv2int` direction is needed.
        """
        lhs, rhs, value, op = components
        as_bv = "(_ int2bv 8)"
        lhs_bv, rhs_bv = f"({as_bv} {lhs})", f"({as_bv} {rhs})"
        value_bv = f"({as_bv} {value})"
        cases = {
            0: f"(bvand {lhs_bv} {rhs_bv})",
            1: f"(bvor {lhs_bv} {rhs_bv})",
            2: f"(bvxor {lhs_bv} {rhs_bv})",
            3: "#x00",
        }
        return (
            "(and "
            + " ".join(
                f"(=> (= {op} {code}) (= {value_bv} {expr}))"
                for code, expr in cases.items()
            )
            + ")"
        )


def _emit_copies(
    emitter: _Emitter, system: System, copies: tuple[str, ...], title: str
) -> None:
    emitter.emit(f"; {title} for family {system.family!r}")
    emitter.emit(f"; p = {MODULUS}, copies {', '.join(repr(c) for c in copies)}")
    if system.notes:
        for line in system.notes.splitlines():
            emitter.emit(f"; {line}")
    emitter.emit("(set-logic ALL)")
    emitter.emit("(set-option :produce-models true)")
    for copy in copies:
        emitter.emit(f"; ---- copy {copy}: columns ----")
        for column in system.columns:
            lo, hi = emitter.column_bounds[column.name]
            emitter.declare(f"{column.name}@{copy}", lo, hi)
        emitter.emit(f"; ---- copy {copy}: polynomials ----")
        terms = emitter.node_terms(copy)
        emitter.emit(f"; ---- copy {copy}: vanishing constraints ----")
        emitter.emit_constraints(terms, copy)
        emitter.emit(f"; ---- copy {copy}: lookup obligations ----")
        emitter.emit_lookups(terms, copy, record=copy == copies[0])


def _finish(emitter: _Emitter, system: System, copies: tuple[str, ...]) -> Query:
    emitter.emit("(check-sat)")
    return Query(
        text="\n".join(emitter.lines) + "\n",
        family=system.family,
        columns={c.name: c.role for c in system.columns},
        copies=copies,
        skipped_bus_lookups=tuple(emitter.skipped),
        modelled_lookups=tuple(emitter.modelled),
    )


def emit_uniqueness_query(system: System, refine: bool = True) -> Query:
    """`refine=False` drops the implied-bounds narrowing while keeping the
    factor rewrite.  It exists so the narrowing can be differentially checked:
    an optimisation that silently deleted counterexamples is the one failure
    this pipeline cannot tolerate, and the cheap evidence against it is that
    every `sat` model stays `sat` without it."""
    emitter = _Emitter(system, refine)
    _emit_copies(emitter, system, COPIES, "witness-uniqueness query")

    emitter.emit("; ---- architectural inputs agree ----")
    for name in system.by_role("input"):
        emitter.emit(f"(assert (= {name}@{COPIES[0]} {name}@{COPIES[1]}))")

    emitter.emit("; ---- negated conclusion: some architectural output differs ----")
    differing = [
        f"(not (= {name}@{COPIES[0]} {name}@{COPIES[1]}))"
        for name in system.by_role("output")
    ]
    disjunction = differing[0] if len(differing) == 1 else f"(or {' '.join(differing)})"
    emitter.emit(f"(assert {disjunction})")
    return _finish(emitter, system, COPIES)


def emit_satisfiability_query(system: System, refine: bool = True) -> Query:
    """One copy, constraints and lookups only.

    An unsatisfiable constraint system is trivially unique, so a `unique`
    verdict means nothing until this comes back `sat`.  Every `check` run pairs
    the two rather than leaving the vacuity check to whoever remembers.
    """
    emitter = _Emitter(system, refine)
    _emit_copies(emitter, system, COPIES[:1], "satisfiability probe")
    return _finish(emitter, system, COPIES[:1])
