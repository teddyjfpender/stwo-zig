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

from dataclasses import dataclass, field as dataclass_field, replace

from .analysis import (
    determined_columns,
    eliminable_inverses,
    factors,
    implied_column_bounds,
    node_bounds,
    one_hot_selectors,
    pins,
    projectable_sinks,
    renormalise,
)

try:
    from riscv_air_ir_lib import tables
    from riscv_air_ir_lib.ir import MODULUS, IRError, System
except ModuleNotFoundError:  # Imported as scripts.air_uniqueness_lib in tests.
    from scripts.riscv_air_ir_lib import tables
    from scripts.riscv_air_ir_lib.ir import MODULUS, IRError, System

COPIES = ("a", "b")
# Suffix for a variable both copies share; see `_Emitter._shared_nodes`.
SHARED = "s"


@dataclass(frozen=True)
class Shard:
    """One sub-query of a family's uniqueness question.

    `output` is the single architectural output required to differ; `selector`
    is the one-hot input pinned to 1 with its siblings pinned to 0.  Empty means
    "do not split on this axis", so `Shard()` is the monolithic query.

    Both splits are complete case splits, so a family is unique iff every shard
    of it is unsat -- the output axis because the conclusion is a disjunction
    over outputs, the opcode axis because `one_hot_selectors` only returns a
    group the constraints force into exactly-one-of.  Sharding also sharpens a
    counterexample: it arrives already labelled with the output that differs and
    the opcode it differs under, rather than leaving both to be read off a model.

    The ladder fields (`solve.ladder` schedules them):

    `group` widens the conclusion to a set of columns -- witnesses allowed --
    required to differ.  `assume_agree` treats columns as shared: it is the
    HYPOTHESIS of a sequential step, and the emitter takes it on faith, so the
    caller owes the proof that each assumed column was concluded `unsat` by an
    earlier step over the same system and selector.  The chain rule is what
    makes the composition complete: a family counterexample has a first
    differing conclusion in any fixed order, agrees on everything before it,
    and so survives into exactly that step's query.

    `lookup_prefix` is a proof-only weakening: only lookups before that index
    are asserted.  An `unsat` weakened query proves the full query unsat because
    it searched a superset of the AIR's witnesses.  A `sat` weakened query is
    not an AIR counterexample and must be reported as unfinished.
    """

    output: str = ""
    selector: str = ""
    group: tuple[str, ...] = ()
    assume_agree: tuple[str, ...] = ()
    lookup_prefix: int | None = None

    def conclusion(self) -> tuple[str, ...]:
        return self.group if self.group else (self.output,) if self.output else ()

    def label(self) -> str:
        parts = [p for p in (self.selector, self.output) if p]
        if self.group:
            parts.append("|".join(self.group))
        if self.assume_agree:
            parts.append(f"given[{len(self.assume_agree)}]")
        if self.lookup_prefix is not None:
            parts.append(f"lookups[:{self.lookup_prefix}]")
        return "/".join(parts) or "monolithic"


def plan_shards(
    system: System, by_output: bool, by_selector: bool
) -> tuple[Shard, ...]:
    """The sub-queries whose conjunction is the family's uniqueness question."""
    outputs = system.by_role("output") if by_output else ("",)
    selectors = (one_hot_selectors(system) if by_selector else ()) or ("",)
    return tuple(Shard(o, s) for s in selectors for o in outputs)


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
    # Columns the query carries as a single variable; see `_Emitter.label_for`.
    shared_columns: frozenset[str] = frozenset()
    # Witness columns projected out of the query (`eliminable_inverses`), as
    # column -> the factor node that is linear in it.  A decoded model has no
    # value for these, and a witness pair missing a column would fail replay
    # against the AIR, so the decoder re-solves the factor for each copy; the
    # node arena rides along for exactly that evaluation.
    eliminated: dict[str, int] = dataclass_field(default_factory=dict)
    nodes: tuple = ()
    # The columns the negated conclusion ranges over; a decoded model reports
    # its disagreements against exactly these.
    conclusion: tuple[str, ...] = ()
    # A proof-only obligation slice may establish unsat, but its sat model need
    # not satisfy the dropped AIR lookups and is therefore never exportable.
    weakened: bool = False

    def var(self, column: str, copy: str) -> str:
        return f"{column}@{SHARED if column in self.shared_columns else copy}"


class _Emitter:
    def __init__(
        self,
        system: System,
        refine: bool,
        assume_domains: bool,
        derived: bool = True,
        shard: Shard = Shard(),
    ) -> None:
        # Every analysis must see the same weakened obligation set the solver
        # sees.  In particular, a range window derived from a dropped lookup
        # would silently put that lookup back as an interval assumption and
        # make a proof-only slice unsound.
        self.system = (
            system
            if shard.lookup_prefix is None
            else replace(system, lookups=system.lookups[: shard.lookup_prefix])
        )
        self.shard = shard
        proof_system = self.system
        self.declared = proof_system.declared_domains() if assume_domains else {}
        bounds = (
            implied_column_bounds(proof_system)
            if refine
            else {c.name: (0, MODULUS - 1) for c in proof_system.columns}
        )
        # Pinning the opcode as a bound rather than an assertion is what makes
        # the split pay: interval analysis then sees `flag * anything` collapse
        # to either that thing or zero, instead of a product over [0, 1].
        for name in _selector_group(proof_system, shard):
            bounds[name] = (1, 1) if name == shard.selector else (0, 0)
        # Implied and declared bounds are intersected, never merged: the first
        # is a consequence of the asserted system, the second an assumption
        # imported from the AIR around it, and `assume_domains` has to be able
        # to drop exactly the second.
        for name, domain in self.declared.items():
            lo, hi = bounds[name]
            bounds[name] = (max(lo, domain.lo), min(hi, domain.hi))
        self.column_bounds = bounds
        self.renorm = renormalise(
            proof_system, bounds, values=None if derived else {}
        )
        self.bounds = self.renorm.effective
        self.static = node_bounds(proof_system, bounds)
        # `assume_agree` joins the seed: a sequential step's hypothesis is that
        # the copies agree on those columns, exactly as they agree on inputs.
        seed = frozenset(proof_system.by_role("input")) | frozenset(
            shard.assume_agree
        )
        self.shared_columns = (
            determined_columns(proof_system, seed, pins(bounds))
            if derived
            else seed
        )
        self.inverse_elim = eliminable_inverses(proof_system) if derived else {}
        # Free-sink definitions are projected out entirely: keep everything the
        # question is about, the hypothesis set, and the conclusion set.
        keep = seed | frozenset(
            shard.conclusion() or proof_system.by_role("output")
        )
        self.sunk = (
            dict(projectable_sinks(proof_system, keep)) if derived else {}
        )  # constraint position -> column, in drop order
        self.live = self._live_constraints()
        self.needed = self._reachable()
        self.shared_nodes = self._shared_nodes()
        self.lines: list[str] = []
        self.said: set[str] = set()
        self.skipped: list[str] = []
        self.modelled: list[str] = []

    # -- low level ---------------------------------------------------------

    def emit(self, line: str) -> None:
        """Append a line, dropping one already emitted verbatim.

        Every line here is either a declaration, which must not repeat, or an
        assertion of a fact, which is idempotent.  So dropping exact repeats is
        always safe -- and it is what makes sharing work: the second copy
        regenerates character-identical text for every shared node, and the
        filter removes it without either pass needing to know about the other.
        """
        if line in self.said:
            return
        self.said.add(line)
        self.lines.append(line)

    def declare(self, name: str, lo: int | None, hi: int | None) -> str:
        self.emit(f"(declare-const {name} Int)")
        if lo is not None:
            self.emit(f"(assert (<= {_lit(lo)} {name}))")
        if hi is not None:
            self.emit(f"(assert (<= {name} {_lit(hi)}))")
        return name

    def declare_stride(self, name: str, copy: str) -> None:
        """Alignment, as `value = stride * k` with `k` an explicit integer.

        A `mod` term would say the same thing and is banned everywhere else in
        this encoding, so it is banned here too; the multiplier keeps the query
        in linear integer arithmetic and keeps the reason auditable.
        """
        domain = self.declared.get(name)
        if domain is None or domain.stride == 1:
            return
        lo, hi = self.column_bounds[name]
        multiplier = self.declare(
            f"{name}!stride@{copy}", _ceil_div(lo, domain.stride), hi // domain.stride
        )
        self.emit(f"(assert (= {name}@{copy} (* {domain.stride} {multiplier})))")

    def _shared_nodes(self) -> frozenset[int]:
        """Nodes the two copies must agree on, so the query gives them one name.

        A node over input columns alone takes the same value in both copies --
        that is the hypothesis of the theorem, not a guess -- so naming it twice
        only asks the solver to rediscover it.  It is not a micro-optimisation:
        a bitwise request decomposes its operands into bits, and with two names
        the solver must first prove an 8-bit decomposition unique before it can
        conclude anything about the result.  Sharing makes that free.
        """
        support: list[frozenset[str]] = []
        shared: set[int] = set()
        for index, node in enumerate(self.system.nodes):
            if node.op == "col":
                assert node.name is not None
                names = frozenset({node.name})
            elif node.op == "const":
                names = frozenset()
            else:
                names = frozenset().union(*(support[a] for a in node.args))
            support.append(names)
            if names <= self.shared_columns:
                shared.add(index)
        return frozenset(shared)

    def label_for(self, index: int, copy: str) -> str:
        return SHARED if index in self.shared_nodes else copy

    def label_of(self, column: str, copy: str) -> str:
        return SHARED if column in self.shared_columns else copy

    # -- expressions -------------------------------------------------------

    def node_terms(self, copy: str) -> list[str]:
        """One SMT term per IR node.  Leaves inline; every interior node gets a
        defining constant so the emitted text stays linear in the DAG rather
        than exponential in its depth."""
        terms: list[str] = []
        for index, node in enumerate(self.system.nodes):
            if index not in self.needed:
                # Nothing emitted reads this node, and reachability is closed
                # downwards, so no emitted node can read it either.  The marker
                # is deliberately unparseable rather than a plausible 0.
                terms.append("<unreachable>")
                continue
            if node.op == "const":
                assert node.value is not None
                terms.append(_lit(node.value))
                continue
            if node.op == "col":
                terms.append(f"{node.name}@{self.label_for(index, copy)}")
                continue
            if node.op == "neg":
                body = f"(- {terms[node.args[0]]})"
            else:
                symbol = {"add": "+", "sub": "-", "mul": "*"}[node.op]
                lhs, rhs = terms[node.args[0]], terms[node.args[1]]
                body = f"({symbol} {lhs} {rhs})"
            lo, hi = self.renorm.raw[index]
            label = self.label_for(index, copy)
            name = self.declare(f"n{index}@{label}", lo, hi)
            self.emit(f"(assert (= {name} {body}))")
            terms.append(self.representative(index, name, label))
        return terms

    def representative(self, index: int, name: str, copy: str) -> str:
        """The term this node's parents see: itself, or a pinned stand-in.

        Handing a parent a congruent term is exact -- every assertion here reads
        a node only through its residue mod p -- and it is what stops the
        byte-carry chain from compounding its interval by 2^23 per limb.  A
        value-set pin also asserts membership; a window pin (`renorm.windows`)
        is bounds only.
        """
        values = self.renorm.representatives.get(index)
        if values is None and index not in self.renorm.windows:
            return name
        lo, hi = self.bounds[index]
        stand_in = self.declare(f"v{index}@{copy}", lo, hi)
        if values is not None and len(values) < hi - lo + 1:
            memberships = " ".join(f"(= {stand_in} {_lit(v)})" for v in values)
            self.emit(f"(assert (or {memberships}))")
        raw_lo, raw_hi = self.renorm.raw[index]
        quotient = self.declare(
            f"v{index}q@{copy}",
            _ceil_div(raw_lo - hi, MODULUS),
            (raw_hi - lo) // MODULUS,
        )
        self.emit(f"(assert (= {name} (+ {stand_in} (* {MODULUS} {quotient}))))")
        return stand_in

    def vanishing(self, node: int, term: str, copy: str, stem: str) -> str:
        """Assertion body for "the field value of `node` is zero"."""
        copy = self.label_for(node, copy)
        lo, hi = self.bounds[node]
        if -MODULUS < lo and hi < MODULUS:
            # Zero is the only multiple of p in (-p, p), so no quotient is
            # needed and the constraint stays linear in the node term.
            return f"(= {term} 0)"
        quotient = self.declare(
            f"{stem}k@{copy}",
            _ceil_div(lo, MODULUS),
            hi // MODULUS,
        )
        return f"(= {term} (* {MODULUS} {quotient}))"

    def reduced(self, node: int, term: str, copy: str, stem: str) -> str:
        """Canonical representative in [0, p) of the field value of `node`."""
        copy = self.label_for(node, copy)
        lo, hi = self.bounds[node]
        if 0 <= lo and hi < MODULUS:
            return term
        name = self.declare(f"{stem}r@{copy}", 0, MODULUS - 1)
        quotient = self.declare(
            f"{stem}q@{copy}",
            _ceil_div(lo - MODULUS + 1, MODULUS),
            hi // MODULUS,
        )
        self.emit(f"(assert (= {term} (+ {name} (* {MODULUS} {quotient}))))")
        return name

    # -- static field-value status -----------------------------------------

    def vanishes(self, node: int) -> bool | None:
        """Whether the node's field value is always / never / maybe zero.

        Read off `self.static`, the interval implied by the *declared* column
        ranges alone, and deliberately not off the pinned value sets.  A value
        set is a consequence of the constraints, so discharging a constraint
        with it is circular -- and worse than circular, because the emitter then
        prunes the pinned node as unreachable and the fact is asserted nowhere.
        Declared ranges are in the query unconditionally, so reading them is not.

        It earns its place under the opcode split: with one selector pinned to
        zero by its declaration, every other opcode's machinery sits behind a
        statically zero factor, and asserting it anyway leaves the solver a
        query full of dead 10^74-wide terms.
        """
        lo, hi = self.static[node]
        if lo == hi:
            return lo % MODULUS == 0
        return None if hi // MODULUS >= _ceil_div(lo, MODULUS) else False

    def _live_constraints(self) -> list[tuple[int, list[int]]]:
        """Constraints still worth asserting, as (position, vanishing factors).

        A factor that always vanishes discharges its product, and one that never
        vanishes cannot be the reason a product does; dropping either is exact.
        A constraint left with no candidate factor is unsatisfiable, and is kept
        so the solver reports that as the vacuous unsat it is.
        """
        out: list[tuple[int, list[int]]] = []
        for position, node in enumerate(self.system.constraints):
            if position in self.sunk:
                continue  # Projected free-sink definition; see `projectable_sinks`.
            candidates = []
            for factor in factors(self.system, node):
                status = self.vanishes(factor)
                if status is True:
                    candidates = []
                    break
                if status is None:
                    candidates.append(factor)
            else:
                out.append((position, candidates))
        return out

    def _reachable(self) -> set[int]:
        """Nodes some emitted obligation reads, closed downwards.

        An eliminated factor contributes its A and B, never itself: the whole
        point of the projection is that the witness inside it is not declared.
        """
        roots: list[int] = []
        for _, candidates in self.live:
            for factor in candidates:
                projected = self.inverse_elim.get(factor)
                if projected is None:
                    roots.append(factor)
                else:
                    roots.extend(projected[:2])
        for lookup in self.system.lookups:
            if tables.is_constraining(lookup.domain) and self.vanishes(
                lookup.numerator
            ) is not True:
                roots.extend((lookup.numerator, *lookup.tuple_))
        seen: set[int] = set()
        while roots:
            node = roots.pop()
            if node in seen:
                continue
            seen.add(node)
            roots.extend(self.system.nodes[node].args)
        return seen

    # -- obligations -------------------------------------------------------

    def emit_constraints(self, terms: list[str], copy: str) -> None:
        for position, candidates in self.live:
            stem = f"c{position}"
            clauses = [
                self.factor_clause(factor, terms, copy, f"{stem}f{i}")
                for i, factor in enumerate(candidates)
            ]
            if not clauses:
                self.emit(f"; constraint {position}: no factor can vanish")
                self.emit("(assert false)")
                continue
            body = clauses[0] if len(clauses) == 1 else f"(or {' '.join(clauses)})"
            self.emit(f"(assert {body})")

    def factor_clause(self, factor: int, terms: list[str], copy: str, stem: str) -> str:
        """Clause under which this factor lets its constraint vanish: the
        factor's own vanishing, or -- for a projected inverse witness -- the
        exact solvability condition `A != 0 or B = 0` from
        `eliminable_inverses`."""
        projected = self.inverse_elim.get(factor)
        if projected is None:
            return self.vanishing(factor, terms[factor], copy, stem)
        a, b, column = projected
        self.emit(f"; witness {column} projected out: A*Z = B iff A != 0 or B = 0")
        alive = self.reduced(a, terms[a], copy, f"{stem}a")
        vanishes = self.vanishing(b, terms[b], copy, f"{stem}b")
        return f"(or (not (= {alive} 0)) {vanishes})"

    def emit_lookups(self, terms: list[str], copy: str, record: bool) -> None:
        for position, lookup in enumerate(self.system.lookups):
            tables.check_arity(lookup.domain, len(lookup.tuple_))
            label = lookup.label or f"{lookup.domain}[{position}]"
            if not tables.is_constraining(lookup.domain):
                if record:
                    self.skipped.append(label)
                self.emit(f"; lookup {position} {label}: bus relation, not a table")
                continue
            if self.vanishes(lookup.numerator) is True:
                self.emit(f"; lookup {position} {label}: numerator is zero, no request")
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
            widths = tables.box_widths(lookup.domain)
            assert widths is not None
            clauses = [
                f"(< {component} {1 << width})"
                for component, width in zip(components, widths)
            ]
            if lookup.domain == tables.BITWISE_DOMAIN:
                labels = [self.label_for(node, copy) for node in lookup.tuple_]
                clauses.append(self._bitwise_definition(components, labels, stem))
            # A box is a superset wherever the real table omits a row inside it.
            # Leaving the omission out admits witnesses the AIR rejects, which
            # shows up as spurious `sat`, never as a false `unsat`.
            for excluded in tables.EXCLUDED_TUPLES.get(lookup.domain, ()):
                literal = " ".join(
                    f"(= {component} {value})"
                    for component, value in zip(components, excluded)
                )
                clauses.append(f"(not (and {literal}))")
            body = clauses[0] if len(clauses) == 1 else f"(and {' '.join(clauses)})"
            self.emit(f"(assert (=> (not (= {live} 0)) {body}))")

    def bits_of(self, term: str, stem: str, copy: str) -> tuple[list[str], str]:
        """Eight 0/1 constants, plus the equation making them `term`'s bits.

        The bits are declared unconditionally but the equation is returned, not
        asserted: it belongs inside the membership implication.  Asserting it
        eagerly would force `term < 256` on a row whose request is not live,
        which is an over-constraint and so a deleted counterexample.
        """
        names = [self.declare(f"{stem}b{i}@{copy}", 0, 1) for i in range(8)]
        weighted = " ".join(
            name if i == 0 else f"(* {1 << i} {name})" for i, name in enumerate(names)
        )
        return names, f"(= {term} (+ {weighted}))"

    def _bitwise_definition(
        self, components: list[str], labels: list[str], stem: str
    ) -> str:
        """`value` as a function of `(lhs, rhs, op)`, bit by bit in integers.

        The obvious encoding is `int2bv` over the byte-boxed operands, and it is
        the one this replaced.  It is correct and it is slow: it drags the query
        into the bitvector theory, and a family whose ALU shard is `add` closes
        in 0.4 s while the same family's `xor` shard did not close in 25 s.
        Eight 0/1 integers per operand and one product per bit keeps the whole
        query in the arithmetic the rest of the encoding already uses.

        Each component's bits carry that component's own copy label: the bits
        of a shared operand are shared, so the second copy re-emits the same
        text and `emit` drops it, instead of the solver having to prove an
        8-bit decomposition unique before concluding anything about the value.
        """
        lhs, rhs, value, op = components
        left, left_sum = self.bits_of(lhs, f"{stem}l", labels[0])
        right, right_sum = self.bits_of(rhs, f"{stem}r", labels[1])
        out, out_sum = self.bits_of(value, f"{stem}v", labels[2])
        clauses = [left_sum, right_sum]
        # op 3 is the padding row, whose value is zero for every operand pair,
        # so it needs no bit decomposition of `value` at all.
        for code, definition in enumerate(("(* {l} {r})", "(- (+ {l} {r}) (* {l} {r}))",
                                           "(- (+ {l} {r}) (* 2 {l} {r}))")):
            body = " ".join(
                f"(= {v} {definition.format(l=l, r=r)})"
                for l, r, v in zip(left, right, out)
            )
            clauses.append(f"(=> (= {op} {code}) (and {out_sum} {body}))")
        clauses.append(f"(=> (= {op} 3) (= {value} 0))")
        return "(and " + " ".join(clauses) + ")"


def _selector_group(system: System, shard: Shard) -> tuple[str, ...]:
    if not shard.selector:
        return ()
    group = one_hot_selectors(system)
    if shard.selector not in group:
        raise IRError(
            f"{system.family}: {shard.selector!r} is not in the derived one-hot "
            f"group {group}; splitting on it would not be a complete case split"
        )
    return group


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
            label = SHARED if column.name in emitter.shared_columns else copy
            emitter.declare(f"{column.name}@{label}", lo, hi)
            emitter.declare_stride(column.name, label)
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
        shared_columns=emitter.shared_columns,
        skipped_bus_lookups=tuple(emitter.skipped),
        modelled_lookups=tuple(emitter.modelled),
        eliminated={
            # Inverse projections first: a sunk definition may read a projected
            # inverse, never the other way round (a sink is read by nothing).
            # Sinks in reverse drop order, so a definition whose right side
            # uses a later-orphaned column is re-solved after that column is.
            **{
                column: factor
                for factor, (_, _, column) in emitter.inverse_elim.items()
            },
            **{
                column: system.constraints[position]
                for position, column in reversed(list(emitter.sunk.items()))
            },
        },
        nodes=system.nodes,
        conclusion=emitter.shard.conclusion() or system.by_role("output"),
        weakened=(
            emitter.shard.lookup_prefix is not None
            and emitter.shard.lookup_prefix < len(system.lookups)
        ),
    )


def emit_uniqueness_query(
    system: System,
    refine: bool = True,
    assume_domains: bool = False,
    derived: bool = True,
    shard: Shard = Shard(),
) -> Query:
    """`refine=False` drops the implied-bounds narrowing while keeping the
    factor rewrite.  It exists so the narrowing can be differentially checked:
    an optimisation that silently deleted counterexamples is the one failure
    this pipeline cannot tolerate, and the cheap evidence against it is that
    every `sat` model stays `sat` without it.

    `assume_domains` adds the declared input domains, and defaults OFF because
    they are assumptions rather than optimisations: the query without them
    proves a strictly stronger statement, and one that rests on strictly less.
    Turn them on to triage a `sat` whose counterexample sits at an input no
    execution can present."""
    reason = system.uniqueness_skip_reason()
    if reason is not None:
        raise IRError(f"{system.family}: {reason}")
    outputs = system.by_role("output")
    _validate_shard(system, shard, outputs)
    emitter = _Emitter(system, refine, assume_domains, derived, shard)
    _emit_copies(emitter, system, COPIES, f"witness-uniqueness query [{shard.label()}]")

    # The hypothesis is structural rather than asserted: an input is one
    # variable, so "the copies agree on it" cannot be omitted or mis-stated.
    emitter.emit(
        "; ---- architectural inputs are one variable each: "
        + ", ".join(f"{name}@{SHARED}" for name in system.by_role("input"))
        + " ----"
    )

    emitter.emit("; ---- negated conclusion: some concluded column differs ----")
    # A shared conclusion column cannot differ, and says so as `x@s != x@s`:
    # the static analysis has already decided that shard, and the text records
    # which.
    differing = [
        f"(not (= {name}@{emitter.label_of(name, COPIES[0])}"
        f" {name}@{emitter.label_of(name, COPIES[1])}))"
        for name in (shard.conclusion() or outputs)
    ]
    disjunction = differing[0] if len(differing) == 1 else f"(or {' '.join(differing)})"
    emitter.emit(f"(assert {disjunction})")
    return _finish(emitter, system, COPIES)


def _validate_shard(system: System, shard: Shard, outputs: tuple[str, ...]) -> None:
    """Reject a shard whose question would be about different columns than the
    caller believes, before any solver time is spent on it."""
    if shard.output and shard.group:
        raise IRError(f"{system.family}: a shard takes `output` or `group`, not both")
    if shard.output and shard.output not in outputs:
        raise IRError(f"{system.family}: {shard.output!r} is not an output column")
    inputs = frozenset(system.by_role("input"))
    known = set(system.column_names())
    for name in shard.group + shard.assume_agree:
        if name not in known:
            raise IRError(f"{system.family}: {name!r} is not a column")
    for name in shard.group:
        if name in inputs:
            raise IRError(
                f"{system.family}: {name!r} is an input; the copies agree on it "
                "by hypothesis, so concluding about it asks nothing"
            )
    overlap = set(shard.group) & set(shard.assume_agree)
    if overlap:
        raise IRError(
            f"{system.family}: {sorted(overlap)} both assumed and concluded; "
            "that step would prove nothing and hide that it proved nothing"
        )
    if shard.lookup_prefix is not None and not (
        0 <= shard.lookup_prefix <= len(system.lookups)
    ):
        raise IRError(
            f"{system.family}: lookup prefix {shard.lookup_prefix} is outside "
            f"[0, {len(system.lookups)}]"
        )


def emit_satisfiability_query(
    system: System,
    refine: bool = True,
    assume_domains: bool = False,
    derived: bool = True,
    shard: Shard = Shard(),
) -> Query:
    """One copy, constraints and lookups only.

    An unsatisfiable constraint system is trivially unique, so a `unique`
    verdict means nothing until this comes back `sat`.  Every `check` run pairs
    the two rather than leaving the vacuity check to whoever remembers.

    Only `shard.selector` is read: the output axis does not restrict the
    witnesses, so it cannot change whether one exists.  Probing per opcode does
    matter -- one opcode's constraints can be contradictory while the family as
    a whole is satisfiable, and that opcode's shards would then be unsat for a
    reason that says nothing about its semantics.

    `assume_domains` must match the uniqueness query it accompanies: a system
    satisfiable only outside the assumed domains is, for the purposes of that
    verdict, not satisfiable.
    """
    probe = Shard(selector=shard.selector)
    emitter = _Emitter(system, refine, assume_domains, derived, probe)
    _emit_copies(emitter, system, COPIES[:1], f"satisfiability probe [{probe.label()}]")
    return _finish(emitter, system, COPIES[:1])
