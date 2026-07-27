"""z3 runner over the emitted SMT-LIB2 text, with counterexample decoding.

The solver is fed the emitted text rather than a parallel z3-API construction,
so the artifact a reviewer reads is the artifact that was checked.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from typing import Sequence

from . import tables
from .analysis import column_support, implied_column_bounds
from .ir import MODULUS, System
from .smtlib import (
    COPIES,
    Query,
    Shard,
    emit_satisfiability_query,
    emit_uniqueness_query,
)


@dataclass
class Witness:
    """One decoded side of a counterexample, as field elements per column."""

    inputs: dict[str, int] = field(default_factory=dict)
    outputs: dict[str, int] = field(default_factory=dict)
    witness: dict[str, int] = field(default_factory=dict)


@dataclass
class Result:
    family: str
    status: str  # "sat" | "unsat" | "unknown" | "skipped"
    seconds: float
    witnesses: dict[str, Witness] = field(default_factory=dict)
    differing_outputs: tuple[str, ...] = ()
    reason_unknown: str = ""
    modelled_lookups: tuple[str, ...] = ()
    skipped_bus_lookups: tuple[str, ...] = ()
    # None when the vacuity probe was not run; see `emit_satisfiability_query`.
    constraints_satisfiable: bool | None = None
    # Non-empty exactly when `status == "skipped"`.
    skip_reason: str = ""
    # Which sub-query this is, or which sub-queries an aggregate covers.
    shard: str = "monolithic"
    open_shards: tuple[str, ...] = ()

    @property
    def unique(self) -> bool:
        return self.status == "unsat"

    @property
    def vacuous(self) -> bool:
        """Unique only because nothing satisfies the constraints at all."""
        return self.unique and self.constraints_satisfiable is False


def check(
    system: System,
    timeout_ms: int = 0,
    refine: bool = True,
    assume_domains: bool = False,
    derived: bool = True,
    shard: Shard = Shard(),
    probe: bool = True,
) -> Result:
    """Run one uniqueness query.  `sat` is a real under-constraint witness pair;
    see `air_uniqueness.py explain` for what `unsat` does not mean.

    A family the query cannot say anything about returns `skipped` with the
    reason, never a verdict.  A fabricated `unsat` on such a family is worse
    than no row on the board, because the board is read as coverage.

    The default `Shard()` asks the family's whole question at once.  A board
    asks it one shard at a time and combines the answers with `aggregate`.
    """
    reason = system.uniqueness_skip_reason()
    if reason is not None:
        return Result(
            family=system.family, status="skipped", seconds=0.0, skip_reason=reason
        )
    options = {
        "refine": refine,
        "assume_domains": assume_domains,
        "derived": derived,
        "shard": shard,
    }
    result = run_query(emit_uniqueness_query(system, **options), timeout_ms)
    result.shard = shard.label()
    if result.unique and probe:
        result.constraints_satisfiable = satisfiable(system, timeout_ms, **options)
    return result


def satisfiable(system: System, timeout_ms: int = 0, **options: object) -> bool | None:
    """Whether an honest witness exists at all, or None if the probe ran out.

    `None` is not `False`.  An unsatisfiable system is trivially unique, so a
    probe that times out leaves the accompanying `unsat` unqualified rather than
    disproved -- reporting it as VACUOUS would invent a defect out of a budget.
    """
    result = run_query(emit_satisfiability_query(system, **options), timeout_ms)
    return {"sat": True, "unsat": False}.get(result.status)


def aggregate(family: str, shards: Sequence[Result]) -> Result:
    """Combine one family's shard verdicts into the family's verdict.

    The shards partition a complete case split, so the family is unique exactly
    when all of them are.  Precedence is `sat` over `unknown` over `unsat`,
    because one counterexample decides the family however the rest went, and one
    unfinished shard means the remaining `unsat`s do not add up to a proof.
    Seconds are summed: that is the solver work the verdict cost, and a board
    that reported the max would understate a family split many ways.
    """
    if not shards:
        raise ValueError(f"{family}: nothing to aggregate")
    for status in ("skipped", "sat", "unknown"):
        chosen = [s for s in shards if s.status == status]
        if chosen:
            merged = replace(chosen[0], family=family)
            break
    else:
        merged = replace(shards[0], family=family)
        merged.constraints_satisfiable = all(
            s.constraints_satisfiable is not False for s in shards
        )
    merged.seconds = sum(s.seconds for s in shards)
    merged.shard = f"{len(shards)} shards"
    merged.open_shards = tuple(
        s.shard for s in shards if s.status in ("sat", "unknown")
    )
    return merged


@dataclass(frozen=True)
class Rung:
    """One step of the sequential ladder.

    `lemma=True` marks a witness-agreement step: its `unsat` extends the shared
    set, and its `sat` means only that the witness is genuinely free -- rd_inv
    is free whenever rd_addr is zero -- so a lemma verdict is NEVER family
    evidence.  `lemma=False` steps carry architectural outputs, where `sat` is a
    real counterexample: the model satisfies every obligation and differs on an
    output, and the prefix assumption only restricted where the solver looked.
    """

    columns: tuple[str, ...]
    lemma: bool

    def label(self) -> str:
        return ("lemma " if self.lemma else "") + "|".join(self.columns)


def plan_rungs(system: System) -> tuple[Rung, ...]:
    """The ladder's steps: witness-agreement lemmas, then one step per output.

    Lemma candidates are the witnesses some obligation narrows below the full
    field: an unnarrowed witness is pinned by nothing a per-row query can see,
    so asking whether it agrees would time out to say "free".  Pinned columns
    (both copies forced to one value) agree trivially and are skipped.  The
    joint rung over all candidates exists for the families whose witnesses are
    only determined together -- DIV's quotient and remainder pin each other
    through the division identity, so every singleton fails where the joint
    question is the provable one.
    """
    bounds = implied_column_bounds(system)
    singles = [
        column.name
        for column in system.columns
        if column.role == "witness"
        and bounds[column.name] != (0, MODULUS - 1)
        and bounds[column.name][0] != bounds[column.name][1]
    ]
    rungs = [Rung((name,), lemma=True) for name in singles]
    if len(singles) > 1:
        rungs.append(Rung(tuple(singles), lemma=True))
    rungs.extend(Rung((name,), lemma=False) for name in system.by_role("output"))
    return tuple(rungs)


def ladder(
    system: System,
    timeout_ms: int,
    shard: Shard = Shard(),
    **options: object,
) -> Result:
    """Sequential uniqueness for one family under one opcode selector.

    Chain rule: with the output steps attempted in any fixed order, each
    assuming agreement on everything already proved, `unsat` on every output
    step composes to family uniqueness -- and completeness survives the
    ordering, because a family counterexample has a first differing column in
    that order and is a model of exactly that step.  Witness lemmas are pure
    strengthening: a lemma is assumed only after its own `unsat`.

    Budget: output steps and the joint lemma get `timeout_ms` each; singleton
    lemmas run at a quarter, because a lemma that misses its window costs only
    sharing, not soundness.  Steps are attempted cheapest-looking first (fewest
    obligation-support columns outside the agreed set), re-planned after every
    success, and an output step that failed is retried once if later steps
    widened the agreed set.  The composed verdict never averages: one open
    output step makes the family `unknown` however many closed.
    """
    support = column_support(system)
    reads: dict[str, set[int]] = {}
    for index, root in _obligation_roots(system):
        for name in support[root]:
            reads.setdefault(name, set()).add(index)
    roots = dict(_obligation_roots(system))

    def outside(rung: Rung, agreed: frozenset[str]) -> int:
        exempt = set(rung.columns) | agreed | set(system.by_role("input"))
        touched: set[str] = set()
        for column in rung.columns:
            for obligation in reads.get(column, ()):
                touched |= support[roots[obligation]]
        return len(touched - exempt)

    pending = list(plan_rungs(system))
    agreed: frozenset[str] = frozenset(shard.assume_agree)
    steps: list[Result] = []
    retried: set[Rung] = set()
    sat_step: Result | None = None
    while pending and sat_step is None:
        pending.sort(key=lambda rung: (outside(rung, agreed), rung.label()))
        rung = pending.pop(0)
        remaining = tuple(c for c in rung.columns if c not in agreed)
        if not remaining:
            continue  # Proved column by column; nothing left to ask.
        budget = timeout_ms if not rung.lemma or len(remaining) > 1 else timeout_ms // 4
        step = check(
            system,
            timeout_ms=budget,
            shard=Shard(
                selector=shard.selector,
                group=remaining,
                assume_agree=tuple(sorted(agreed)),
            ),
            probe=False,
            **options,
        )
        step.shard = Rung(remaining, rung.lemma).label() + f"/given[{len(agreed)}]"
        steps.append(step)
        if step.status == "unsat":
            agreed |= set(rung.columns)
        elif step.status == "sat" and not rung.lemma:
            sat_step = step
        elif not rung.lemma and rung not in retried:
            retried.add(rung)
            pending.append(rung)  # One retry, in case a later step unlocks it.
    return _compose(system, shard, steps, sat_step, agreed)


def _obligation_roots(system: System) -> list[tuple[int, int]]:
    """(obligation index, root node) for constraints and constraining lookups."""
    out = list(enumerate(system.constraints))
    base = len(system.constraints)
    for position, lookup in enumerate(system.lookups):
        if tables.is_constraining(lookup.domain):
            for node in (lookup.numerator, *lookup.tuple_):
                out.append((base + position, node))
    return out


def _compose(
    system: System,
    shard: Shard,
    steps: list[Result],
    sat_step: Result | None,
    agreed: frozenset[str],
) -> Result:
    """Fold ladder steps into the family-under-selector verdict."""
    open_outputs = sorted(set(system.by_role("output")) - agreed)
    if sat_step is not None:
        merged = replace(sat_step)
    elif not open_outputs:
        merged = Result(family=system.family, status="unsat", seconds=0.0)
    else:
        merged = Result(
            family=system.family,
            status="unknown",
            seconds=0.0,
            reason_unknown="open ladder steps: " + ", ".join(open_outputs),
        )
        merged.open_shards = tuple(open_outputs)
    merged.family = system.family
    merged.seconds = sum(step.seconds for step in steps)
    merged.shard = (
        (f"{shard.selector}/" if shard.selector else "")
        + f"ladder[{len(steps)} steps]"
    )
    if steps:
        merged.modelled_lookups = steps[0].modelled_lookups
        merged.skipped_bus_lookups = steps[0].skipped_bus_lookups
    return merged


def run_query(query: Query, timeout_ms: int = 0) -> Result:
    import z3  # Imported lazily: emitting SMT-LIB must not require the bindings.

    solver = z3.Solver()
    if timeout_ms:
        solver.set("timeout", timeout_ms)
    solver.add(z3.parse_smt2_string(query.text))

    started = time.perf_counter()
    verdict = solver.check()
    seconds = time.perf_counter() - started

    if verdict == z3.sat:
        status = "sat"
    elif verdict == z3.unsat:
        status = "unsat"
    else:
        status = "unknown"

    result = Result(
        family=query.family,
        status=status,
        seconds=seconds,
        modelled_lookups=query.modelled_lookups,
        skipped_bus_lookups=query.skipped_bus_lookups,
    )
    if result.status == "unknown":
        result.reason_unknown = solver.reason_unknown()
        return result
    if result.status == "unsat":
        return result

    model = solver.model()
    values = {
        declaration.name(): model[declaration].as_long()
        for declaration in model.decls()
        if z3.is_int_value(model[declaration])
    }
    for copy in query.copies:
        decoded = Witness()
        for name, role in query.columns.items():
            value = values.get(query.var(name, copy))
            if value is None:
                # z3 leaves don't-care constants out of the model; any value
                # works, and 0 is in range for every column.
                value = 0
            getattr(decoded, "witness" if role == "witness" else f"{role}s")[
                name
            ] = value
        for name, factor in query.eliminated.items():
            decoded.witness[name] = _solve_linear(query.nodes, factor, name, decoded)
        result.witnesses[copy] = decoded

    if len(query.copies) >= 2:  # The satisfiability probe emits a single copy.
        first, second = query.copies[0], query.copies[1]

        def value(copy: str, name: str) -> int:
            side = query.columns[name]
            witness = result.witnesses[copy]
            return getattr(witness, "witness" if side == "witness" else f"{side}s")[
                name
            ]

        result.differing_outputs = tuple(
            name
            for name in query.conclusion
            if value(first, name) != value(second, name)
        )
    return result


def _solve_linear(nodes: tuple, factor: int, column: str, decoded: Witness) -> int:
    """The value the projected witness must take for `factor` to vanish.

    The emitter replaced this factor with its solvability condition (see
    `eliminable_inverses`), so the model carries no value for `column`; the
    factor is linear in it, so evaluating at 0 and 1 recovers offset and slope
    and one field division re-solves it.  Zero slope means the factor vanishes
    for no choice or every choice -- either way the model satisfied some other
    factor of the constraint, and any in-range value serves; 0 is one.
    """
    assignment = {**decoded.inputs, **decoded.outputs, **decoded.witness}
    at_zero = _eval_node(nodes, factor, {**assignment, column: 0})
    slope = (_eval_node(nodes, factor, {**assignment, column: 1}) - at_zero) % MODULUS
    if slope == 0:
        return 0
    return -at_zero * pow(slope, MODULUS - 2, MODULUS) % MODULUS


def _eval_node(nodes: tuple, root: int, assignment: dict[str, int]) -> int:
    """Field value of one DAG node under a full column assignment."""
    values: dict[int, int] = {}
    for index in range(root + 1):
        node = nodes[index]
        if node.op == "const":
            values[index] = node.value % MODULUS
        elif node.op == "col":
            values[index] = assignment[node.name] % MODULUS
        elif node.op == "neg":
            values[index] = -values[node.args[0]] % MODULUS
        else:
            lhs, rhs = values[node.args[0]], values[node.args[1]]
            op = {"add": lhs + rhs, "sub": lhs - rhs, "mul": lhs * rhs}[node.op]
            values[index] = op % MODULUS
    return values[root]


def counterexample_payload(system: System, result: Result) -> dict[str, object]:
    """A `sat` model as a self-contained malicious-witness record.

    Both sides satisfy every constraint and every modelled table membership, so
    each is a valid witness in isolation; what the pair demonstrates is that the
    family admits two of them for one architectural input.  That makes the
    record directly usable as a mutation-corpus seed rather than only a report.
    """
    if result.status != "sat":
        raise ValueError(f"no counterexample to export: verdict is {result.status}")
    first, second = COPIES
    return {
        "family": system.family,
        "kind": "per_row_witness_uniqueness_counterexample",
        "differing_outputs": list(result.differing_outputs),
        "shared_inputs": dict(sorted(result.witnesses[first].inputs.items())),
        "witnesses": {
            copy: {
                "witness": dict(sorted(result.witnesses[copy].witness.items())),
                "outputs": dict(sorted(result.witnesses[copy].outputs.items())),
            }
            for copy in (first, second)
        },
        "unmodelled_bus_lookups": list(result.skipped_bus_lookups),
    }


def format_result(result: Result) -> str:
    if result.status == "skipped":
        return "\n".join(
            [
                f"family                : {result.family}",
                "verdict               : skipped",
                f"reason                : {result.skip_reason}",
            ]
        )
    lines = [
        f"family                : {result.family}",
        f"verdict               : {result.status}",
        f"solver wall clock     : {result.seconds:.3f}s",
        f"table lookups modelled: {len(result.modelled_lookups)}",
        f"bus lookups ignored   : {len(result.skipped_bus_lookups)}"
        + (
            f" ({', '.join(result.skipped_bus_lookups)})"
            if result.skipped_bus_lookups
            else ""
        ),
    ]
    if result.status == "unsat":
        lines.append(f"constraints satisfiable: {result.constraints_satisfiable}")
        if result.vacuous:
            lines.append(
                "VACUOUS: nothing satisfies the constraints, so uniqueness is "
                "empty. Fix the model before reading this as evidence."
            )
        elif result.constraints_satisfiable is None:
            lines.append(
                "the honest-witness probe did not finish, so this unsat is not "
                "yet known to be non-vacuous."
            )
        else:
            lines.append(
                "outputs are a function of the inputs, under the assumptions "
                "in `air_uniqueness.py explain`."
            )
        return "\n".join(lines)
    if result.status == "unknown":
        lines.append(f"reason unknown        : {result.reason_unknown}")
        return "\n".join(lines)

    lines.append(f"differing outputs     : {', '.join(result.differing_outputs)}")
    return "\n".join(lines + _format_counterexample(result))


def _format_counterexample(result: Result) -> list[str]:
    """The witness pair, side by side, with the disagreements marked."""
    first, second = COPIES
    lines = ["", "shared architectural inputs:"]
    lines += [
        f"  {name:<24} {value}"
        for name, value in sorted(result.witnesses[first].inputs.items())
    ]
    header = f"  {'column':<24} {'copy ' + first:>12} {'copy ' + second:>12}"
    for title, side in (
        ("witness columns (free prover choice)", "witness"),
        ("architectural outputs", "outputs"),
    ):
        lines += ["", f"{title}:", header]
        left_side = getattr(result.witnesses[first], side)
        right_side = getattr(result.witnesses[second], side)
        for name in sorted(left_side):
            left, right = left_side[name], right_side[name]
            marker = "  <-- differs" if left != right else ""
            lines.append(f"  {name:<24} {left:>12} {right:>12}{marker}")
    return lines
