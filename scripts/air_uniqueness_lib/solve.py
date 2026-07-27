"""z3 runner over the emitted SMT-LIB2 text, with counterexample decoding.

The solver is fed the emitted text rather than a parallel z3-API construction,
so the artifact a reviewer reads is the artifact that was checked.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Sequence

from .analysis import column_support, implied_column_bounds
from .smtlib import (
    COPIES,
    Query,
    Shard,
    emit_satisfiability_query,
    emit_uniqueness_query,
)

try:
    from riscv_air_ir_lib import tables
    from riscv_air_ir_lib.ir import MODULUS, System
except ModuleNotFoundError:  # Imported as scripts.air_uniqueness_lib in tests.
    from scripts.riscv_air_ir_lib import tables
    from scripts.riscv_air_ir_lib.ir import MODULUS, System


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
    fresh: bool = False,
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
    query = emit_uniqueness_query(system, **options)
    result = (
        run_query_fresh(query, timeout_ms)
        if fresh
        else run_query(query, timeout_ms)
    )
    # A full proof shard that is genuinely sat still owes callers the decoded
    # AIR witness pair.  Re-run only that easy direction in-process; weakened
    # shards are converted to `unknown` by either runner and never reach here.
    if fresh and result.status == "sat":
        result = run_query(query, timeout_ms)
    result.shard = shard.label()
    if result.unique and probe:
        result.constraints_satisfiable = satisfiable(system, timeout_ms, **options)
    return result


def satisfiable(
    system: System, timeout_ms: int = 0, *, fresh: bool = False, **options: object
) -> bool | None:
    """Whether an honest witness exists at all, or None if the probe ran out.

    `None` is not `False`.  An unsatisfiable system is trivially unique, so a
    probe that times out leaves the accompanying `unsat` unqualified rather than
    disproved -- reporting it as VACUOUS would invent a defect out of a budget.
    """
    query = emit_satisfiability_query(system, **options)
    result = (
        run_query_fresh(query, timeout_ms)
        if fresh
        else run_query(query, timeout_ms)
    )
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


def prefers_ladder(system: System) -> bool:
    """Whether the emitted shape is a long byte-product carry chain.

    Eight `range_check_8_11` requests are the MULH/DIV shape that repeatedly
    exhausts a monolithic nonlinear query before the exact prefix ladder closes
    it.  This is scheduling only: `ladder` still proves every output through a
    complete sequence of two-copy queries.
    """
    return sum(
        lookup.domain == "range_check_8_11" for lookup in system.lookups
    ) >= 8


# Fail-closed identity of the production-emitted DIV-family row system.  The
# extraction differential proves that this structure is the AIR evaluated by
# `Semantics(S)`/`Entries(S)`; `_division_structure_digest` makes every column,
# node, direct constraint, lookup, and referenced table shape part of the
# certificate boundary.
DIVISION_CONTROL_DIGEST = (
    "2feaee5ddd2b1f24a3264a2a09840a3dedb77c9761c8733f7980f9dee97b5d0a"
)
DIVISION_SELECTORS = (
    "opcode_div_flag",
    "opcode_divu_flag",
    "opcode_rem_flag",
    "opcode_remu_flag",
)


def _division_structure_digest(system: System) -> str:
    payload = {
        "family": system.family,
        "columns": [
            (
                column.name,
                column.role,
                None
                if column.domain is None
                else (
                    column.domain.lo,
                    column.domain.hi,
                    column.domain.stride,
                    column.domain.why,
                ),
            )
            for column in system.columns
        ],
        "nodes": [
            (node.op, node.args, node.value, node.name) for node in system.nodes
        ],
        "constraints": system.constraints,
        "lookups": [
            (lookup.domain, lookup.numerator, lookup.tuple_, lookup.label)
            for lookup in system.lookups
        ],
        # The certificate uses byte/carry and positive-difference widths, not
        # just relation names. A schema-width change must therefore invalidate
        # it even when the extracted request DAG itself is unchanged.
        "table_semantics": {
            domain: (
                tables.ARITIES.get(domain),
                tables.BOX_TABLES.get(domain),
                tables.BITWISE_WIDTHS
                if domain == tables.BITWISE_DOMAIN
                else None,
                tables.is_constraining(domain),
            )
            for domain in sorted({lookup.domain for lookup in system.lookups})
        },
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def division_control(
    system: System,
    selector: str,
    timeout_ms: int,
    **options: object,
) -> Result:
    """Close one DIV-family opcode against its arithmetic known-answer control.

    Why the control follows from the certified AIR shape:

    * the eight `range_check_8_11` product requests byte-bound `(q, r)` and
      bound every base-256 carry. Subtracting two recurrences cancels the
      shared (possibly non-byte) dividend limbs; the remaining terms are too
      small to wrap M31. The eight sign-extension limbs telescope modulo
      ``2^64``; the opcode-specific canonical quotient signs and strict
      remainder bounds make the difference strictly smaller than ``2^64``, so
      this is the integer equality ``C*Q_a + R_a = C*Q_b + R_b``;
    * the divisor byte requests, sign checks, negation recurrence, high-to-low
      marker scan, and positive `lt_diff - 1` request give `D = abs(C) > 0`
      and either ``0 <= R < D`` or ``-D < R <= 0`` in the regular case;
    * the zero-divisor constraints instead pin one shared opcode-specific
      quotient, after which the same subtracted recurrence pins the remainder.

    The emitted control query proves the elementary consequence: two rows with
    one divisor have the same integer `(Q, R)` and, because every limb is a
    byte, the same limb representation.  The surrounding two-copy queries
    prove that operand limbs and zero/sign controls agree from the architectural
    inputs and that those agreed quotient/remainder limbs determine every real
    AIR output column.

    This is deliberately fail-closed rather than a name-based special case.
    Any mutation of an extracted obligation or referenced table shape changes
    the structural digest and turns the result into `unknown` until the
    derivation is re-audited.
    """
    observed = _division_structure_digest(system)
    if system.family != "div" or observed != DIVISION_CONTROL_DIGEST:
        return Result(
            family=system.family,
            status="unknown",
            seconds=0.0,
            reason_unknown=(
                "DIV known-answer control certificate does not match the "
                f"production-emitted IR (observed {observed})"
            ),
            shard=f"{selector}/division-control",
        )
    if selector not in DIVISION_SELECTORS:
        return Result(
            family=system.family,
            status="unknown",
            seconds=0.0,
            reason_unknown=f"DIV control has no certified opcode {selector!r}",
            shard=f"{selector}/division-control",
        )

    steps: list[Result] = []
    prerequisite = check(
        system,
        timeout_ms,
        refine=bool(options.get("refine", True)),
        assume_domains=bool(options.get("assume_domains", False)),
        derived=bool(options.get("derived", True)),
        shard=Shard(
            selector=selector,
            group=(
                "zero_divisor",
                "b_sign",
                "c_sign",
                "sign_xor",
                *(f"rs1_next_{index}" for index in range(4)),
                *(f"rs2_next_{index}" for index in range(4)),
            ),
        ),
        probe=False,
        fresh=True,
    )
    steps.append(prerequisite)
    if prerequisite.status != "unsat":
        return _control_open(system, selector, "operand/sign agreement", steps)

    theorem = run_query_fresh(_division_theorem_query(), timeout_ms)
    steps.append(theorem)
    if theorem.status != "unsat":
        return _control_open(system, selector, "integer known-answer theorem", steps)

    destination = check(
        system,
        timeout_ms,
        refine=bool(options.get("refine", True)),
        assume_domains=bool(options.get("assume_domains", False)),
        derived=bool(options.get("derived", True)),
        shard=Shard(
            selector=selector,
            group=("rd_nonzero",),
            lookup_prefix=0,
        ),
        probe=False,
        fresh=True,
    )
    steps.append(destination)
    if destination.status != "unsat":
        return _control_open(system, selector, "destination marker", steps)

    qr_columns = tuple(f"q_{index}" for index in range(4)) + tuple(
        f"r_{index}" for index in range(4)
    )
    for output in system.by_role("output"):
        binding = check(
            system,
            timeout_ms,
            refine=bool(options.get("refine", True)),
            assume_domains=bool(options.get("assume_domains", False)),
            derived=bool(options.get("derived", True)),
            shard=Shard(
                selector=selector,
                group=(output,),
                assume_agree=(*qr_columns, "rd_nonzero"),
                lookup_prefix=0,
            ),
            probe=False,
            fresh=True,
        )
        steps.append(binding)
        if binding.status != "unsat":
            return _control_open(
                system, selector, f"AIR output binding {output}", steps
            )

    return Result(
        family=system.family,
        status="unsat",
        seconds=sum(step.seconds for step in steps),
        modelled_lookups=prerequisite.modelled_lookups,
        skipped_bus_lookups=prerequisite.skipped_bus_lookups,
        shard=(
            f"{selector}/division-control["
            f"{len(steps)} proofs@{DIVISION_CONTROL_DIGEST[:12]}]"
        ),
    )


def division_known_answer_satisfiable(
    system: System, selector: str, timeout_ms: int, **options: object
) -> bool | None:
    """Check one concrete valid DIV row against the complete emitted system.

    A generic satisfiability search is unnecessarily hard for signed DIV: the
    solver has to invent operands, quotient/remainder limbs, signs, carries,
    comparison markers, and inverse witnesses at once. This control pins the
    complete easy row ``0 / 1 = 0 remainder 0`` (with a real nonzero
    destination), then asks the *unchanged* one-copy AIR query. `sat` therefore
    proves non-vacuity of the corresponding opcode shard; it is not a synthetic
    model or an assumed witness.

    The same exact-IR certificate guards the assignment. A changed system gets
    no inherited non-vacuity claim.
    """
    if (
        system.family != "div"
        or selector not in DIVISION_SELECTORS
        or _division_structure_digest(system) != DIVISION_CONTROL_DIGEST
    ):
        return None

    query = emit_satisfiability_query(
        system,
        refine=bool(options.get("refine", True)),
        assume_domains=bool(options.get("assume_domains", False)),
        derived=bool(options.get("derived", True)),
        shard=Shard(selector=selector),
    )
    # Start from zero so every unlisted arithmetic witness is explicitly pinned
    # too. This makes the check a known-answer test, not a narrowed search.
    answer = {column.name: 0 for column in system.columns}
    answer.update(
        {
            "clock": 9,
            "pc": 0,
            "rd_addr": 1,
            "rs1_addr": 2,
            "rs2_addr": 3,
            "rs2_prev_0": 1,
            "rs2_next_0": 1,
            "r_zero": 1,
            "c_sum_inv": 1,
            "rd_nonzero": 1,
            "rd_inv": 1,
            "next_pc": 4,
            selector: 1,
        }
    )
    assertions = "\n".join(
        f"(assert (= {query.var(name, COPIES[0])} {value}))"
        for name, value in answer.items()
    )
    marker = "(check-sat)\n"
    if not query.text.endswith(marker):
        raise AssertionError("satisfiability query lost its final check-sat marker")
    pinned = replace(
        query,
        text=query.text[: -len(marker)] + assertions + "\n" + marker,
    )
    result = run_query_fresh(pinned, timeout_ms)
    return {"sat": True, "unsat": False}.get(result.status)


def _control_open(
    system: System, selector: str, stage: str, steps: Sequence[Result]
) -> Result:
    failed = steps[-1]
    return Result(
        family=system.family,
        status="unknown",
        seconds=sum(step.seconds for step in steps),
        reason_unknown=f"{stage} open: {failed.status} {failed.reason_unknown}".strip(),
        modelled_lookups=failed.modelled_lookups,
        skipped_bus_lookups=failed.skipped_bus_lookups,
        shard=f"{selector}/division-control",
        open_shards=(stage,),
    )


def _division_theorem_query() -> Query:
    """SMT spelling of quotient/remainder and canonical-limb uniqueness.

    There is intentionally no absolute integer `B` here. DIV's source limbs are
    bus inputs and are not locally byte-ranged, so interpreting their canonical
    field representatives as a u32 would strengthen the real row system. The
    certified fact is the *subtracted* carry balance below: the shared source
    terms cancel before the remaining bounded recurrence is lifted to integers.
    """
    lines = [
        "; certified DIV known-answer control",
        "(set-logic ALL)",
        "(set-option :produce-models false)",
    ]

    def declare(name: str, lo: int | None = None, hi: int | None = None) -> str:
        lines.append(f"(declare-const {name} Int)")
        if lo is not None:
            lines.append(f"(assert (<= {lo} {name}))")
        if hi is not None:
            lines.append(f"(assert (<= {name} {hi}))")
        return name

    zero = declare("zero_divisor", 0, 1)
    remainder_negative = declare("remainder_negative", 0, 1)
    divisor_negative = declare("divisor_negative", 0, 1)
    divisor_magnitude = declare("D")
    divisor = declare("C")
    lines.append(
        f"(assert (= {divisor} (ite (= {divisor_negative} 0) "
        f"{divisor_magnitude} (- {divisor_magnitude}))))"
    )
    lines.append(
        f"(assert (=> (= {zero} 0) (> {divisor_magnitude} 0)))"
    )

    q_values: list[str] = []
    r_values: list[str] = []
    q_limbs: list[list[str]] = []
    r_limbs: list[list[str]] = []
    radix = 1 << 32
    for copy in COPIES:
        quotient = declare(f"Q_{copy}")
        remainder = declare(f"R_{copy}")
        quotient_sign = declare(f"q_sign_{copy}", 0, 1)
        remainder_zero = declare(f"r_zero_{copy}", 0, 1)
        q = [declare(f"q_{index}_{copy}", 0, 255) for index in range(4)]
        r = [declare(f"r_{index}_{copy}", 0, 255) for index in range(4)]
        q_word = "(+ " + " ".join(
            f"(* {1 << (8 * index)} {limb})" for index, limb in enumerate(q)
        ) + ")"
        r_word = "(+ " + " ".join(
            f"(* {1 << (8 * index)} {limb})" for index, limb in enumerate(r)
        ) + ")"
        lines.append(
            f"(assert (= {quotient} (- {q_word} (* {radix} {quotient_sign}))))"
        )
        lines.append(
            f"(assert (= {remainder} (- {r_word} "
            f"(* {radix} {remainder_negative} (- 1 {remainder_zero})))))"
        )
        regular_bound = (
            f"(ite (= {remainder_negative} 0) "
            f"(and (<= 0 {remainder}) (< {remainder} {divisor_magnitude})) "
            f"(and (< (- {divisor_magnitude}) {remainder}) (<= {remainder} 0)))"
        )
        lines.append(f"(assert (=> (= {zero} 0) {regular_bound}))")
        q_values.append(quotient)
        r_values.append(remainder)
        q_limbs.append(q)
        r_limbs.append(r)

    # This is the reviewed consequence of the two real eight-limb carry chains,
    # not a fresh semantic assumption about either source word in isolation.
    left = f"(+ (* {divisor} {q_values[0]}) {r_values[0]})"
    right = f"(+ (* {divisor} {q_values[1]}) {r_values[1]})"
    lines.append(f"(assert (= {left} {right}))")
    lines.append(
        f"(assert (=> (= {zero} 1) (= {q_values[0]} {q_values[1]})))"
    )

    differences = [
        f"(not (= {q_values[0]} {q_values[1]}))",
        f"(not (= {r_values[0]} {r_values[1]}))",
        *(
            f"(not (= {q_limbs[0][index]} {q_limbs[1][index]}))"
            for index in range(4)
        ),
        *(
            f"(not (= {r_limbs[0][index]} {r_limbs[1][index]}))"
            for index in range(4)
        ),
    ]
    lines.append(f"(assert (or {' '.join(differences)}))")
    lines.append("(check-sat)")
    return Query(
        text="\n".join(lines) + "\n",
        family="div",
        columns={},
        copies=(),
        modelled_lookups=("certified DIV integer known-answer theorem",),
    )


def ladder(
    system: System,
    timeout_ms: int,
    shard: Shard = Shard(),
    fresh: bool = False,
    **options: object,
) -> Result:
    """Sequential uniqueness for one family under one opcode selector.

    Chain rule: with the output steps attempted in any fixed order, each
    assuming agreement on everything already proved, `unsat` on every output
    step composes to family uniqueness -- and completeness survives the
    ordering, because a family counterexample has a first differing column in
    that order and is a model of exactly that step.  Witness lemmas are pure
    strengthening: a lemma is assumed only after its own `unsat`.

    Budget: output steps, the joint lemma, and mechanically identified lookup-
    prefix digits get `timeout_ms` each; other singleton lemmas run at a
    quarter, because a lemma that misses its window costs only sharing, not
    soundness. Steps are attempted in carry order with direct sign facts first
    and the joint fallback last, re-planned after every success. An output step
    that failed is retried once if later steps widened the agreed set. The
    composed verdict never averages: one open output step makes the family
    `unknown` however many closed.
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

    def order(rung: Rung, agreed: frozenset[str]) -> tuple[int, int, int, str]:
        remaining = tuple(c for c in rung.columns if c not in agreed)
        prefix = _proof_lookup_prefix(system, remaining or rung.columns, rung.lemma)
        if rung.lemma and len(rung.columns) > 1:
            phase = 3  # Joint fallback only after every singleton had its turn.
        elif rung.lemma and prefix is None:
            phase = 0  # Cheap direct/sign facts unlock the carry chain.
        elif rung.lemma:
            phase = 1  # Lookup-carried witness digits, in request order.
        elif prefix not in (None, 0):
            phase = 2  # Lookup-carried architectural product digits.
        else:
            phase = 4  # Direct write-back / next-pc after semantic outputs.
        return (
            phase,
            prefix if prefix is not None else -1,
            outside(rung, agreed),
            rung.label(),
        )

    pending = list(plan_rungs(system))
    agreed: frozenset[str] = frozenset(shard.assume_agree)
    steps: list[Result] = []
    retried: set[Rung] = set()
    sat_step: Result | None = None
    while pending and sat_step is None:
        pending.sort(key=lambda rung: order(rung, agreed))
        rung = pending.pop(0)
        remaining = tuple(c for c in rung.columns if c not in agreed)
        if not remaining:
            continue  # Proved column by column; nothing left to ask.
        lookup_prefix = _proof_lookup_prefix(system, remaining, rung.lemma)
        full_budget = (
            not rung.lemma or len(remaining) > 1 or lookup_prefix is not None
        )
        budget = (
            timeout_ms
            if full_budget or timeout_ms == 0
            else max(1, timeout_ms // 4)
        )
        step = check(
            system,
            timeout_ms=budget,
            shard=Shard(
                selector=shard.selector,
                group=remaining,
                assume_agree=tuple(sorted(agreed)),
                lookup_prefix=lookup_prefix,
            ),
            probe=False,
            fresh=fresh,
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


def _proof_lookup_prefix(
    system: System, columns: tuple[str, ...], lemma: bool
) -> int | None:
    """Smallest lookup prefix sufficient for a ladder conclusion, when one is
    mechanically visible.

    Carry-chain tables put the digit they range-check in tuple slot zero and
    list requests in recurrence order.  Keeping through the first request whose
    slot zero is a concluded column retains that digit and every predecessor,
    while dropping later requests.  This is a weakening, so only its `unsat`
    direction is evidence (the query records that fact).

    An architectural output no constraining lookup reads at all is controlled
    solely by direct constraints once the ladder prefix is shared; asking it
    with no table lookups is the strongest cheap proof.  Witness lemmas without
    the slot-zero shape keep the full system: sign witnesses, for example, sit
    inside a lookup expression rather than in slot zero.
    """
    support = column_support(system)
    wanted = set(columns)
    read_by_lookup: set[str] = set()
    for position, lookup in enumerate(system.lookups):
        if not tables.is_constraining(lookup.domain):
            continue
        read_by_lookup |= support[lookup.numerator]
        for node in lookup.tuple_:
            read_by_lookup |= support[node]
        first = system.nodes[lookup.tuple_[0]]
        if first.op == "col" and first.name in wanted:
            return position + 1
    roles = {column.name: column.role for column in system.columns}
    if not lemma and all(roles[name] == "output" for name in columns):
        if wanted.isdisjoint(read_by_lookup):
            return 0
    return None


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
    if query.weakened:
        result.status = "unknown"
        result.reason_unknown = (
            "proof-only weakened shard is satisfiable; dropped AIR lookups make "
            "that model inconclusive"
        )
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


def run_query_fresh(query: Query, timeout_ms: int = 0) -> Result:
    """Decide one proof shard in a disposable Python/Z3 process.

    Long nonlinear queries measurably degrade later queries when solver use is
    kept in one process, while the same later shards finish quickly in a clean
    process. A reported external 529/worker exit carries no Z3 proof verdict.
    A proof shard needs only a verdict, so process isolation is the exact
    lifecycle boundary: no solver state crosses from one logical query to the
    next.

    Any abnormal worker exit, malformed reply, or outer wall timeout is
    `unknown`, never `unsat`.  This is important: isolation improves liveness
    but cannot manufacture proof evidence.
    """
    helper = Path(__file__).with_name("fresh_solver.py")
    started = time.perf_counter()
    deadline = None if timeout_ms == 0 else started + timeout_ms / 1000 + 5.0
    active: list[subprocess.Popen[str]] = []
    results: list[Result] = []
    try:
        for seed in (0, 17, 31):
            process = subprocess.Popen(
                [sys.executable, str(helper), str(timeout_ms), str(seed)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            active.append(process)
            assert process.stdin is not None
            process.stdin.write(query.text)
            process.stdin.close()
            process.stdin = None
        while active:
            for process in list(active):
                returncode = process.poll()
                if returncode is None:
                    continue
                active.remove(process)
                stdout, stderr = process.communicate()
                result = _fresh_result(query, returncode, stdout, stderr)
                results.append(result)
                if result.status in ("unsat", "sat"):
                    return result
            if deadline is not None and time.perf_counter() >= deadline:
                break
            time.sleep(0.01)
    finally:
        for process in active:
            process.terminate()
        for process in active:
            try:
                process.communicate(timeout=1.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
    if not results:
        return Result(
            family=query.family,
            status="unknown",
            seconds=time.perf_counter() - started,
            reason_unknown="isolated solver portfolio exceeded its outer wall timeout",
            modelled_lookups=query.modelled_lookups,
            skipped_bus_lookups=query.skipped_bus_lookups,
        )
    chosen = results[0]
    chosen.seconds = time.perf_counter() - started
    chosen.reason_unknown = "; ".join(
        sorted({result.reason_unknown for result in results if result.reason_unknown})
    )
    return chosen


def _fresh_result(
    query: Query, returncode: int, stdout: str, stderr: str
) -> Result:
    """Decode one isolated worker without promoting process failure to proof."""
    if returncode != 0:
        diagnostic = (stderr or stdout).strip().splitlines()
        detail = diagnostic[-1] if diagnostic else "no diagnostic"
        return Result(
            family=query.family,
            status="unknown",
            seconds=0.0,
            reason_unknown=f"isolated solver exited with status {returncode}: {detail}",
            modelled_lookups=query.modelled_lookups,
            skipped_bus_lookups=query.skipped_bus_lookups,
        )
    try:
        payload = json.loads(stdout)
        status = payload["status"]
        if status not in ("sat", "unsat", "unknown"):
            raise ValueError(f"invalid status {status!r}")
        seconds = float(payload["seconds"])
        reason_unknown = str(payload.get("reason_unknown", ""))
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        return Result(
            family=query.family,
            status="unknown",
            seconds=0.0,
            reason_unknown=f"isolated solver returned a malformed reply: {error}",
            modelled_lookups=query.modelled_lookups,
            skipped_bus_lookups=query.skipped_bus_lookups,
        )
    if status == "sat" and query.weakened:
        status = "unknown"
        reason_unknown = (
            "proof-only weakened shard is satisfiable; dropped AIR lookups make "
            "that model inconclusive"
        )
    return Result(
        family=query.family,
        status=status,
        seconds=seconds,
        reason_unknown=reason_unknown,
        modelled_lookups=query.modelled_lookups,
        skipped_bus_lookups=query.skipped_bus_lookups,
    )


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
