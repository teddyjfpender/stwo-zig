#!/usr/bin/env python3
"""Per-row witness-uniqueness checking for AIR families, via z3.

Uniqueness is one leg of the tractable decomposition of AIR-refines-Sail:

    witness uniqueness (here)
  + completeness (the existing Sail differential)
  + the honest generator matching Sail
  => soundness

The uniqueness leg needs no reference model, which is what makes it cheap:

    for any two witness assignments satisfying the constraints AND the range
    table memberships, if they agree on the architectural INPUTS then they
    agree on the architectural OUTPUTS.

Usage
-----
    python3 -m scripts.air_uniqueness explain
    python3 -m scripts.air_uniqueness emit  <model.json> [-o query.smt2]
    python3 -m scripts.air_uniqueness check <model.json> [--timeout-ms N]
        [--no-refine] [--no-derived-facts] [--opcode F] [--output-column C]
        [--counterexample-json out.json]

`explain` prints the encoding decisions a reviewer has to agree with, including
what a green result does not mean.  `check` exits 0 on `unsat` (unique) and 1
on `sat` or `unknown`.  It answers for one family; `scripts/air_uniqueness_board.py`
schedules it across all of them and folds the shard verdicts into a board.

Not wired into any gate: it is an operator tool until a family's IR is emitted
from the real `air/semantics/` modules rather than hand-written.  The models in
`scripts/tests/fixtures/air_uniqueness/` exist to prove the pipeline itself,
not to say anything about the shipped AIR.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from air_uniqueness_lib import analysis, ir, smtlib, solve
except ModuleNotFoundError:  # Imported as scripts.air_uniqueness in tests.
    from scripts.air_uniqueness_lib import analysis, ir, smtlib, solve


ENCODING_SPEC = """\
Encoding decisions a reviewer must check
========================================

1. Field arithmetic.  Every column is an integer in [0, p), p = 2^31 - 1.
   Polynomials are built with exact integer arithmetic and never implicitly
   reduced; each constraint is discharged as `P = p * k` with `k` a fresh
   integer whose range comes from interval analysis.  There is no `mod` or
   `div` term in the query.
   Why it matters: the closed AUIPC under-constraint existed because
   2^32 = 2p + 2 gave every immediate a second byte decomposition offset by
   p + 2.  An encoding that treated limb arithmetic as unbounded-integer
   arithmetic would have declared that family unique.  Reduction is explicit
   so wraparound stays reachable.  The counterexample for the
   `byte_carry_adder_unranged` model is exactly this shape: a sum limb of
   p - 247 standing in for 9.

2. Range-table membership.  A lookup request is (domain, numerator, tuple).
   The encoding asserts: numerator != 0 in the field  =>  the tuple lies in
   the table.  For the box tables (range_check_20 / 8_11 / 8_8_4 / 8_8 / m31)
   that is a per-component bit-width bound on the canonical representative in
   [0, p) -- the representative is explicit, for the same reason as (1).  For
   `bitwise` it is the box on all four components plus `value` defined by the
   operation, bit by bit: each operand becomes eight 0/1 integers summing to it
   and each result bit is `l*r`, `l + r - l*r` or `l + r - 2*l*r`.  The obvious
   alternative is `int2bv`, which was measured and rejected: it pulls the query
   into the bitvector theory, and a family whose `add` shard closed in 0.4 s did
   not close its `xor` shard in 25 s.  The bit equations sit inside the
   membership implication, never outside it -- asserting them for a row whose
   request is not live would force the operand under 256 unconditionally.
   Widths are transcribed from `air/lookups/tables/schema.zig`; a unit test
   cross-checks the transcription against that file.  `bitwise` counts as a box
   for the purpose of (4b) as well as here: a live request bounds every one of
   its components, including the result.
   THIS IS AN ASSUMPTION, and it points one way.  Per row we simply grant that
   a live request implies membership; what actually enforces it is the LogUp
   argument plus a well-formed preprocessed table, neither of which is in
   scope here.  Consequence: a `sat` answer is unconditionally a real
   under-constraint, because the counterexample respects membership and so
   also satisfies the weaker real system.  An `unsat` answer is conditional on
   the lookup argument really enforcing membership.

3. Bus relations are not tables.  registers_state, memory_access,
   program_access, merkle, poseidon2 and poseidon2_io are multiset buses
   closed across rows and components.  A per-row query cannot learn anything
   from them, so it asserts nothing for them and reports how many it ignored.
   Anything whose only protection is bus closure is invisible here.

4. Four rewrites, all exact, that decide whether the query terminates at all.
   Only the unsat direction is sensitive -- a counterexample is found either
   way, the same asymmetry the soundness argument has.  Treat these as the
   highest-risk part of the encoding: an unsound narrowing deletes
   counterexamples rather than producing visibly wrong ones, so each states the
   argument for why it is implied and each has an off-switch the mutation
   differential drives.
   (a) Factor splitting.  A constraint that is a product is discharged as a
       disjunction over its factors, since a product vanishes in a field iff
       some factor does.  `bit(x)` becomes `x = 0 or x = 1` instead of a
       quadratic diophantine equation.
   (b) Implied column bounds.  A column is narrowed only by consequences of
       the asserted obligations: a constraint whose factors all lie on one line
       of the column space, where that line is a single column, confines it to
       the factor roots, and a box-table request live in every satisfying
       assignment bounds a bare column in its tuple.  Narrowing shrinks the
       quotient ranges the solver must search and never removes an assignment
       the AIR admits.  Iterated to a fixpoint: each pinned column unlocks the
       next pass, because a constraint gated by a pinned flag stops being a
       product once the flag reads as its constant.
       `check --no-refine` disables (b); the unit tests assert that every
       `sat` model stays `sat` without it.
       (b) is what makes the shipped families tractable at all.  Every table
       request in `air/lookups/` is gated by `-enabler`, never by a literal, so
       a numerator-is-a-constant test concludes nothing and leaves every limb
       free over [0, p).  The placement constraint pins `enabler = 1`, and
       Gaussian elimination over the constraints that are single linear
       equations turns that into "this request is live in every satisfying
       assignment", which is an implication, not an assumption.
   (c) Node renormalisation.  A constraint pins a *line* of the column space,
       not a column: the AIR spells a byte carry as
       `(a + b + carry_in - s) * inv(256)` with `inv(256) = 2^23`, and `bit()`
       of that pins the line to {0, 1} while pinning no column in it.  Where a
       node's field value is confined to a finite set, the emitter hands its
       parents a representative in that set instead of the expression.  Exact,
       because every assertion here reads a node only through its residue mod p,
       so a congruent substitution changes nothing, and the representative
       exists in every satisfying assignment.  Without it, interval arithmetic
       multiplies the width by 2^23 per limb, four limbs reach 10^60 on the
       `inline_carry_adder` fixture, and the quotient discharging `P = p*k`
       ranges over 10^18 values.  Measured on the shipped families: AUIPC goes
       from 19.1 s to 0.3 s and its widest declared bound from 3e60 to 2e9.
   (d) Shared determined columns.  The two copies agree on the inputs by
       hypothesis, so a column the constraints determine from inputs takes the
       same value in both, and the query gives it one variable rather than two.
       Iterated: a node pinned to a single value whose degree-one expansion has
       exactly one column outside the set determines that column.  This is not
       cosmetic.  A register the row only reads still has a `_next` column tied
       to `_prev` by a selector-gated constraint; it is the operand of the
       bitwise requests, and with two names the solver must first prove an
       8-bit decomposition unique before concluding anything about the result.
       An output that turns out to be determined is decided by this analysis
       rather than by the solver, which is why (c) and (d) share one off-switch:
       `--no-derived-facts` drops both, and the mutation differential in
       `test_air_uniqueness.py` requires the two encodings to agree on every
       one-obligation deletion of every fixture.

4b. Declared input domains, OFF BY DEFAULT.  A column may carry a `domain`: a
   range, an optional stride, and a one-line justification, all emitted in the
   IR.  With `check --assume-declared-domains` both copies get
   `lo <= x <= hi` and, where a stride is declared, `x = stride * k` for an
   explicit integer `k` -- no `mod`, for the reason in (1).
   THIS IS AN ASSUMPTION AND IT POINTS THE OTHER WAY FROM (4).  Narrowing an
   input deletes witnesses, so it can turn a real `sat` into `unsat` and hide a
   bug, which is why it is opt-in and why three rules contain it:
   - only an `input` may declare a domain.  Bounding an output or a witness
     would delete exactly the forgeries this pipeline looks for;
   - the justification lives in the IR, so the assumption set is auditable
     without reading the emitter;
   - the flag makes what an assumption carries measurable rather than argued.
   Consequence, unchanged in shape from (2): `sat` stays unconditional, since a
   counterexample inside the domain also satisfies the wider system.  `unsat`
   becomes conditional on the domain as well as on the lookup argument.
   The one domain the shipped IR declares is `pc`: 4-aligned and below 2^30,
   because the row consumes `program_access(pc, ..)` and the yielding side is
   the program table, whose address the AIR splits into range-checked 20- and
   8-bit limbs (`air/program/interaction.zig`).  The reason to reach for it is
   a `sat` at an input no execution presents -- `jal` once reported one at
   `pc = p - 4`.  It is off by default because assuming it currently costs
   solver time and decides nothing: with the `range_check_m31` exclusion and
   (b) in place, every family that terminates reaches the same verdict without
   it, and two families that terminate without it time out with it.

4c. Sharding, and why a shard verdict adds up to a family verdict.  A family
   splits along two axes, and both are complete case splits, so the family is
   unsat iff every shard is.
   - by output: the negated conclusion is a disjunction over outputs, so one
     query per disjunct covers it;
   - by opcode: only where the IR carries a non-product constraint expanding to
     `sum(f) - 1 = 0` with a `bit` constraint on every `f` in it, and every `f`
     an input.  Both facts are read off the IR, never off a naming convention:
     `f + g = 1` alone allows f = 7, g = -6, and enumerating two cases would
     delete every other solution and any counterexample living there.  Inputs
     only, because the copies are one variable on an input, so one case pins
     both; a one-hot over witnesses would need the |F|^2 cross product.
   The pinned opcode enters as a *bound*, not an assertion, so interval analysis
   sees every other opcode's machinery collapse to a statically zero factor; the
   emitter then drops those constraints and the nodes only they reached.  A
   statically zero factor discharges its product and a factor whose interval
   contains no multiple of p cannot be why one vanished -- both read off the
   declared column ranges alone, never off (c), because discharging a constraint
   with a fact derived from it is circular.
   Sharding is not uniformly faster and the board does not pretend it is; see
   the benchmark in the commit message.  It is uniformly *sharper*: a sat shard
   names the output and the opcode without anyone reading a model.

5. Inputs versus outputs.  An `input` column is what the row is given and may
   not choose: the program counter and clock, opcode selectors, the immediate,
   and the `previous` side of an access.  An `output` column is what the row
   claims about the machine after the step: result limbs, the `next` side of
   an access, the next program counter.  Everything else is `witness` -- free
   prover choice: sign bits, comparison markers, carries, inverse
   certificates.  The classification is part of the model, not inferred, and a
   wrong classification silently changes the theorem.  Three failure modes to
   check by hand:
   - marking a genuinely free column `input` makes it one variable across
     copies and can turn a real `sat` into `unsat`;
   - marking a derived value `output` when nothing observes it can produce a
     `sat` nobody cares about;
   - omitting the family's placement constraint.  Every opcode constraint is
     gated by the activation flag, so an inactive row leaves every output
     free and the family reports `sat` for a reason that says nothing about
     its semantics.  The extractor must emit `placementConstraint` alongside
     `evaluate`, pinning the row active.  This was observed, not predicted:
     a synthetic model at real-family size reported `sat` until it was added.

6. What the query does NOT cover.  Read a green result narrowly.
   - Cross-row properties.  One row, no `next`/`prev` row, no boundary
     conditions.  Transition and permutation arguments are out of scope.
   - Multiset and LogUp properties.  Numerator signs (yield vs consume),
     batch composition, denominators, and global sum-to-zero are not
     modelled; only the zero/non-zero status of a numerator is read.
   - Completeness.  Uniqueness says at most one output per input.  It does not
     say the honest witness satisfies the constraints, nor that the unique
     output is the one Sail specifies.  Those are the other two legs.
   - Column presence.  A column absent from the extracted IR is invisible; the
     IR is only as good as the extractor.
   - Degenerate uniqueness.  An unsatisfiable constraint system is trivially
     unique.  Pair every `unsat` with a satisfiable honest-witness check.
   - Families with nothing to conclude about.  A family whose columns carry no
     `output` role gets the verdict `skipped`, with the reason, rather than the
     `unsat` an empty disjunction would produce.
   - Budget.  A shard that runs out is `unknown` and makes its family a
     `timeout`; nine unsat shards and one timeout is not an unsat family.  The
     same goes for the honest-witness probe: a probe that does not finish leaves
     the accompanying `unsat` unqualified, not disproved.

7. Expression-valued outputs.  Only columns carry roles.  If an architectural
   output is an expression (e.g. `composeU32(next_limbs)`), the extractor
   introduces an alias column plus a defining constraint, which is exactly
   equivalent and keeps one mechanism instead of two.
   The next program counter is the case that matters.  One retired step
   produces three things: the word written, the next clock, and the next pc.
   The first is a committed column everywhere.  The other two appear only inside
   the `registers_state` emit request, so a classifier reading committed columns
   would never ask about them -- and `jalr`, whose jump target is a pair of
   columns any such classifier calls witness, would report `unsat` while saying
   nothing about where it jumps.  The extractor therefore reads both out of the
   request: it checks the emitted clock IS `clock + 1`, making it a function of
   an input and so nothing to ask about, and aliases the emitted pc to a column
   named `next_pc` with role `output`.  Straight-line families get `pc + 4`,
   `jal` gets `pc + imm`, the branches get their selected target, and `jalr`
   gets `4 * (low20 + 2^20 * high8)`.
"""


def _cmd_explain(_: argparse.Namespace) -> int:
    print(ENCODING_SPEC)
    return 0


def _cmd_emit(args: argparse.Namespace) -> int:
    query = smtlib.emit_uniqueness_query(
        ir.load(args.model),
        refine=not args.no_refine,
        assume_domains=args.assume_declared_domains,
        derived=not args.no_derived_facts,
        shard=smtlib.Shard(args.output_column or "", args.opcode or ""),
    )
    if args.output:
        Path(args.output).write_text(query.text, encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        sys.stdout.write(query.text)
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    system = ir.load(args.model)
    node_degrees = analysis.degrees(system)
    worst = max((node_degrees[c] for c in system.constraints), default=0)
    print(
        f"columns={len(system.columns)} nodes={len(system.nodes)} "
        f"constraints={len(system.constraints)} max_degree={worst}"
    )
    state = "assumed" if args.assume_declared_domains else "declared, NOT assumed"
    for name, domain in sorted(system.declared_domains().items()):
        print(
            f"input domain ({state}): {name} in [{domain.lo}, {domain.hi}] "
            f"step {domain.stride} -- {domain.why}"
        )
    result = solve.check(
        system,
        timeout_ms=args.timeout_ms,
        refine=not args.no_refine,
        assume_domains=args.assume_declared_domains,
        derived=not args.no_derived_facts,
        shard=smtlib.Shard(args.output_column or "", args.opcode or ""),
    )
    print(solve.format_result(result))
    if args.counterexample_json and result.status == "sat":
        # A counterexample is a concrete malicious witness pair. Exporting it
        # is what lets the solver seed the mutation corpus instead of only
        # reporting.
        Path(args.counterexample_json).write_text(
            json.dumps(solve.counterexample_payload(system, result), indent=2)
            + "\n",
            encoding="utf-8",
        )
        print(f"wrote counterexample to {args.counterexample_json}")
    return 0 if result.unique else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    explain = sub.add_parser("explain", help="print the encoding spec")
    explain.set_defaults(func=_cmd_explain)

    domains_help = (
        "assume the declared input domains. Off by default: they are "
        "assumptions, and the query without them proves more while assuming "
        "less. Turn them on to triage a sat at an unreachable input"
    )

    derived_help = (
        "drop the rewrites derived from the constraints -- node "
        "renormalisation and shared determined columns. Slower, and the "
        "control arm for whether they deleted a counterexample"
    )
    shard_help = (
        "ask about one architectural output / under one opcode instead of the "
        "whole family. Both are complete case splits; see `explain`"
    )

    def add_shared(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("model")
        parser.add_argument("--no-refine", action="store_true")
        parser.add_argument(
            "--no-derived-facts", action="store_true", help=derived_help
        )
        parser.add_argument("--output-column", help=shard_help)
        parser.add_argument("--opcode", help=shard_help)
        parser.add_argument(
            "--assume-declared-domains", action="store_true", help=domains_help
        )

    emit = sub.add_parser("emit", help="emit the SMT-LIB2 query")
    add_shared(emit)
    emit.add_argument("-o", "--output")
    emit.set_defaults(func=_cmd_emit)

    check = sub.add_parser("check", help="run the query through z3")
    add_shared(check)
    check.add_argument("--timeout-ms", type=int, default=0)
    check.add_argument(
        "--counterexample-json",
        help="on sat, write the witness pair here for the mutation corpus",
    )
    check.set_defaults(func=_cmd_check)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
