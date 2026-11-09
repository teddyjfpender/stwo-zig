# Experimental OM31-by-M31 dot accumulator

This isolated prototype targets the DEEP numerator `sum(weight * queried_base_value)`. No live DEEP emitter, Context hook, source roster, receiver, protocol or R6 default uses it. It has no physical STARK qualification yet.

The row has 17 MAIN, 10 FIXED and 24 OM31 interaction base columns. Eight weight coordinates, one base scalar and eight inclusive sums are committed. Source-owned fixed columns hold three input IDs, two last-output IDs, their independently supplied whole-graph use counts, enabled/first/last selectors. Every call resets on its first row and exposes the last inclusive sum as two complete QM31 Var tuples. A zero-length call has one explicit zero-input row and two fresh zero outputs. Scalar membership is `(GateTag, id, scalar, 0, 0, 0)`; higher coordinates cannot be silently ignored.

Eight recurrence equations and three paired-LogUp equations have degree at most three. Five actual Var fractions pair with one zero-weight dummy into three OM31 accumulators. Source compilation rejects out-of-range/aliased/reused outputs, cyclic references and characteristic-bound violations; it hashes the complete independently compiled fixed topology. The caller must still establish the *whole circuit* producer/consumer census, including exactly one producer per new output. Local compilation is not a substitute for that production admission gate.

ReleaseSafe tests cover inclusive sums, independent call resets, explicit empty-call behavior, all eight mutated accumulator outputs, malformed/nonbase scalar values, changed output values, source/fanout identity, cyclic/duplicate producer controls, exact complete-Var multisets, hidden scalar coordinates, cyclic paired-prefix witness closure, interaction mutations and finite-difference degree-three checks. The source-fed cost test takes the current OM31-field P2 widths (QM31 arithmetic 12 MAIN / 8 FIXED / 16 INTER), rather than the legacy QM31-field frontend's interaction width.

## What the source counter actually found

A temporary observational counter wrapped only the numerator loop of the existing witness-free source-class model. It was removed afterward. Both native source identities, complete raw censuses and every phase counter exactly match the frozen control. No heavy guest execution, native proof or recursive proof was performed.

| Source class | Dot terms | Dots over 72 queries | Actual QM31 rows in numerator | Remaining QM31 rows | New dot log |
|---|---:|---:|---:|---:|---:|
| 3, widest retained opening class | 566,208 | 2,520 | 2,259,648 | 2,549,964 | 20 |
| 20, representative Miller-heavy class | 527,184 | 1,944 | 2,104,704 | 2,450,138 | 20 |

The naive 6,881-samples × 72 estimate missed the periodicity entry inserted for every two-mask column by `SamplePlan.init`. Source class 3 has 7,864 actual terms per query; class 20 has 7,322. Both therefore need **log 20**, not log 19. The exact generic row count also includes structural zero/add elisions: class 3 emits 1,132,344 multiplications and 1,127,304 additions, while class 20 emits 1,054,296 and 1,050,408. Neither loop emits native full OM31 products.

Under the isolated replacement model, generic arithmetic falls from log 23 to 22. Adding the log-20 dot component changes total native cells from 415,756,288 to 318,238,720: 97,517,568 fewer cells, or 23.46%. MAIN+INTER saves 74,448,896 cells. This is a geometry projection, not a measured prover speedup, and final graph fanout/finalization changes require an integrated source census.

The added chip contributes 57 nonfixed OODS samples: 17 current MAIN plus eight previous accumulators, and 24 current interaction plus eight previous-prefix coordinates. It also adds ten fixed columns. Thus it does not make the opening vector narrower on its own. The prospective maximum commitment log drops 23→22 for these two classes; whether that wins after lifting, hashing and recursion must be measured.

## Remaining gates

- Explicit Context/source-multiplicity hook with no generic QM31 duplicate rows, complete producer coverage and independently derived source keys.
- Component domain/OODS adapter with correctly scaled previous-row masks on mixed-height/lifted domains; never copy a component's index shifts blindly.
- Physical proof + fresh source receiver and adversarial Var/global-claim controls, including zero dots and nonbase scalar attempts.
- Actual source-class graph/cell/opening census, then a short representative physical benchmark. No heavy complete proof is authorized by this prototype.
- Source-bound/security-ledger accounting for the new relation family, including characteristic masses and complete lookup scope.
- A named protocol/receiver/recursive-source authority change before any production admission. Current R5/R6 defaults stay unchanged.

Run `zig build test-riscv64-op-pure-p2 -Doptimize=ReleaseSafe -j1 -Driscv-test-filter='OP native dot isolated'`. Set `STWO_OP_DOT_COST_OUTPUT` to persist the source-fed cost JSON.
