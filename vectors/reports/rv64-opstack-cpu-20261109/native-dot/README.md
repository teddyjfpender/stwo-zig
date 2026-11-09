# Experimental OM31-by-M31 dot accumulator

This isolated prototype targets the DEEP numerator `sum(weight * queried_base_value)`. No live DEEP emitter, Context hook, source roster, receiver, protocol or R6 default uses it. Its standalone physical STARK gate is now qualified; it remains outside every live R5/R6 roster and is not R7 admission.

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

## Standalone physical qualification

The source-pinned dot/Var-debt gate produces a 38,956-byte proof with dot log 4 and a separate nonconstant auxiliary chip at log 6. A fresh independently constructed source key and typed external statement accept it after the producer key is destroyed. The mixed-height adapter exercises eight previous-MAIN accumulator masks and eight previous-prefix coordinate masks; explicit mask counts are 25 MAIN and 32 INTER samples. Each component evaluates on 2n, with degree at most three. The complete allocation/proving/reception/mutation fixture runs under a 2 GiB hard numerical budget, peaks at 423,029 requested bytes, and retires all heap/external ownership. This is not RSS or a performance benchmark.

External Var debt is computed by the receiver from source-fixed input/output IDs, independently derived fanouts and canonical caller-pinned full QM31 values. The witness's MAIN is never its own authority. Internal Var IDs cancel through that same relation. Missing/duplicate bindings fail source admission. Both request and immutable identity enter the transcript, but request values do not change immutable setup identity; replay under a changed statement is rejected.

A locally consistent wrong-input witness and a hidden high-coordinate scalar statement each produce STARK fragments that a test-only checker validates **with debt explicitly pending**. The complete receiver rejects both against its independently pinned debt. The pending checker is unavailable in production builds. An altered empty-dot output with zero fanout preserves Var debt but fails the arithmetic constraints, proving that lookup closure alone is insufficient. Mutated accumulator, prefix and auxiliary-column witnesses likewise fail `ConstraintsNotSatisfied`. Truncation, reordered calls, wrong source identity, noncanonical claims and statement replay are rejected.

Physical MAIN uses the same bounded row iterator as the numerical witness tests and writes directly into final column-major allocations. Raw MAIN is retired after fraction generation and raw INTER after its commitment; no wide logical-row copy is kept for proving.

Run `zig build test-riscv64-op-pure-p2 -Doptimize=ReleaseSafe -j1 -Driscv-test-filter='OP native dot'` for this family, or filter `OP native dot physical standalone` for the actual STARK gate.

## Remaining gates

- Explicit Context/source-multiplicity hook with no generic QM31 duplicate rows, complete producer coverage and independently derived source keys.
- Bind the qualified standalone component/domain/OODS authority into the explicit R7 roster with independently derived global column offsets and source geometry.
- Physical proof of the joined R7 source graph and fresh receiver, beyond the already-qualified standalone external-statement fixture.
- Actual source-class graph/cell/opening census, then a short representative physical benchmark. No heavy complete proof is authorized by this prototype.
- Source-bound/security-ledger accounting for the new relation family, including characteristic masses and complete lookup scope.
- A named protocol/receiver/recursive-source authority change before any production admission. Current R5/R6 defaults stay unchanged.

Run `zig build test-riscv64-op-pure-p2 -Doptimize=ReleaseSafe -j1 -Driscv-test-filter='OP native dot isolated'`. Set `STWO_OP_DOT_COST_OUTPUT` to persist the source-fed cost JSON.

## Live source lowering, still closed for proof admission

[live-source.json](live-source.json) records the next R7 source milestone.
An explicit thread-local scope replaces only the **whole DEEP numerator dot**.
With no scope, DEEP emits the original arithmetic. Scalars keep complete
`(id, value, 0, 0, 0)` Var tuples in the physical dot, not unrestricted QM31
multipliers. Context records every input, owns its term list, reserves exactly
two output producers, and derives usage jointly with generic, P2 and OMUL gates.
An empty dot still owns an explicit zero row and zero outputs.

R7 finalization is a separate capability. It sets `native_dot_finalized` while
leaving legacy `finalized` false; protected R5 and R6 key constructors therefore
refuse **before any allocation**. Every shared mutation/close API checks either
capability. No legacy source API can publish a finalized graph omitting dot debt.

Five focused ReleaseSafe tests qualify the actual DEEP front door against
ordinary arithmetic, numerical/trace-only source parity, unique producers,
joint fanout, legacy omission/duplicate producer attacks, hidden scalar limbs,
nested/error scope restoration, and allocation-failure custody. This does not
qualify a live R7 proof: the seven-role key, shared PCS/Var closure, transcript,
physical receiver and recursive root are separate remaining gates. The prior
heavy source model remains a model; no heavy execution/proof was rerun.

## Seven-role physical fixture

[combined-physical.json](combined-physical.json) qualifies the combined R7 PCS,
not a dot fragment. Equality, generic arithmetic, conversions, Poseidon2, U16,
native OM31 multiplication and dot share one transcript and one Var/range
closure. Six external field inputs and four results are pinned independently
by native field arithmetic. The producer key is destroyed before a fresh
source key verifies the proof. The 546,224-byte proof stays under a 2 GiB
allocator cap (155,159,239-byte observed peak; zero final live/external bytes).
Small fixture timings are qualification telemetry, not controlled benchmarks.

The R7 key hashes its own domain, every role's ordered geometry, full FIXED
root and dot source topology. Wire magic `STP27D01` carries seven claims; each
claim enters the transcript. The legacy R6 receiver rejects it before any
allocation. A different independently compiled dot source with the same fanout,
a changed FIXED root and a changed public input all fail reception. Hidden
QM31 coordinates, a forged native product, changed dot weights/scalars,
nonlast accumulator, internal reset, empty result, prefix and balanced false
claims are rejected. Omitting the seventh provider is rejected as a shape
mismatch. Full-storage and early-retirement paths produce identical bytes.

R7 MAIN collection reads canonical source FIXED IDs directly. It never flips
legacy finalization flags. The unchanged typed P2 and OMUL components are
reused only at their exact original offsets; the dot role has its own offsets,
previous-accumulator masks and native-height circle ordering. Raw MAIN and
INTER are retired after their last consumers. This constructor/collector glue
lives outside protected R5 files and outside R6 topology/root-runtime code.

Actual execution leaf factories, recursive seven-role verification and final
root admission remain separate gates. No selected guest, CPU route or root
protocol is switched by this fixture, and no heavy block was rerun.

The new dot domain evaluator already uses 16-row M31 SIMD for its eight
arithmetic roots. Only shared-Var challenge compression, prefixes and random
accumulation use packed OM31; OODS stays scalar. The scalar-domain control
produces **exactly the same full proof bytes**. A separate randomized test
compares all eleven roots across every SIMD lane, including arbitrary current
and previous accumulator values. This is not a measured large-domain speedup.

## Actual small CPU source: padding regression, no promotion

[actual-small-cpu-source.json](actual-small-cpu-source.json) uses the retained
native bundle for OP block 120,794,432. The shared `ShapeView.emitInto` now owns
the common CPU verifier emission; callers retain their Context, scopes and
finalization policy. Its returned statement handle keeps teardown at the same
point as before. The old R6 source identity and complete 689,252-byte golden
proof (`e80751cd…88c6`) remain **byte-identical** after extraction.

R7 reuses that emitter and qualifies the same public result and joint source
usage. Actual generic rows fall **3,992,911 → 2,135,023**, with **465,408** dot
rows over **1,800** calls. This leaves generic arithmetic **37,871 rows above**
the next power-of-two boundary: its padded log stays 22, and dot adds log 19.
Total native cells consequently **increase 264,302,592 → 291,041,280 (10.12%)**.
R7 is refused for this class; no actual R7 CPU leaf proof was attempted.

Declared mask counts are `[96,521,320,16] → [106,546,352,16]`; sample references
are `1001 → 1084`, including the new previous-accumulator/prefix periodicity
samples. These counts come from the actual old source geometry plus the
qualified physical dot layout, without building a wide R7 key. No block
execution/native proof was regenerated. A fresh native receiver admits the
retained complete bundle before the report is written. The 32 GiB allocator
cap records 5.79 GB peak and zero final live allocation.

Heavier source classes may cross the padding boundary and win, as the earlier
frozen source model predicts, but must be checked independently. A production
choice between R6 and R7 must be source-derived and receiver-authorized;
producer-selected geometry or a blanket switch is insufficient.
