# Session 05 — Cairo AIR composition evaluation (R6)

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Worktree `/private/tmp/stwo-zig-cairo-native-throughput-10x`, branch
`autoresearch/cairo-native-throughput-10x`, head `a52c450c` (clean).

## What I was looking for and why

`composition_evaluation` was the largest unaudited CPU bucket — 392.6 ms of a
2,262 ms arithmetic-2m prove in the first instrumented profile of this
session, the single biggest stage, ahead of `main_trace_commit` (409.2 ms was
measured in the same profile, so they trade places run to run) and well ahead
of `fri_quotient_build_and_commit` (250.1 ms). Increments 1 and 3-5 had
closed the quotient and Merkle paths; this was the last large untouched one.

The prior in the brief was three-way: memory-bound on mask reads,
compute-bound on constraint arithmetic, or dispatch-bound in the template
interpreter. I did not want to guess, and the campaign's history is that
guessing here is expensive — increment 3's fused Merkle kernel and this
increment's own first candidate both looked obviously right and both measured
as nothing.

## Finding the path

`prove.zig:271` records the stage around
`computeCompositionEvaluationForBackend`
(`component_prover.zig:307`). With more than one component and a pool it goes
to `component_parallel.compute` (`component_parallel.zig:15`). Each Cairo
component's `evaluateConstraintQuotientsOnDomainImpl`
(`frontends/cairo/proving/air/component.zig:134`) splits rows across the pool
and calls `simd.evaluatePartRange`, a 300-line four-lane interpreter over the
captured instruction stream (`simd_evaluator.zig`).

Reading the interpreter, one thing jumped out before any measurement. The
`trace_col` arm calls `input.trace.read(...)` — a function pointer — once per
read instruction per four-row group. `readTrace` (`component.zig:295` at
head) then, on every one of those calls:

- checks `context.trace.polys.items.len < 3`,
- for interaction 1/2 calls `geometry.componentSpan`, which **linearly scans
  the component's `trace_spans`** looking for the matching tree,
- does an overflow-checked add and two bounds checks,
- and then, per lane, calls `offsetBitReversedCircleDomainIndex` and
  `Poly.valueAtLiftingPosition`, the latter of which calls `validate()`
  (recomputing `1 << log_size` and comparing it to `values.len`), rechecks
  `log_size > lifting_log_size`, recomputes the shift, and bounds-checks the
  derived index.

None of that depends on the row except the offset derivation. And the offset
derivation depends on `(row, offset)` — **not on the column**.

That is increment 2's shape exactly: per-element layout dispatch that can be
resolved once. But increment 2's lesson is also that the obvious shape is not
always the one that pays, so I measured first.

## Audit instrumentation

Committed at `bb0de1e5`, reverted at `cc4aa924`. Three probes, all env-gated:

1. **Static census** (`STWO_COMPOSITION_AUDIT=1`) — one line per component
   with the exact instruction mix, read-site count, distinct mask offsets and
   register-file widths.
2. **Component wall-span probe** — start/end nanos per component against a
   process epoch. I needed this because ablated runs produce wrong
   composition values and abort at `constraint_check_and_assembly` with
   `error: ConstraintsNotSatisfied` before the CLI writes its stage profile.
   The span `max(end) - min(start)` recovers the stage anyway.
3. **Comptime-selected ablations** (`STWO_COMPOSITION_ABLATE=<mode>`) —
   `no_index`, `no_read`, `no_output`, `no_denominator`, each dispatched once
   per range via `switch (audit.ablation()) { inline else => |mode| ... }` so
   the row loop carries no runtime branch. Each ablation is DCE-safe:
   `no_read` returns `(instruction.a +% @truncate(row)) | 1` so downstream
   arithmetic survives, and `no_output` folds into a sink handed to
   `doNotOptimizeAway`.

Two process notes worth recording. First, my first census emitted through a
buffered `File.stderr().writer()` under a mutex and still produced interleaved
partial lines (`ps=13107200` as a line start). Switching to `bufPrint` +
a single `writeAll` under the mutex fixed it. Second, the CLI refuses to
overwrite existing `--proof` / `--report-out` / `--stage-profile-out` paths
(`error: OutputAlreadyExists`), which silently made my first paired probe
print four identical numbers. Every measurement script since deletes the
outputs before each run.

## Census result

29 components on arithmetic-2m. One dominates: eval log 22 (1,048,576 four-row
groups), 278 base + 493 ext instructions, 63 read sites, 32 roots. It is 56.5%
of all mask reads and 71% of all QM31 multiplies. Top five components are
84.4% of all reads.

Whole-proof dynamic executions: base 372,681,744, ext 720,999,992, root folds
41,717,720. Mask reads 116,856,192, i.e. **467,424,768 per-lane index
derivations and column revalidations**.

`distinct_imms` came back as **2** for every single component. Against 63-69
read sites per group. That is the redundancy the whole fix rests on.

The census also showed 143,504,416 `ext param` + 37,164,024 `ext constant` +
41,717,720 root-coefficient splats = **222,386,160 loop-invariant
`PackedQm31.splat` calls**, plus 85,364,920 loop-invariant base `constant`
splats. I expected that to be the big one. It was not — see below.

## Ablation attribution

Paired A-B-B-A, one untimed warmup per pair, two blocks per ablation.
Raw per-sample span values in ms:

```
no_index        block1  none 350.761  no_index 328.988  no_index 343.972  none 365.658
no_index        block2  none 358.725  no_index 355.881  no_index 345.679  none 365.815
no_read         block1  none 361.835  no_read  290.803  no_read  293.102  none 391.552
no_read         block2  none 437.607  no_read  320.559  no_read  320.594  none 413.209
no_output       block1  none 413.017  no_output 424.533 no_output 397.636 none 437.272
no_output       block2  none 402.334  no_output 397.004 no_output 391.595 none 372.026
no_denominator  block1  none 361.362  no_den   365.774  no_den   385.871  none 377.987
no_denominator  block2  none 365.543  no_den   370.178  no_den   377.437  none 361.783
```

Means and buckets:

| Ablation | none | ablated | bucket |
| --- | ---: | ---: | ---: |
| `no_read` | 401.05 | 306.28 | 94.78 ms |
| `no_index` | 360.25 | 343.66 | 16.59 ms |
| `no_output` | 406.16 | 402.68 | 3.48 ms |
| `no_denominator` | 366.68 | 374.83 | -8.15 ms |

An earlier unpaired sweep (one round-robin per round, three rounds) gave the
same ordering but a visible within-round drift — `none` always first and
lowest, `no_denominator` always last and highest — which is exactly the
artefact A-B-B-A exists to remove. Reported here only as the reason the
paired form was rerun.

Reading: the mask gather plus its dispatch is 23.6% of the stage; the
accumulation scatter and the domain bookkeeping are free; roughly 75% is
interpreted arithmetic and interpreter overhead.

## First candidate: hoist the row-invariant instructions. Rejected.

`program_plan.zig` partitions each program once per range into a row-invariant
prefix and the row-varying remainder, and pre-splats the constraint
coefficients. Admission is `op == .constant`/`.param` **and** the destination
register is written exactly once in the whole stream — I did not want to rely
on the programs happening to be in SSA form (they are: `max_ext_regs` equals
`ext_insts.len` on every component I looked at), so the plan computes write
counts and hoists only provably safe instructions. A unit test covers the
twice-written-constant case that must stay in the loop.

It removes 24.3% of interpreted instruction executions and 222 M splats.
arithmetic-2m reproduced `25e5719f…` on the first try.

Paired probe, three A-B-B-A blocks:

```
pred 386.247  cand 382.691  cand 392.417  pred 563.669
pred 437.353  cand 427.766  cand 413.120  pred 420.826
pred 421.154  cand 423.178  cand 429.123  pred 419.211
```

Excluding the 563.7 outlier: pred 416.96, cand 411.40 — **1.01x**. Noise.

This is the most informative thing the increment produced. Removing a quarter
of the interpreted instructions changed nothing, so the loop is not
instruction-throughput-bound on cheap instructions. At ~22 cycles per
interpreted instruction (1.09 G executions, ~380 ms, 18 workers, ~3.5 GHz),
the cost is not the four-lane NEON op — it is everything around it. That
redirected me to the one instruction class that carries genuinely heavy
per-execution work: the read.

Preserved at `f1c881d6`, reverted at `cde11728`.

## Second candidate: resolve the mask reads once per range. Accepted.

`read_plan.build` walks the stream once per evaluated range and produces
`sites` (one entry per read instruction, in stream order, holding the resolved
column slice and lifting shift) and `offsets` (the distinct immediates, with a
slot index per site). `TraceReader.read` becomes `TraceReader.resolve`;
`component.resolveTrace` does the tree lookup, the `componentSpan` scan and
the shape validation once and returns `{ values, shift_amt }`.

The row loop maps lane positions once per distinct offset per group, then each
site is a straight gather:
`values[lane] = column.values[((position >> shift_amt) << 1) + (position & 1)]`.

I deliberately kept the sites in **stream order** and consumed them with a
cursor rather than hoisting all reads to the front of the group body. Moving
them would have been safe under the same unique-dst argument, but it would
have been a second, unmeasured change riding along, and I already had one
rejected candidate teaching me not to bundle.

arithmetic-2m: `25e5719f…` on the first run. Stage 345.3 ms against ~380-420
for the predecessor in adjacent runs.

Counts: 116,856,192 indirect resolve-and-read calls become 8,082 resolutions;
467,424,768 per-lane index derivations become 22,311,168.

## Mechanism confirmation

I chose a paired phase split over an S1 isolate. Increment 3 established that
S1 single-thread isolation misreads pass-fusion in a traffic-bound pipeline,
and while this change is mostly dispatch removal (which S1 reads correctly),
its residue is a real gather, so a whole-prover phase split is the honest
instrument.

I reapplied the `no_read` ablation to the candidate sources — adapting it to
the new interface — and compared its bucket against the predecessor's,
already measured in this session with the same instrument:

```
candidate, no_read block1  none 287.180  no_read 279.826  no_read 281.271  none 314.993
candidate, no_read block2  none 307.564  no_read 290.529  no_read 287.978  none 312.474
```

| Arm | none | no_read | bucket |
| --- | ---: | ---: | ---: |
| predecessor | 401.05 | 306.28 | 94.78 |
| candidate | 305.55 | 284.90 | 20.65 |

The read bucket is **4.59x smaller**. The `none` levels are not comparable
across sessions (different host load) and I am not comparing them; the bucket
is a within-block paired difference on each side. The 74.1 ms the bucket loses
exceeds the 45.2 ms the whole stage gains, which is what I would expect: the
candidate still performs the column traffic, and `no_read` on the candidate
still computes the per-offset position vectors.

## Paired measurement

Uninstrumented binaries both sides. Predecessor is the pristine `zig-out` tree
from `a52c450c` copied whole before any edit (the whole tree, because
`execution_adapter.zig:116` resolves the VM adapter beside the executable and
`profile.zig:140` resolves params at `<exe_dir>/../share/…`). One untimed
warmup per arm before each workload. `--verify` on every run. Nothing
discarded.

```
arith block1 pred 383.518 2260.451   cand 352.395 2249.096   cand 351.817 2230.907   pred 384.565 2266.368
arith block2 pred 389.986 2296.626   cand 367.228 2430.938   cand 372.400 2470.008   pred 416.647 2510.579
arith block3 pred 429.186 2542.370   cand 383.330 2514.790   cand 376.494 2518.204   pred 471.120 2842.032
mem   block1 pred 1292.193 6067.920  cand 1215.274 6091.940  cand 1187.386 6034.513  pred 1355.866 6295.072
mem   block2 pred 1424.966 6357.980  cand 1264.187 6189.684  cand 1263.775 6302.525  pred 1417.616 6419.825
allop block1 pred 357.933 1459.879   cand 318.744 1429.537   cand 311.793 1428.659   pred 360.600 1466.916
allop block2 pred 356.468 1486.636   cand 322.811 1436.662   cand 318.802 1457.047   pred 363.773 1500.378
allop block3 pred 363.166 1483.265   cand 324.862 1467.735   cand 322.644 1442.145   pred 367.402 1504.295
```
(first number of each pair is `composition_evaluation` ms, second is prove ms;
every sample's proof digest was checked and matched the campaign digest)

| Workload | stage pred | stage cand | ratio | prove pred | prove cand | ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| arithmetic-2m | 412.504 | 367.277 | 1.1231x | 2,453.071 | 2,402.324 | 1.0211x |
| memory-7m | 1,372.660 | 1,232.655 | 1.1136x | 6,285.199 | 6,154.666 | 1.0212x |
| all-opcodes | 361.557 | 319.943 | 1.1301x | 1,483.562 | 1,443.631 | 1.0277x |

Stage ranges are disjoint on all three (arithmetic-2m only just: pred min
383.518 against cand max 383.330). Per-block ratios: arith
1.0907/1.0906/1.1849, memory 1.1021/1.1245, all-opcodes
1.1396/1.1225/1.1283. Eight of eight blocks favour the candidate.

all-opcodes is the block set I trust most — sd 3.7 ms predecessor, 4.3 ms
candidate, blocks agreeing within 1.7% — and it is also the highest ratio.
That the smallest workload shows the largest stage gain is consistent with the
mechanism: the removed cost is per read *call*, not per byte, so it does not
shrink when the columns get smaller.

Host load rose from 3.0 to 13.6 across the session and absolute prove times
drift ~15% upward with it, which is why per-block ratios are reported next to
the pooled means. Prove-level per-sample ranges overlap; I claim prove
1.021x-1.028x only on the paired per-block structure and say so in the note.

## What I did not do

- No S1 harness. Budget went to the paired phase split, which I judged the
  better instrument here for the reason above.
- No third memory-7m block. Two blocks, four samples per arm, disjoint ranges.
- No strip-mining of the interpreter (the loop interchange that would amortise
  opcode dispatch over a tile of row groups). It is the natural next target
  given the ~22 cycles-per-instruction finding, but the dominant component's
  extension register file crosses this host's L1D at T=4, so it needs its own
  T sweep and is not a drop-in.

## Commits

- `bb0de1e5` audit instrumentation (reverted at `cc4aa924`)
- `f1c881d6` row-invariant hoist, byte-exact, measured 1.01x (reverted at
  `cde11728`, preserved for the record)
- `9ea1e4bc` the accepted change: resolve mask reads once per range
