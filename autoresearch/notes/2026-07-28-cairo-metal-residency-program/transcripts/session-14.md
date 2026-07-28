# Session 14 — increment 3.13, the gate

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.

## What I expected to do, and what was actually there

The brief had four pieces of work: admit the delivered metallib, fold in the
3.11-mandated batching fix, build a mixed-coverage path for the stragglers, and
measure the gate. **Two of the four were already done when I got there**, and
finding that out was most of the first half hour.

**The batching fix.** The brief said a prior agent had started and reverted it.
It had not been reverted — it was sitting in the working tree uncommitted (34
insertions), which is why `git status` disagreed with the brief's "local head
d385ffd9 clean". Then, while I was editing the manifest, the 3.12 agent committed
it as `f5c0a66c` and my HEAD moved underneath me mid-task. I verified the commit
existed as an object and was on my branch before believing the orchestrator's
note about it. Reviewing the diff rather than rewriting it was the right call:
`prepareEvalBatch`/`evalBatchPrepared` already existed
(`prepared_execution.zig:554-573` → `dynamic_evaluation.m:607-633`), and the ObjC
is exactly one `MTLCommandBuffer`, N compute encoders in encode order, one
`commit`, one `waitUntilCompleted`. Encode order is what makes the cross-part
accumulation into the coordinate planes safe, so the change is sound.

The line reference in my brief (`composition_stage.zig:430-434`) was stale — at
the delivered head those lines are the `ext_params` loop. The per-plan submission
loop it described was at 449-456 and is what f5c0a66c replaced.

**Mixed coverage.** The brief asked me to implement it "if not already
supported". I re-read 3.8 §3 as instructed and its policy table already had the
row: kernel resolution failing for *some* components evaluates those on the host
inside the stage as declared coverage. Then I checked the code rather than the
prose, because prose can describe intent: `device_stage.zig:155-167` walks
`session.accepts`, and a false entry goes to
`evaluateConstraintQuotientsOnDomainParallel` against the *same*
`DomainAccumulator` in the *same* component order, incrementing `host_components`
and not `device_fallbacks`. That ordering is the whole reason mixing is
byte-exact and not just plausible. So the answer was: nothing to build, and the
right contribution is to prove it works and correct the brief.

It works. arithmetic-2m opened 28/29 and memory-7m 31/32, both byte-exact, both
`cpu_fallbacks = 0`, both `accelerated_without_fallbacks`. Without that
pre-existing mechanism neither gate row would have been measurable at all, which
is exactly what the brief warned.

## The cold cliff

First armed all-opcodes run: I gave it a 120s timeout and it blew through it. It
finished at **prove = 183,001 ms, of which `composition_device_admission` =
181,740 ms**. Metal pipeline creation for the whole 5.9 MB library, from source,
with no binary archive.

I went looking for whether that was fatal or amortised and found
`archive_store.m` — an on-disk `MTLBinaryArchive` store under `NSCachesDirectory`.
Second run: admission **12.08 ms**, prove 1035.3 ms, same digest. So it is a
one-time cost per library per machine, and the untimed warmups in the gate
protocol absorb it. Worth recording as a deployment fact though: a cold CI runner
pays three minutes on its first armed proof.

This also explains why arithmetic-2m and memory-7m showed warm admission
(10-12 ms) on their *first* armed run — the archive serialises the whole library,
not just the pipelines that were asked for.

## The measurement mistake I made, and how I caught it

I ran the gate harness with `nohup … &` and waited on it with
`until ! pgrep -f "python3 gate.py"`. **That pattern never matches.** The process
shows up as `…/Python.app/Contents/MacOS/Python gate2.py`, so argv[0] is the
framework path and "python3" appears nowhere. My wait loop returned immediately
and reported "GATE DONE" while the harness was still running.

I then launched a second harness. Two gates ran concurrently against the same
GPU. I did not notice from the logs — I noticed from the *data*: the summary said
all-opcodes had 12 pred and 12 cand samples over 3 blocks, when 3 blocks is 12
samples total. Counting `(workload, block, slot)` showed every slot exactly twice.
The arm spreads were 1.30x/1.49x with outliers at 1795 ms and 210 ms, against
1.03-1.15x once clean.

I also could not rule out that the *first* gate.py was still alive during the
arithmetic-2m re-run, for the same pgrep reason. So I threw away all of it —
including the memory-7m set, whose spreads looked fine — quarantined it to
`contaminated_*`, confirmed the host idle at loadavg 2.04, and re-ran all three
workloads as one sequential job waited on by `kill -0 $PID`. The reported gate is
that single run and nothing else.

The lesson is narrow and worth keeping: **never pattern-match a process by its
interpreter name.** Wait on the PID.

Separately, the load average was 16-17 when I started, which is why the very
first spot check reads 1885 ms for a workload that measures 1369 ms clean. That
was the concurrent 3.12 agent's builds. It drained to ~2 before the gate.

## Raw gate numbers

Same binaries at `3cea1e66`, arms differ only by `STWO_ZIG_COMPOSITION_DEVICE`.
`STWO_CAIRO_PREPROCESSED_CACHE=0` both arms. 1 untimed warmup per arm per
workload. A-B-B-A × 3 blocks.

### arithmetic-2m — loadavg(1m) 2.09-2.16

```
        prove_ms  comp_eval  admission   lift    gpu   sha              disp sub  acc
A1 pred  1704.7    370.51      0.01       -      -    25e5719f4c578eb7  74   -    -
B1 cand  1601.6    247.48     11.23     73.594 63.215 25e5719f4c578eb7 102   28  28/29
B2 cand  1608.2    237.96     11.49     73.437 54.067 25e5719f4c578eb7 102   28  28/29
A2 pred  1702.7    371.57      0.01       -      -    25e5719f4c578eb7  74   -    -
A1 pred  1755.1    376.56      0.01       -      -    25e5719f4c578eb7  74   -    -
B1 cand  1662.1    243.85     11.41     73.989 54.321 25e5719f4c578eb7 102   28  28/29
B2 cand  1660.4    243.67     11.76     73.776 54.413 25e5719f4c578eb7 102   28  28/29
A2 pred  1855.2    418.72      0.01       -      -    25e5719f4c578eb7  74   -    -
A1 pred  1822.0    401.07      0.01       -      -    25e5719f4c578eb7  74   -    -
B1 cand  1635.8    242.28     11.75     74.109 54.228 25e5719f4c578eb7 102   28  28/29
B2 cand  1682.2    251.31     11.47     71.720 63.480 25e5719f4c578eb7 102   28  28/29
A2 pred  1824.1    416.40      0.01       -      -    25e5719f4c578eb7  74   -    -
```

stage 392.47 → 244.43 = **1.606x** [1.520, 1.696]; prove 1777.30 → 1641.74 =
1.083x [1.042, 1.125].

### memory-7m — loadavg(1m) 4.08-8.88

```
A1 pred  4372.3   1219.43      0.01        -       -    e3317e55a5db5a42  79   -    -
B1 cand  3815.9    596.14     11.68    157.911 145.212 e3317e55a5db5a42 110   31  31/32
B2 cand  3837.3    611.76     11.82    156.936 155.222 e3317e55a5db5a42 110   31  31/32
A2 pred  4454.2   1254.13      0.01        -       -    e3317e55a5db5a42  79   -    -
A1 pred  4469.1   1257.09      0.01        -       -    e3317e55a5db5a42  79   -    -
B1 cand  3807.2    609.47     11.95    158.992 154.729 e3317e55a5db5a42 110   31  31/32
B2 cand  3836.6    593.43     11.63    158.843 144.552 e3317e55a5db5a42 110   31  31/32
A2 pred  4501.5   1271.59      0.01        -       -    e3317e55a5db5a42  79   -    -
A1 pred  4507.6   1286.47      0.01        -       -    e3317e55a5db5a42  79   -    -
B1 cand  3813.8    597.50     11.86    158.876 153.572 e3317e55a5db5a42 110   31  31/32
B2 cand  3828.3    576.76     11.96    156.339 145.464 e3317e55a5db5a42 110   31  31/32
A2 pred  4533.0   1287.44      0.01        -       -    e3317e55a5db5a42  79   -    -
```

stage 1262.69 → 597.51 = **2.113x** [2.058, 2.170]; prove 4472.94 → 3823.19 =
1.170x [1.156, 1.184].

### all-opcodes — loadavg(1m) 6.67-7.98

```
A1 pred  1334.6    327.75      0.01       -      -    79ae76e1ac0c48b1  75   -     -
B1 cand  1155.4    147.46     15.49    37.595 29.422 79ae76e1ac0c48b1 121   46  46/46
B2 cand  1161.4    148.95     15.27    37.588 29.469 79ae76e1ac0c48b1 121   46  46/46
A2 pred  1386.5    363.14      0.01       -      -    79ae76e1ac0c48b1  75   -     -
A1 pred  1361.6    338.00      0.01       -      -    79ae76e1ac0c48b1  75   -     -
B1 cand  1163.5    148.22     14.46    37.111 29.588 79ae76e1ac0c48b1 121   46  46/46
B2 cand  1179.5    150.69     15.78    37.299 29.554 79ae76e1ac0c48b1 121   46  46/46
A2 pred  1394.1    378.16      0.01       -      -    79ae76e1ac0c48b1  75   -     -
A1 pred  1346.3    337.69      0.01       -      -    79ae76e1ac0c48b1  75   -     -
B1 cand  1159.4    148.73     15.23    37.024 29.421 79ae76e1ac0c48b1 121   46  46/46
B2 cand  1169.5    145.65     15.41    37.285 29.201 79ae76e1ac0c48b1 121   46  46/46
A2 pred  1388.5    364.20      0.01       -      -    79ae76e1ac0c48b1  75   -     -
```

stage 351.49 → 148.28 = **2.370x** [2.250, 2.497]; prove 1368.59 → 1164.78 =
1.175x [1.154, 1.196].

CIs are ratio-of-means with a delta-method interval on the log ratio, df = 10,
t = 2.228 — the same construction 3.8 §5 used.

## Diagnosing the arithmetic-2m miss

1.606x against a projected 4.60x is a big miss and the brief said to treat that
as a bug. I do not think it is one, and here is the reasoning that got me there.

First I checked the things that would indicate a bug: the digest is exact on all
six candidate samples, arm spreads are 1.06-1.13x, and `cpu_fallbacks` is 0. So
the stage is doing the right work and the measurement is stable.

Then I decomposed the stage from the numbers I already had — lift and device GPU
are logged per proof, admission is a profiler span:

```
arithmetic-2m  244.43 = lift 73.44 (30.0%) + gpu 57.29 (23.4%) + residual 113.70 (46.5%)
memory-7m      597.51 = lift 157.98 (26.4%) + gpu 149.79 (25.1%) + residual 289.74 (48.5%)
all-opcodes    148.28 = lift 37.32 (25.2%) + gpu 29.44 (19.9%) + residual 81.52 (55.0%)
```

The kernels are *faster* than 3.7 projected (57.29 vs 76.0 ms). Kernels alone
would give 392.47/57.29 = 6.85x. So the GPU is not the problem; 76.6% of the
device stage is host-side bridge.

Going back to 3.7 §4 found three compounding errors, and the sizes matter:

- the lift was priced at 89.84 GB/s from a standalone single-threaded loop; it
  measures **21.9-30.8 GB/s** in situ. 18.8 ms projected, 73.44 ms measured.
- the residual — memsets, readback accumulate, the host straggler — was not
  modelled at all, and it is the largest term.
- the host baseline was the single-threaded `simd_evaluator` (435.7 ms) while the
  shipped path is the parallel one (392.47 ms measured). The "at 8 threads" line
  parallelised the lift but not the baseline it divided by.

The same three shares explain all three workloads, which is what convinced me
this is cost structure and not a defect.

I could not split the residual further: `composition_evaluation` has no
per-component children in the stage profile, so the straggler's host cost and the
readback cost are not separable at this head. I decided against adding spans and
re-running — that is a rebuild plus a full gate re-measurement, and the structural
conclusion does not depend on the split. It is item 1 of the recommended order
instead.

## The number the gate did not ask for

The gate is a stage-level proxy. Folding the measured prove-level savings into
3.11 §6's bar arithmetic gives geomean **1.982x against the 1.768x bar** — cleared
by 12.1%, from 5.3% short. Composition residency is worth ~6x what epoch fusion
was worth. pedersen-aggregator is carried unchanged (not measured here), so it is
a lower bound.

I want to be explicit that this is the same arithmetic 3.11 set up, with one
column substituted by measurement, not a new framing invented to rescue a missed
gate. And I am reporting the missed gate as missed.

## 3.12's claim, withdrawn

`dispatches == submissions` on every workload: 46/46, 28/28, 31/31. Every
accepted component has exactly one part, because 3.10's emitter fuses each
component into a single program. So the per-plan loop f5c0a66c replaced never
made more than one submission per component, and **the batching fix is worth
0 ms today** on the entire portfolio. 3.11's "+12.7 ms on all-opcodes" and 3.12's
"75 → ~14 submissions" both assumed multi-part components. The change is still
correct and still costs nothing; it is insurance, not a win. Recording this
because a future increment will otherwise re-derive the 12.7 ms and wonder where
it went.

## SN2

The brief left keeping-or-dropping to me. I initially kept it and wrote a
justification (it preserved three fail-closed regressions pointed at a
checked-in artifact). The orchestrator then directed removal, and on reflection
removal is better than my first answer: the regressions do not need *that* blob,
they need *a* blob, and repointing them at the eval-domain library means they
now guard the artifact the product actually opens rather than one it never will.
Dropping the entry also removes a second accepted digest for the one env var that
chooses which file the prover loads.

I added the inverse regression — that the SN2 blob is now refused — and confirmed
it end to end: the override declines with `UnapprovedCompositionMetallib`, the
proof returns to the host path at 75 dispatches, and it still reports
`79ae76e1ac0c48b1` with `cpu_fallbacks = 0`. That last part is 3.8 §3's rule
working through the manifest.

## What I could not verify

`test-cairo-metal-product` does not run on this host. It depends on
`metal-core-aot-acceptance`, which mints the core AOT bundle with `metal`/
`metallib`; this box has CommandLineTools only. Passing the prebuilt bundle via
`-Dmetal-core-aot-bundle` does not skip the mint step — I tried, and it spent ten
minutes and failed the same way. So **the five unit tests I added are
type-checked but never executed.** That is the one real gap and it needs CI.

`metal-test` reproduces 3.12's exact profile — 75/79, 2 skipped, 2 failed at
`resident_data_test` and `proof_residency_test` — which is the attribution
argument that my changes added no failure.
