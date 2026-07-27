# Session 01 — CPU FRI quotient fragmentation audit (R7)

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Worktree `/private/tmp/stwo-zig-cairo-native-throughput-10x`, branch
`autoresearch/cairo-native-throughput-10x`, base `ad2d3ac5` (clean).
Host: Apple M5 Max, 26 days uptime, load average 2.5–4.4 throughout with
unrelated suites running. Every timing block below is bracketed by `uptime`.

## Prior and hypothesis

Read `autoresearch/notes/2026-07-27-cairo-system-throughput/note.md`, section
"Final Metal quotient round". The Metal defect was concrete: a
`raw_bytes >= 64 MiB` predicate launched one full-domain numerator pass per
physical source run, 361 runs on arithmetic-2m, 1,291 ms of device time. The
fix applied the documented 64-run ceiling at every byte size and gathered
high-fragmentation inputs into a flat private arena — 1,350 ms to 212 ms.

The note says the CPU lane "retained the previously proven CPU flat pack" only
for small fragmented inputs. Working hypothesis: some byte-keyed predicate on
the CPU excludes large Cairo inputs from the same collapse, leaving the
601 ms / 278 ms `fri_quotient_build_and_commit` costs on memory-7m and
arithmetic-2m.

## Build and harness setup

Built the predecessor first, before touching sources:
`zig build stwo-cairo-cpu -Doptimize=ReleaseFast`, then copied the whole
`zig-out` tree to `/private/tmp/campaign-inc1-pred/zig-out`.

Copying only the two binaries failed with `error: FileNotFound`. Two
sibling-relative resources are resolved from the executable directory:
`src/products/cairo/shared/execution_adapter.zig:116` finds
`stwo-cairo-vm-adapter` next to the binary, and
`src/products/cairo/shared/profile.zig:140` resolves the default params
manifest at `<exe_dir>/../share/stwo-zig/cairo/official/all_opcodes.params.json`.
Copying the entire `zig-out` fixed both. Recording this because it will bite
every future paired-arm measurement in this campaign.

## Reading the path

`src/prover/pcs/quotients/execution.zig` is the eager path — it partitions the
domain across workers by row range, so even there each worker walks the domain
once, not once per column. But Cairo does not use it. The Cairo prover goes
through the fused lazy provider: `src/prover/pcs/scheme.zig:706` builds a
`LazyQuotientProvider` via `initForBackend`, and the commit is fused through
`commitWithLazyQuotients` (`src/prover/vcs_lifted/prover.zig:75`).

`ColumnEvaluation` (`src/prover/pcs/quotient_column_geometry.zig:19`) is a
single contiguous `[]const M31` plus a `log_size`. That is the first thing that
undercuts the hypothesis: on the CPU there is no such object as a physical
source run to gather. Fragmentation here means implicit lifting — a smaller
column repeats each even/odd source pair across `2^shift_amt` output rows,
`valueAtLiftingPosition` at line 26.

`initForBackend` picks `.bounded_cpu` whenever
`tile_executor.shouldUseBoundedInput(lifting_log_size)`, which is
`lifting_log_size >= 13` (`quotient_tile_executor.zig:27`). Cairo lifting log
sizes are 22 and 23, so `.bounded_cpu` always.

In `.bounded_cpu` (`lazy_provider.zig:219`) two plans are built:

- `buildCompactContributionPlan` with `COMPACT_GROUP_MIN_SHIFT = 2` and
  `MAX_COMPACT_GROUP_BYTES = 1 MiB` (`lazy_provider.zig:33-34`). This is the
  "CPU flat pack". It groups every lifted contribution by
  `(batch_index, value_count, shift_amt)`.
- `buildDirectContributionPlan` with the compact shifts excluded, leaving only
  full-domain columns.

`MAX_COMPACT_GROUP_BYTES` was the prime suspect: a 1 MiB byte budget looked
exactly like the Metal `64 MiB` predicate. Reading
`buildCompactContributionPlanInner` (`planning.zig:439`) killed that: the
budget is compared against `group_bytes + member_bytes`, i.e. the size of the
plan structs, not the column data. `CompactContributionMember` is
`{ []const M31, [4]M31 }` = 32 bytes.

`quotient_compact_groups.accumulate` (`quotient_compact_groups.zig:35`)
confirms the collapse is real: per lifted run it reduces every member of the
group to one even/odd `Vec4` pair (aarch64 path, four members at a time), then
broadcasts that pair across the run's output rows. Cost per output row is one
packed load-add-store per group per coordinate — independent of member count.

`quotient_direct_groups.canAccumulate` / `accumulate`
(`quotient_direct_groups.zig:9,33`) fuses four direct columns into a single
`dot4Packed` pass when they are consecutive, share a batch, and each has one
contribution.

At that point the mechanism looked already-collapsed, but "looks fine" is not
evidence. Instrumented it.

## Instrumentation

Added, behind `std.posix.getenv("STWO_QUOTIENT_AUDIT")`:

- in `lazy_provider.zig`, after plan construction: lifting log size, domain
  size, flattened/active/active-non-zero column counts, summed raw column
  bytes, compact admission flag, group and member counts, batch count, and a
  histogram of `shift_amt`;
- in `quotient_tile_executor.zig`: global atomics summing per-phase worker
  nanoseconds around the domain walk, `prepareBatchMajor`, `clearNumerators`,
  `accumulateTile`, and the finalize+emit tail, plus counters for tiles,
  view-loop passes, and four-way fusions;
- printed from `LazyQuotientProvider.deinit`.

All of it reverted with `git checkout --` before any commit. Nothing from this
section is in the tree.

## Raw measurements

arithmetic-2m
(`test_prove_verify_large_trace_canonical_small/compiled.json`), plan shape:

```
log_size=22 domain=4194304 flat_columns=761 active=646 active_nonzero=472
raw_MiB=1166.298 compact_admitted=true compact_groups=26 compact_members=550
batches=14
shift_hist= 1:50 2:1 4:129 5:94 6:7 7:5 8:11 10:1 11:6 14:6 15:7 16:29 18:126
tiles=16398 view_passes=278766 fused4=180378 direct_views=50 compact_groups=26
```

memory-7m (`stwo_memory_200x300.json`):

```
log_size=23 domain=8388608 flat_columns=882 active=768 active_nonzero=611
raw_MiB=4139.296 compact_admitted=true compact_groups=36 compact_members=704
batches=16
shift_hist= 1:59 2:56 3:79 4:159 5:39 7:7 8:5 9:11 10:20 11:27 12:50 14:57 15:34 16:7 17:1
tiles=32778 view_passes=655560 fused4=426114 direct_views=59 compact_groups=36
```

Derived:

- `16398 * 256 = 4,194,688`; the last tile is short, so tiles x 256 covers the
  4,194,304-row domain exactly once. Same for memory-7m: `32778 * 256`
  covers 8,388,608 once. **One full-domain pass**, not one per run.
- arithmetic-2m view passes per tile: `278766 / 16398 = 17.0`, fusions per
  tile `180378 / 16398 = 11.0`. So 11 four-way passes (44 views) plus 6 single
  passes = 50 direct views in 17 passes. With 26 compact groups that is 43
  numerator streams per tile for 472 active non-zero source columns.
- memory-7m: `655560 / 32778 = 20.0` passes, `426114 / 32778 = 13.0` fusions,
  13 x 4 + 7 = 59 direct views. 36 + 20 = 56 streams for 611 columns.
- Compact metadata: 550 x 32 B = 17.6 KiB and 704 x 32 B = 22.0 KiB against a
  1,048,576 B budget — 1.7% and 2.2%. The budget cannot be what excludes
  anything.

Phase split, worker-summed, lighter instrumentation build (timers only, no
view-loop counter), arithmetic-2m, wall stage 277.1 ms:

```
walk=28.7ms denom=182.5ms clear=12.8ms accum=474.8ms finalize_emit=370.3ms
```

Heavier build (timers plus per-view atomic), arithmetic-2m:

```
walk=36.6ms denom=296.1ms clear=22.4ms accum=770.6ms finalize_emit=559.3ms
```

The inflation between the two builds is the atomic in the view loop plus host
noise; it is why the note presents shares rather than absolute phase costs.

memory-7m, heavier build, wall stage 630.3 ms:

```
walk=62.4ms denom=459.0ms clear=36.4ms accum=1994.7ms finalize_emit=845.3ms
```

Clean-build stage costs on the same host for reference: arithmetic-2m
`fri_quotient_build_and_commit = 321.3 ms` in the first cold run, 277.1 ms in
a later one. Host load was 2.5–4.4 throughout; that spread is contamination,
not signal.

## Why I stopped rather than shipping a change

The hypothesis was falsified by direct count, not by absence of an idea. There
is no byte-keyed exclusion, no per-run pass, and no gather to eliminate. Two
levers remain visible but neither is this increment's job:

1. Merging compact groups that share a batch across different shifts would
   take arithmetic-2m from 26 compact streams to at most 14 (one per batch),
   about 12 of 43 numerator streams. M31 addition is associative and
   commutative so proof bytes would survive reordering, but merging runs with
   different block boundaries is fiddly and the ceiling is roughly 28% of the
   44% accumulation share of a 277 ms stage — well under 1% of a 5.3 s proof.
2. Finalize + emit is 35% and denominator batch inversion 17% of the stage.
   Neither is a fragmentation problem, and both deserve their own increment
   with their own isolate.

Shipping a speculative restructuring to avoid returning a negative would have
been the wrong call. The negative is the finding.

## Validation performed on the unchanged head

Paired A-B-B-A between the pristine predecessor `zig-out` copy and a fresh
rebuild of the same sources. Raw lines as emitted, with the `uptime` that
preceded each:

```
--- arithmetic-2m pred 1   load 4.57 3.98 4.01
prove_ms=3142.939 quotient_ms=300.489 sha=25e5719f... fallbacks=0
--- arithmetic-2m cand 1   load 4.44 3.96 4.00
prove_ms=3296.576 quotient_ms=342.335 sha=25e5719f... fallbacks=0
--- arithmetic-2m cand 2   load 6.97 4.49 4.19
prove_ms=3202.980 quotient_ms=331.860 sha=25e5719f... fallbacks=0
--- arithmetic-2m pred 2   load 6.73 4.49 4.19
prove_ms=3178.248 quotient_ms=300.461 sha=25e5719f... fallbacks=0
--- memory-7m pred 1   load 6.59 4.49 4.19
prove_ms=7392.830 quotient_ms=617.102 sha=e3317e55... fallbacks=0
--- memory-7m cand 1   load 8.25 4.94 4.35
prove_ms=7584.830 quotient_ms=623.093 sha=e3317e55... fallbacks=0
--- memory-7m cand 2   load 9.35 5.22 4.46
prove_ms=7591.878 quotient_ms=607.022 sha=e3317e55... fallbacks=0
--- memory-7m pred 2   load 11.09 5.71 4.64
prove_ms=7437.917 quotient_ms=602.469 sha=e3317e55... fallbacks=0
--- all-opcodes pred 1   load 11.19 5.90 4.72
prove_ms=1643.247 quotient_ms=138.474 sha=79ae76e1... fallbacks=0
--- all-opcodes cand 1   load 10.86 5.92 4.73
prove_ms=1603.982 quotient_ms=137.453 sha=79ae76e1... fallbacks=0
```

Contamination, stated plainly: `test-riscv-release-exhaustive` had been running
in another checkout since 23:28 and was still running at the end, and the
`stwo-cairo-metal` build overlapped the first two arithmetic-2m samples. That
is why the load average climbed from 4.57 to 11.19 across the block. I should
have serialised the Metal build ahead of the timing block; I did not, and the
A-B-B-A ordering is the only mitigation applied.

Because both arms are the same sources, the resulting spread is the noise
floor, not an effect: -2.4% to +2.8% on prove time, up to +12.2% on the
quotient stage alone. That is the single most useful number this increment
produced for the campaign — it sets the bar any later candidate must clear.

Other checks:

- Official Rust verifier on `arithmetic-2m-cand-1.proof.json`:
  `{"verified":true,"channel":"blake2s","proof_sha256":"25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6","wall_time_ns":197993125,"error":null}`.
- Metal arithmetic-2m: digest `25e5719f...` identical to CPU,
  `classification: accelerated_without_fallbacks`, `metal_dispatches: 74`,
  `cpu_fallbacks: 0`, prove 2,156.876 ms.
- `zig build test-cairo-cpu-product test-cairo-frontend -Doptimize=ReleaseFast`
  passed. Closure PASS, 326 transitive Zig sources, identity `dirty: false`.

No source file differs from `ad2d3ac5`; the commits carry the note and this
transcript only.
