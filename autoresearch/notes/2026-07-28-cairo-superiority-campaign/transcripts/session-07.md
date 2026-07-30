# Session 07 — Intra-component witness row parallelism (R2a)

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Worktree `/private/tmp/stwo-zig-cairo-native-throughput-10x`, branch
`autoresearch/cairo-native-throughput-10x`, head `2f77af64` (clean).

Host: Apple M5 Max, `hw.ncpu` 18 = 12 performance cores
(`hw.perflevel0.logicalcpu`) + 6 efficiency cores (`hw.perflevel1.logicalcpu`).
Load average 4.72 at session open, 3.55 at the start of the paired probe,
rising monotonically to 10.56 by the last block — seven other users are on
this box and their load grew under me. That drift is why every block is
A-B-B-A: the drift is absorbed inside a block, not across blocks.

## The premise did not survive first contact

The brief asked me to "make the dominant witness component's bytecode
execution split its row range across the work pool." I opened
`src/frontends/cairo/witness/component_executor.zig` expecting to find a
single-threaded row loop.

It is already row-parallel, and has been. `execute` at line 148 pulls the
global pool, computes a worker count, allocates one private register file and
one private deduction-argument file per worker, cuts `row_count` into
`divCeil(row_count, worker_count)` ranges, and calls
`program_mod.executeAllRange(start, end, ...)` on each. Row independence is
structural and documented at `program.zig:327`: outputs go to
`output_columns[col][row]`, lookup words to `lookup_words[imm * row_count + row]`
(`program.zig:493`), sub-words to `sub_words[row * n_sub_words + imm]`
(`program.zig:498`). Every write is indexed by `row`. Multiplicity tables —
the one genuinely accumulating output — are rejected outright for partial
ranges (`program.zig:349`) and the executor requires `n_mult_tables == 0`
before it starts (`component_executor.zig:62`).

So R2a as stated was already done. Increment 6's observation was still real
though: program execution parallelises at only 52-64%. If the split exists and
is still 52% efficient, the interesting question is *why*, and that is a
different question from the one I was handed.

I decided the honest version of the increment was: form a specific mechanical
hypothesis for the lost 40%, implement the fix it implies, and measure it.

## The hypothesis

`sysctl` says 12 P-cores and 6 E-cores. An E-core on this part retires scalar
integer work at roughly a third to a half of a P-core's rate. The executor
hands out *exactly one static equal range per worker*. On a heterogeneous
machine that is the textbook failure: the component's span is set by the
slowest range, so six E-core ranges each 1/18 of the rows stretch the whole
component by the E/P ratio while twelve P-cores sit idle at the end.

The arithmetic is attractive. Take the measured worker sweep on memory-7m,
`add_opcode_small`'s `witness_program_execute`:

```
W= 4  base_trace 1930.3  graph 1835.7  exec_all 1702.4  aos_exec 971.9
W= 8  base_trace 1418.7  graph 1322.2  exec_all 1181.3  aos_exec 660.3
W=18  base_trace  877.9  graph  779.8  exec_all  637.0  aos_exec 371.8
```

If W=4 is four P-cores at full rate, one P-core-second of work is ~3888 ms.
Perfectly balanced across 12 P + 6 E at E = P/2.5 gives 14.4 P-equivalents,
so 270 ms against the measured 371.8 — a 1.38x recovery on the dominant
component, which on arithmetic-2m (where it is 95.9% of program execution)
would carry `base_trace_build` past the 1.10x bar.

## The fix

`scheduleChunkRows` in `component_executor.zig`. Cut the row range into about
sixteen chunks per worker rather than one, and let workers claim chunks from a
single `std.atomic.Value(usize)` cursor with `fetchAdd(1, .monotonic)`. Fast
cores simply claim more chunks; the tail is bounded by one chunk instead of by
one eighteenth of the component.

Three properties I held onto:

- Chunks are contiguous disjoint row ranges, so byte-exactness is inherited
  from the existing per-range disjointness, unchanged. Claim order cannot
  affect any output because no output index depends on anything but `row`.
- The floor is `parallelRowsPerWorker` (32 rows for programs containing a
  `deduce_call`, 4096 otherwise) and the ceiling is the previous even static
  split, so the schedule can only ever degrade to exactly today's behaviour.
- `worker_count == 1` — null pool, `builtin.is_test` — keeps one range over
  the whole component and never touches the cursor.

Admission is `row_count`, `worker_count`, and the program's own opcode census.
No name, no path, no digest.

Byte-exact on first run: arithmetic-2m `25e5719f…` at 1, 3 and 18 workers,
memory-7m `e3317e55…`, all-opcodes `79ae76e1…`.

## It did nothing, and the reason is the finding

Single-run mechanism check, default workers:

```
memory-7m    base_trace  pred 835.5  cand 838.2   aos_exec pred 358.7 cand 356.0
arithmetic-2m base_trace pred 266.6  cand 270.9   aos_exec pred 158.2 cand 160.2
```

Before believing that I checked the schedule was actually engaged, because a
no-op schedule would have measured exactly like this. Temporary probe:

```
AUDIT rows=4194304 workers=18 min_chunk=4096 chunk_rows=14564 chunks=288
AUDIT rows=2097152 workers=18 min_chunk=4096 chunk_rows=7282  chunks=288
AUDIT rows=1048576 workers=18 min_chunk=4096 chunk_rows=4096  chunks=256
AUDIT rows= 524288 workers=18 min_chunk=4096 chunk_rows=4096  chunks=128
AUDIT rows=   4096 workers=1  min_chunk=4096 chunk_rows=4096  chunks=1
```

288 chunks over 18 workers on `add_opcode_small`. Engaged.

Then the census that actually answers the question — chunks claimed and busy
time per worker, same component, same run:

```
rows=4194304 chunks=288 per-worker:
  17/357ms 16/358ms 18/367ms 15/372ms 17/367ms 16/365ms
  16/363ms 16/360ms 17/369ms 15/357ms 16/368ms 16/373ms
  16/370ms 15/367ms 16/359ms 15/369ms 16/373ms 15/363ms
```

Every worker claims 15 to 18 of 288 chunks. Every worker is busy 357 to 373
ms — a 4.5% spread across the whole pool. Six of those eighteen threads are on
E-cores, and they retire rows at the same rate as the P-core threads.

That kills the hypothesis and replaces it with a better one. If a
supposedly-half-speed core keeps up with a full-speed core on this loop, the
loop is not core-throughput-bound on either of them. It is bound by something
they share, and the only thing eighteen threads share here is the memory
system. `add_opcode_small` on memory-7m streams 4.19M rows through input
columns, output columns and lookup words in canonical column-major layout —
this is a bandwidth problem wearing an interpreter's clothes.

It also retro-explains the "52-64% efficiency" number cleanly. Static equal
chunks were *already* balanced — increment 6 read sub-linear scaling as
scheduling loss, but scaling is sub-linear because per-core throughput falls as
workers are added, not because any worker finishes early. There was no
straggler to fix.

## The paired measurement anyway

The gate deserves real numbers rather than my inference from a single run, so
I ran it: A-B-B-A, three blocks per workload, one untimed warmup per arm,
uninstrumented binaries, outputs deleted before every run (the CLI refuses to
overwrite and silently reproduces stale numbers otherwise). Predecessor is the
pristine `zig-out` tree copied whole from `2f77af64`. `prove` is the sum of
top-level stages in the same process.

arithmetic-2m, ms:

```
b1 pred base_trace 264.441 exec_all 185.825 aos_exec 156.536 prove 2241.915
b1 cand base_trace 262.578 exec_all 183.160 aos_exec 152.981 prove 2234.043
b1 cand base_trace 269.952 exec_all 191.708 aos_exec 160.929 prove 2266.868
b1 pred base_trace 269.461 exec_all 191.004 aos_exec 161.226 prove 2265.154
b2 pred base_trace 271.292 exec_all 191.138 aos_exec 162.244 prove 2271.289
b2 cand base_trace 267.627 exec_all 188.440 aos_exec 156.894 prove 2405.600
b2 cand base_trace 272.276 exec_all 193.801 aos_exec 163.489 prove 2510.689
b2 pred base_trace 283.944 exec_all 203.324 aos_exec 171.913 prove 2373.000
b3 pred base_trace 277.879 exec_all 197.978 aos_exec 169.713 prove 2310.763
b3 cand base_trace 271.762 exec_all 190.228 aos_exec 159.686 prove 2318.463
b3 cand base_trace 269.984 exec_all 190.622 aos_exec 159.896 prove 2328.543
b3 pred base_trace 280.621 exec_all 196.719 aos_exec 167.891 prove 2339.854
```

memory-7m, ms:

```
b1 pred base_trace 879.662 exec_all 629.305 aos_exec 373.579 prove 5670.151
b1 cand base_trace 868.013 exec_all 615.581 aos_exec 374.084 prove 5704.458
b1 cand base_trace 902.800 exec_all 643.535 aos_exec 398.992 prove 5768.865
b1 pred base_trace 893.445 exec_all 643.906 aos_exec 381.648 prove 5801.072
b2 pred base_trace 889.179 exec_all 638.477 aos_exec 381.167 prove 5738.552
b2 cand base_trace 875.661 exec_all 620.511 aos_exec 378.239 prove 5777.998
b2 cand base_trace 875.973 exec_all 621.335 aos_exec 379.323 prove 5830.132
b2 pred base_trace 901.841 exec_all 638.462 aos_exec 382.528 prove 5888.005
b3 pred base_trace 906.852 exec_all 645.753 aos_exec 388.417 prove 5905.804
b3 cand base_trace 895.583 exec_all 628.253 aos_exec 380.779 prove 5901.369
b3 cand base_trace 889.662 exec_all 632.376 aos_exec 385.570 prove 5904.609
b3 pred base_trace 911.952 exec_all 652.755 aos_exec 384.651 prove 5949.569
```

Block ratios (pred/cand, arm-averaged within block):

| Quantity | b1 | b2 | b3 | pooled |
| --- | ---: | ---: | ---: | ---: |
| arithmetic-2m `base_trace_build` | 1.0026 | 1.0284 | 1.0309 | 1.0207 |
| arithmetic-2m `add_opcode_small` execute | 1.0123 | 1.0430 | 1.0564 | 1.0374 |
| arithmetic-2m all `witness_program_execute` | 1.0052 | 1.0320 | 1.0364 | 1.0246 |
| arithmetic-2m prove | 1.0014 | 0.9447 | 1.0008 | 0.9814 |
| memory-7m `base_trace_build` | 1.0013 | 1.0225 | 1.0188 | 1.0142 |
| memory-7m `add_opcode_small` execute | 0.9769 | 1.0081 | 1.0088 | 0.9978 |
| memory-7m all `witness_program_execute` | 1.0112 | 1.0283 | 1.0300 | 1.0231 |
| memory-7m prove | 0.9998 | 1.0016 | 1.0042 | 1.0019 |

Acceptance was `base_trace_build` >= 1.10x across three blocks, or prove
>= 1.02x with non-overlapping paired CI. Pooled `base_trace_build` is 1.021x
and 1.014x; prove is 0.981x and 1.002x. Rejected, and not marginally.

The honest reading of the 1.02x that is there: it is not the dominant
component. On memory-7m `add_opcode_small` is 0.998x — nothing — while the
aggregate of all twelve components' execute is 1.023x. The gain such as it is
comes from the *small* components, where 18 static ranges over a few hundred
thousand rows do leave a visible tail, and it is worth about 15 ms on an
878 ms stage. Also note blocks 2 and 3 read higher than block 1 on both
workloads, which is the direction host load moved; I would not defend the
difference between 1.00x and 1.03x on this box tonight.

Preserved at `39a3c449`, reverted at `2aba09b6`.

## Audit rider: the 94 ms dark bucket

Fifteen minutes, done first. Increment 6 reported a pool-invariant ~94 ms on
memory-7m "outside `base_witness_graph` that no probe attributes at all". It
is attributed, and has been — the claim came from summing only the graph
subtree. `base_trace_build`'s own dark residue is 4.5 ms. The 94 ms is
`base_fixed_multiplicities` (41.3 ms) plus `base_memory_tables` (48.2 ms),
both already top-level probes and both flat across `STWO_ZIG_WORKERS`
4/8/18 at 41.9/43.8/44.1 and 48.1/48.2/49.6.

That is a correction rather than a finding, so I spent the remaining rider
budget splitting the inside of those buckets, plus the one genuinely
unattributed node I could see. Temporary nested probes in `base_trace.zig` and
`live_graph.zig`, memory-7m, ms:

| Probe | W=4 | W=18 |
| --- | ---: | ---: |
| `base_memory_tables` / `collectTopology` | 27.815 | 29.793 |
| `base_memory_tables` / `memoryAddress` + capture | 11.022 | 12.005 |
| `base_memory_tables` / `memoryBig` + capture | 0.021 | 0.034 |
| `base_memory_tables` / `memorySmall` + capture | 9.103 | 9.677 |
| `verify_instruction` / `compact_inputs.materializeDerived` | 37.963 | 43.320 |

The last row is the real one. `verify_instruction`'s stage node is 34.8-43.4
ms of which its own child probes account for 0.07 ms; increment 6 filed this
under "48.8 ms unattributed per-component residue". It is 99.8%
`compact_inputs.materializeDerived` — deriving the unique tuple set for the
compact consumer — and it is fully serial and pool-invariant.

So the pool-invariant serial floor inside `base_trace_build` on memory-7m is
about 139 ms: 44 ms `fixed_trace.populateLiveTopology`, 52 ms memory tables (of
which 30 ms is `cpu_memory.collectTopology`), 43 ms compact tuple derivation.
14% of the stage, none of it touched by any amount of pool. Probes reverted;
`git diff` against `2f77af64` on those two files is empty.

## Secondary: the W=1 defect

Increment 6 found it and left it. `component.zig` had two serial exits from
`evaluateConstraintQuotientsOnDomainImpl` — the null-pool path and the
`row_count < parallel_row_threshold or workerCount() <= 1` path — both calling
`evaluation.evaluateRange(0, row_count, false)` and neither touching
`column.next_fresh_index`. The parallel path derives `direct_store` from that
index, passes `additive = !direct_store`, and publishes the index back. A
composition column shared by two components therefore had its first
contribution overwritten.

Both exits now route through `evaluateSerial`, which applies the identical
protocol. Validation:

```
pred  STWO_ZIG_WORKERS=1  arithmetic-2m  error: ConstraintsNotSatisfied  exit=1
cand  STWO_ZIG_WORKERS=1  arithmetic-2m  verified                        25e5719f…
cand  STWO_ZIG_WORKERS=2  arithmetic-2m  verified                        25e5719f…
cand  default workers     arithmetic-2m  verified                        25e5719f…
```

Byte-identical to the predecessor at default workers, which is the point: the
parallel path was always correct, so nothing on the default configuration
moves.

This is the only source change that survives the increment, and it survives on
correctness grounds, not throughput.

## Gates on the final tree (`2aba09b6`)

- Digests: arithmetic-2m `25e5719f…` (default and `STWO_ZIG_WORKERS=1`),
  memory-7m `e3317e55…`, all-opcodes `79ae76e1…`. All self-verify.
- `zig build test-cairo-cpu-product test-cairo-frontend -Doptimize=ReleaseFast`
  passes; closure PASS, 328 transitive Zig sources.
- Metal arithmetic-2m with `-Dmetal-core-aot-bundle=/private/tmp/cairo-quotient-baseline-v2/aot-bundle`:
  `25e5719f…`, `cpu_fallbacks` 0.
- Official Rust verifier on arithmetic-2m: `"verified":true`,
  `proof_sha256` `25e5719f…`, stwo-cairo `82f21252…`.
- Pre-existing, not chased: `merkle-worker-stress` `blake_deep`
  `InvalidNRounds`; stale untracked
  `vectors/reports/merkle_worker_stress_artifacts/`; corpus `pedersen.json`
  `SegmentPointerOverflow` in the adapter.

## What I did not do

- No all-opcodes paired blocks. It is the smallest workload and the two larger
  ones had already rejected the candidate by more than an order of magnitude
  of the bar.
- No attempt at a bandwidth fix. Once the census showed a memory-bound loop the
  right move is a layout or working-set change, which is an increment, not the
  tail of this one.

## Commits

- `6d752592` the serial fresh-column protocol fix (lands)
- `39a3c449` the shared chunk cursor, byte-exact, measured 1.021x / 1.014x
  `base_trace_build` (preserved for the record)
- `2aba09b6` the revert
- note and this transcript
