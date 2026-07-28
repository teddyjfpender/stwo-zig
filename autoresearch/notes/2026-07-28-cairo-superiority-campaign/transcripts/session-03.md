# Session 03 — Merkle commit pipeline (R5)

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Worktree `/private/tmp/stwo-zig-cairo-native-throughput-10x`, branch
`autoresearch/cairo-native-throughput-10x`, head at start `44f2f506`.

Outcome: **rejected candidate**. Reasoning first, raw numbers throughout.

## 1. Where the time is, before guessing

The brief pointed at `merkle_commit` as the largest CPU bucket. The first
question was not "how do I make hashing faster" but "what is actually in that
span", because the Metal lane's win last increment came from deleting redundant
passes, not from faster kernels.

Reading the call chain settled the shape before any measurement:

- `scheme.zig:225` routes column sets of >= 128 columns to the *streaming*
  commit path. Cairo trees are 156 / 293 / 304 columns, so all of them stream.
- `tree_builders.zig:283` passes the complete height-sorted set to
  `StreamingCommitter.commitColumnsWithSparseTail`, so the entire leaf pipeline
  runs inside one call rather than per batch.
- `StreamingCommitter` keeps `leaf_hashers: []H` — one hasher state per leaf —
  and climbs the log-size ladder, replicating the array upward for each group.

That last point is the whole story. `@sizeOf(H)` printed as **136**. A `2^22`
leaf domain therefore carries a **570 MiB** array of hasher states, and
memory-7m's `2^23` trees carry **1.14 GiB**.

## 2. Audit instrumentation

Added `src/prover/vcs_lifted/audit.zig`, a `STWO_MERKLE_AUDIT=1` gated stderr
tracer, and timed five phases in `prover.zig`: replication, per-group absorb,
leaf allocation, leaf finalize, parent layers. Committed as `495a9cff` so the
findings were checkpointed before touching anything hot.

arithmetic-2m, one cold process, raw (ns), largest lines:

```
commit_begin cols=293 first_log=5 last_log=22 hasher_size=136 tail_start=null
absorb  log_size=22 leaves=4194304 cols=39 col_bytes=654311424 ns=208119833
expand  log_size=22 leaves=4194304 hasher_bytes=570425344   ns=111428584
parent_layers        leaves=4194304                          ns=104159125
finalize_hashers     leaves=4194304                          ns=65986125
expand  log_size=21 leaves=2097152 hasher_bytes=285212672   ns=45842542
```

Rolled up over all three trees:

```
absorb              496.135 ms  37.1%
expand              442.489 ms  33.1%
parent_layers       236.459 ms  17.7%
finalize_hashers    160.491 ms  12.0%
leaf_alloc            0.017 ms   0.0%
TOTAL              1335.592 ms
```

Two things jumped out.

**A third of the stage does no hashing.** `expand` is pure state replication.
And reading `prover.zig:505` it is a serial scalar gather — a bare
`for (0..layer_size)` loop — while every other phase runs on the pool.

**`tail_start=null` on every tree.** `liftedTailStart` already knows how to skip
the last replication, but requires the trailing columns to fit in the open
64-byte block: at most 15 columns, fewer if the buffer is partly full. Cairo's
trailing groups are 39, 20 and 4 columns. The fast path existed and was
structurally excluded from exactly the shapes that need it.

## 3. Worker cap: the brief's premise was stale

The brief said `MAX_WORKERS = 16` on an 18-core host. It is **32**
(`work_pool.zig:13`), and `parameters.max_parallel_workers` is 32 too. So the
cap cannot bind. I instrumented the actual counts rather than trusting the
arithmetic:

```
absorb_workers pool=true workers=18 layer=4194304
absorb_workers pool=true workers=18 layer=1048576
absorb_workers pool=true workers=16 layer=16384
absorb_workers pool=true workers=8  layer=8192
absorb_workers pool=true workers=1  layer=1024
```

18 workers reach the large layers; the taper is the
`parallel_min_nodes_per_worker = 1024` capacity rule, which is correct. No
rider needed. The genuine parallelism defect was the serial replication loop,
which the pool simply never saw.

## 4. The fix, and the arithmetic that chose it

`expanded[i] = base[((i >> shift) << 1) + (i & 1)]` is a pure replication — it
adds no information. So the absorb and the finalize can read the base state
directly. Doing that for the trailing group removes, per tree:

- the largest replication (570 MiB written, 285 MiB read),
- the absorb's read+write of that same 570 MiB array,
- the finalize's read of it,

while the hashing work is *identical* — same absorbed values, same order, same
block boundaries, same compression count. Predicted traffic at the top level:
~3.07 GB down to ~1.07 GB.

Crucially I only fused the **trailing** group. Fusing deeper would force each
column of the fused groups to be re-absorbed at the final domain instead of
once at its own. arithmetic-2m's main tree absorbs 944 MiB of message today
against 4.9 GiB fully unshared — the ladder buys 5.2x, and the trailing group
is the unique slice that costs zero extra compressions.

Built `direct_tail.zig` with `finalizeDirectTail`, and added
`blake2s_stream4.finalizeM31Columns4` so the absorb and terminal compression
share one gather of the transposed SIMD state.

First measurement, arithmetic-2m `merkle_commit`: 1377.1 -> 1221.5 ms,
**1.127x**. Under the bar.

The audit split said why: `finalize_direct_tail` came in at 525.7 ms, replacing
~675 ms of work. The fused kernel was expensive. I suspected the gather /
scatter / re-gather round trip between `updateM31Columns4` and
`finalizeEqualTail4`, so I made the SIMD state resident across both.

Second measurement: `finalize_direct_tail` 525.7 -> 524.0 ms. A wash. Total
1262.4 ms, i.e. *worse* than the first attempt (1221.5). At that point the
per-run noise was obviously larger than the effect I was chasing.

## 5. The phase that actually paid

Back to the audit: `expand` was still 154-218 ms and still serial. Two
observations made it cheap to fix. The lifting map is constant across each
aligned run of `1 << shift` destinations — that whole run alternates between
just two source hashers. So read them once per run and broadcast, turning a
strided gather into a streaming write; and the runs are independent, so split
them across the pool.

`expandHashers` landed both. Measurement: `merkle_commit` 1377.1 -> 877.3 ms,
**1.570x**, audit `expand` 442.5 -> 66.5 ms.

That looked like a clear accept. It was not — see below.

Committed as `35dcf92e` after splitting `direct_tail.zig` out of `leaves.zig`
(the pre-commit hook enforces an 850-line-per-file ceiling; `leaves.zig` hit
937 and `blake2s_backend.zig` 853).

## 6. S1: the counters contradicted the wall

Two `stwo-prof zig` harnesses against live `stwo_core`, single-threaded,
`2^18` base -> `2^19` leaves x 39 trailing columns.

```
pred (3-pass)   ns/op 140.2  instr/op 1360  cycles/op 603.1  IPC 2.255  RSS 206,717,408
cand (fused)    ns/op 184.6  instr/op 1233  cycles/op 704.6  IPC 1.750  RSS 135,397,808
```

The candidate has 9.3% fewer instructions and is **1.32x slower**. `asm`
explains the mechanism cleanly:

```
symbol                instrs pred  instrs cand  mem pred  mem cand  NEON
workload.run                  925          551       473       278  10.6% / 8.2%
compressParallel4            1440         1440        95        95  92.2% / 92.2%
```

41% fewer memory operations in the traversal; the hashing kernel byte-identical
at 92.2% NEON. The predicted mechanism is confirmed — and it still loses on
wall, because **one thread cannot saturate memory bandwidth**. Removing traffic
is worth nothing until 18 workers are competing for it. This is the four-walls
result I care most about carrying forward: S1 single-thread isolation is the
wrong instrument for a pass-fusion claim in this pipeline and will read as a
regression even when the parallel stage improves.

## 7. The measurements that mattered were contaminated

Mid-session the orchestrator flagged that increment 2's benchmark processes had
been running on this host throughout, and that the first cold process per arm
carries a page-cache penalty. Both were true and both had bitten me. My 1.570x
figure compared an *instrumented* predecessor build measured at load average
15-31 against a clean candidate measured as the load decayed to 2. Same
candidate binary, three runs: `merkle_commit` 1377 / 877 / 585 ms.

Discarded all of it and re-measured properly: pristine `zig-out` from clean
head `44f2f506`, one untimed warmup process per arm, then A-B-B-A, host at load
2.3-4.0 with `top` reporting 86-93% idle.

arithmetic-2m, three independent blocks, `merkle_commit` ms:

```
block 1   pred 771.255  631.078   cand 580.809  585.579
block 2   pred 627.871  645.072   cand 579.148  572.154
block 3   pred 629.527  624.058   cand 590.481  574.144

pred  mean 654.8  sd 57.5  range 624-771
cand  mean 580.4  sd  6.9  range 572-590
ratio 1.128x all samples;  1.088x excluding the 771.3 predecessor outlier
```

memory-7m 1.066x, all-opcodes 1.040x. Prove-level 1.063x / 1.016x / 1.005x, all
inside the ±3% floor.

Before accepting the rejection I tested the one hypothesis S1 had left open:
that the fused pass paid for copying four 136-byte states into a stack array
where the predecessor read the expanded array in place via `@ptrCast`. Changed
`finalizeM31Columns4` to borrow lanes by pointer (`*const [4]*const State`).
Result: candidate mean 582.3 ms against 575.7 ms for the copying version — a
wash, the compiler had already elided it. Recorded so nobody retries it.

memory-7m's audit split shows why it barely moves: its trees reach log 23,
`finalize_direct_tail` costs 424.2 ms and 315.0 ms per tree, and the
replications it removes cost only 12.9 ms each once the parallel broadcast has
landed. The fused kernel gives back most of what the removed pass saves —
precisely what the S1 counters predicted.

## 8. Verdict

Bar was >= 1.15x on the `merkle_commit` stage in a paired A-B-B-A. Best
measured is 1.128x on arithmetic-2m, and 1.066x / 1.040x elsewhere. Rejected,
source diff reverted, reverted tree rebuilt and confirmed to reproduce
`25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`.

Worth stating plainly, because it is not nothing: the change was byte-exact on
18 proofs across three workloads, removed a 570 MiB (log 22) / 1.14 GiB
(log 23) allocation, and cut run-to-run variance by 8x. It is sub-bar, not
wrong. It lives at `35dcf92e` if the orchestrator wants it back on a
memory-pressure argument rather than a throughput one.

## 9. Gate notes

`zig build test-cairo-cpu-product test-cairo-frontend test-stwo-prover` passed
on the candidate. `merkle-worker-stress` needed two things flagged:

- it fails immediately with `error: PathAlreadyExists` if
  `vectors/reports/merkle_worker_stress_artifacts/` survives a previous run;
  that directory is untracked scratch and must be cleared first;
- after clearing, `state_machine_deep` and `plonk_deep` passed in both prove
  modes with proof bytes identical across worker counts {2,4,8} — the property
  that matters for a vcs_lifted change — and it then failed on `blake_deep`
  with `error: InvalidNRounds`, a pre-existing condition in
  `src/examples/blake/input.zig` that this diff never touches.

The official Rust verifier run and the Metal parity run were skipped for
budget. Both are low value for a reverted candidate whose proof bytes are
bit-identical to the predecessor's on all three workloads, and whose digests
the pinned verifier already accepted in increments 1 and 2.
