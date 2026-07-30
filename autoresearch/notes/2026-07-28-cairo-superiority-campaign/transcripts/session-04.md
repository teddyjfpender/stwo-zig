# Session 04 — parallel hasher-state replication (R5b)

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Worktree `/private/tmp/stwo-zig-cairo-native-throughput-10x`, branch
`autoresearch/cairo-native-throughput-10x`, head `34b2a898` at start.

## What this increment was asked to isolate

Increment 3 built a three-mechanism candidate (`35dcf92e`), measured it at
1.04x-1.13x on the `merkle_commit` stage, and rejected it. Its audit named one
component as the clean part: the streaming committer's hasher-array
replication was a serial scalar gather while every other phase in the leaf
pipeline ran on the shared work pool. The audit attributed 442.5 ms of a
1,335.6 ms instrumented arithmetic-2m stage — 33% — to that pass, and that pass
does no hashing at all.

This session extracts only `expandHashers` from `35dcf92e`. Not the fused
finalization kernel (`finalizeM31Columns4`), not the direct-tail policy
(`directTailStart` / `finalizeDirectTail`). Those two are what increment 3
measured as giving back the win.

## The change

`src/prover/vcs_lifted/expand.zig`, new, 137 lines including its test.
`src/prover/vcs_lifted/prover.zig`, three lines changed: one import, one
`ExpandOps` alias, and the call site replacing the gather loop at what was
line 505.

The observation the module rests on: the lifting map

    dst[i] = src[((i >> shift) << 1) + (i & 1)]

is constant across each aligned run of `1 << shift` destinations. Every
destination in run `r = i >> shift` reads either `src[2r]` (even `i`) or
`src[2r + 1]` (odd `i`). So a run reads two hashers and writes `1 << shift` of
them. The predecessor loop recomputed `src_idx` and re-dereferenced the source
array per destination; the run form hoists both source states out of the inner
loop, and the inner loop becomes a streaming write.

Runs are independent and destinations are disjoint, so the pass splits over
`[dst.len * w / n, dst.len * (w+1) / n)` per worker with the same
`parallel_min_nodes_per_worker = 1024` capacity rule `leaves.zig` uses for
absorb and finalize. A worker's range can start mid-run; `expandRange` handles
that by clamping `run_end` to `ctx.end`, which is why the split does not have
to be run-aligned.

Guard rails checked before measuring:

- Byte exactness is structural, not argued. Nothing is computed. The
  destination array holds the same hasher states in the same positions; only
  the order of the loads changes.
- `work_pool.getGlobalPool()` returns `null` under `builtin.is_test` and
  `builtin.single_threaded` (`src/prover/work_pool.zig:65-67`), so
  `worker_count` collapses to 1 and the pass runs serially in test builds. No
  `builtin` branch was needed in the new module.
- Disjointness: half-open ranges, `start[w+1] == end[w]`, `end[n-1] == dst.len`.
- Two asserts pin the caller's contract: `shift >= 1` and
  `dst.len == src.len << (shift - 1)`.
- The unit test in `expand.zig` walks source sizes `2^1..2^6` × shifts `1..6`
  and compares elementwise against the scalar gather written out longhand.

Spot check before committing: all-opcodes proof digest
`79ae76e1ac0c48b1e3b06810ddb1fed8aabe5dfb10d028e879105b79716cb310`, equal to
the campaign's recorded value. Committed as `1e234274`.

## Measurement setup

Predecessor: the whole `zig-out` tree built from clean `34b2a898` *before* the
edit, copied to `/private/tmp/campaign-inc4-pred`. The whole tree, not the
binary, because the CLI resolves `stwo-cairo-vm-adapter` beside the executable
and the params manifest at `<exe_dir>/../share/...` (harness note from
increment 1).

Three A-B-B-A blocks per workload, 6 paired samples per arm, one untimed warmup
process per arm before each workload's blocks (increment 2 measured the
cold-first-sample penalty at +26% on a stage). `--verify` on every run.

One harness bug cost a few minutes: the CLI refuses to overwrite an existing
`--proof` / `--report-out` / `--stage-profile-out` (`error: OutputAlreadyExists`),
and the runner's warmup tag was shared between arms. Fixed by unlinking the
three outputs at the top of each run.

Observable: `stages.json` has `merkle_commit` as a child of three stages —
`preprocessed_materialize_and_commit`, `main_trace_commit`,
`interaction_trace_commit`. Both the aggregate parent times (the brief's stated
observable) and the `merkle_commit` children are reported, because the parents
carry materialization work the change cannot touch and therefore dilute the
ratio.

## Result

    arithmetic-2m  merkle_commit sum  pred 659.499 (sd 11.183)  cand 584.750 (sd  5.343)  1.1278x
    arithmetic-2m  commit stage agg   pred 894.801 (sd 13.130)  cand 819.852 (sd  8.095)  1.0914x
    arithmetic-2m  prove             pred 2498.877             cand 2418.508             1.0332x
    memory-7m      merkle_commit sum  pred 1554.479 (sd 37.583) cand 1374.981 (sd 11.136) 1.1305x
    memory-7m      commit stage agg   pred 2221.862 (sd 45.733) cand 2045.538 (sd 16.796) 1.0862x
    memory-7m      prove             pred 6384.175             cand 6225.493             1.0255x
    all-opcodes    merkle_commit sum  pred  366.103             cand  364.910             1.0033x  (block 3 contaminated)
    all-opcodes    merkle, blocks 1-2 pred  347.029 (sd  3.279) cand  330.770 (sd  4.329) 1.0492x

Bar is 1.15x on arithmetic-2m and memory-7m. Neither reaches it on either
reading. **Rejected.**

The separation is nonetheless total: the arms' per-sample ranges do not overlap
on either large workload (arith pred 646.3-680.1 vs cand 578.7-591.8; memory
pred 1503.4-1626.7 vs cand 1355.1-1390.3). This is not a noise result. It is a
real 75 ms / 179 ms saving that is simply smaller than the bar.

all-opcodes block 3 caught a load spike — all four of its samples, both arms,
are 25-33% above blocks 1 and 2. Reported rather than dropped; the clean blocks
give 1.049x, same direction.

## Why it is only 1.13x — the phase split

The brief allowed re-borrowing `495a9cff`'s `STWO_MERKLE_AUDIT=1`
instrumentation for the final phase split. It was applied to *both* arms
(predecessor sources from `34b2a898`, candidate from `1e234274`), two
instrumented trees built, three interleaved cold arithmetic-2m runs per arm,
then removed. Both instrumented builds reproduce the arithmetic-2m digest.

    phase      pred ms   cand ms   ratio
    absorb       332.8     347.5   0.957
    parents      167.4     172.7   0.970
    expand       146.6      95.7   1.532
    finalize     110.0     118.5   0.928
    total        756.7     734.3   1.030

Per-run expand: pred 145.4 / 147.1 / 147.1, cand 96.2 / 90.9 / 99.9. The
individual 570 MiB replications go 32.3 → 11.7 ms and 32.2 → 12.2 ms, about
2.7x each.

**This forced a correction to increment 3's audit.** That audit put the
replication phase at 442.5 ms / 33.1% of a 1,335.6 ms stage. The same
instrumentation on a quiet host measures 146.6 ms of 756.7 ms — 19.4%. The
earlier run was on a busier machine, and the serial gather is precisely the
phase that degrades worst under contention, so it was the most inflated line in
that table. The brief's "expected ~1.4x if the 442.5 ms bucket parallelizes"
was derived from the inflated figure and was never reachable: even driving a
146.6 ms bucket to zero inside a 756.7 ms stage caps the stage at 1.24x, and the
achievable fraction of it caps at about 1.08x.

I take the methodological lesson to be the mirror of increment 3's: single-cold
instrumented runs on a shared host over-attribute to whichever phase is serial,
because that phase absorbs the contention the pooled phases spread out. Phase
splits should be paired and repeated the same way stage measurements are. This
session's split is three runs per arm interleaved, which is why its per-run
spread is 1.4%.

**Where the remaining 95.7 ms goes.** Summing `hasher_bytes` across the
replications in the three trees, the pass writes roughly 2.5 GB and reads
roughly 1.3 GB. 3.8 GB in 95.7 ms is about 40 GB/s — this host's streaming
ceiling. The phase is now bandwidth-bound. More workers cannot help; the only
remaining lever is not doing the replication, which is `35dcf92e`'s fused tail,
already measured and rejected.

One negative detail worth keeping: the log-20 replication (142 MiB) gets
*slightly worse*, 8.2 → 9.0 ms. At that size the pass is dominated by
first-touch page faults on the fresh `alloc`, which splitting the write does not
remove. Not worth chasing — it is 1 ms.

## Verification

- 36 timed proofs, one digest per workload, all equal to the campaign's
  recorded values: arith `25e5719f…`, memory `e3317e55…`, all-opcodes
  `79ae76e1…`.
- `zig build test-cairo-cpu-product test-cairo-frontend test-stwo-prover
  -Doptimize=ReleaseFast` — pass. Cairo CPU closure 327 sources, prover closure
  187, conformance 5 explained legacy findings, `dirty: false`.
- Metal arithmetic-2m: digest `25e5719f…`, `accelerated_without_fallbacks`,
  74 dispatches, `cpu_fallbacks: 0`.
- Official Rust verifier on `arithmetic-2m.cand3.2.proof.json`:
  `verified: true`, `blake2s`, `82f21252…`.
- `merkle-worker-stress` was not re-run this session; increment 3 recorded its
  pre-existing `blake_deep InvalidNRounds` failure and the stale
  `vectors/reports/merkle_worker_stress_artifacts/` collision, neither of which
  this diff touches.

## Revert

Per the standing directive the source diff is reverted. `1e234274` is preserved
in history as the measured implementation.

## What I would take forward

R5 is done. Two structural attacks on the Merkle commit stage have now been
built and measured at pool scale, and the post-change phase split says why a
third would not pay: 84% of the stage is BLAKE2s compression through a kernel
that increment 3's `asm` breakdown showed is 92.2% NEON with identical
instruction counts across every variant tried, and the other 13% is a
bandwidth-saturated copy. The stage is at its floor for this data layout.

The one idea that would change the floor is not a Merkle idea at all: it is
reducing how much state the ladder has to carry, i.e. a hasher representation
smaller than 136 bytes per leaf, or a commit order that does not require the
array to exist at the largest domain. Both are large redesigns with decommit
contract exposure, not increments.

R6 (composition) is the right next target and it is a bigger one:
`composition_evaluation` is 302.7 ms on arithmetic-2m in these very profiles,
larger than any single Merkle phase, and it has never been audited on this
branch.
