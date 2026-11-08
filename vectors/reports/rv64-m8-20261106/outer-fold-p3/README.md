# outer-fold-p3 receipts: hybrid recursion complete (STWO_RV64_M8_OUTER_JOBS=1)

Branch `codex/rv64-m8-outer-fold-p3`, rebased onto `codex/rv64-m7-integrate @ bf2b6c072` (the three paused
commits, now 9b6a2a5a1 / f9870cb98 / 826fb1cca), plus 686c8cbbd (fixes) and f5eb1beae (FIXED graph replay, GPU timing).
Pod 2x RTX 5090 (`rv64-resident-2x5090`). Labels: [M] measured, [D] derived, [E] estimated.
Hybrid = legacy request orchestration + native proving; every leaf / fold / root node is an `OuterNodeJob` on a
persistent per-GPU `DeviceWorker` (`WorkerSet.startParked`, `unpark` per request, `park` at request end).

## What was wrong, what changed

| item | root cause | fix |
|---|---|---|
| teardown abort `host budget heap underflow` (host_budget_allocator.zig:290 via rv64_large_block_recycler.deinit), and the intermittent fold `RootMismatch`, glibc `corrupted size vs. prev_size` and SIGSEGV seen on the fold runs | `OuterNodeJob.allocator` defaults to `c_allocator`; the PCS proof was decoded with it and `assemble` MOVED it into the om31 `Produced`, which the request layer frees with its own allocator (budgeted `LargeBlockRecycler` -> `SharedHostBudget` -> `smp_allocator`). Large blocks were "returned" to a budget that never admitted them (heap_live drifts down until the recycler's final cache release underflows); small blocks went into smp free lists while still owned by malloc (overlapping allocations: corrupted later proofs, glibc aborts). Found with a ReleaseSafe build: `SmpAllocator.free: incorrect alignment` from `Wrapped.deinit -> commitment_scheme_proof.deinit` in `execution_wrap.hostWorker` | `OuterNodeJob.proof_allocator`, set by `outer_job_factory.Prover.prove` to the `prove()` allocator; `assemble` refuses a mismatch (`OuterProofAllocatorMismatch`). Regression test `outer_staged.zig` "moved proof ownership requires the identical allocator instance"; end-to-end negative test below |
| cached fold statics borrowed the first node's PP | `StaticsCache` (fold classes, cross-request) kept `fixed_raw` (PP column slices) and `geometry.fixed_logs` (pointer into the Authority) | raw FIXED evaluations are per node (`Staged.fixed_raw`, owned by the prestage Owner); the plan keeps no pointer into the authority |
| suspected 2^31-element index | the whole-LDE INTER of a fold is 2.36e9 words; the chunk-bounded node never holds it. Largest held buffer: in-place INTER coefficients, [M] 1.245e9 words (26235156 and 24628607 folds) | `Plan.requireIndexable`: every held node buffer and stream scratch must be < 2^31 words, else fail closed `OuterBufferExceedsInt32Index` (host test). Ruled out on both dev blocks: every node ran |
| FIXED precommit launched ~47-55 kernels per node, never captured | FixedJob enqueued directly | FixedJob body replays through the per-worker graph cache (key = FIXED log topology, placement bit 4) |
| no per-node GPU time | receipts were host wall clock | `K.Timing`: two CUDA events (base image `stwo_rv64_event_*`) created and recorded on the worker thread around the body, outside capture, resolved in `finish`; `gpu_ns` in `GPU_M8_OUTER_NODE` / `GPU_M8_OUTER_FIXED` |

Test hook (default unset): `STWO_RV64_M8_OUTER_FAULT_ORDINAL=n` fails node n where a footprint refusal returns.

## Byte parity per node [M]

Every produced `*.proof` compared by SHA-256 to the frozen D2 golden
(`vectors/reports/rv64-m7-20261105/d2-composed/combined-d2-package/<block>-combined-d2-coalesce-v1/trial-1/artifact-fingerprints.json`):

| run (persistent window, N requests) | block | nodes (leaves + folds + root) | identical, every request |
|---|---|---|---|
| `26235156-r2-p4` (2) | 26235156 | 16 (11 + 4 + root) | 16/16, 16/16 |
| `26235156-r3-p6` (3) | 26235156 | 16 | 16/16, 16/16, 16/16 |
| `24628607-r3-p5` (3) | 24628607 | 20 | 20/20, 20/20, 20/20 |

Negative test `26235156-r1-f1` (`STWO_RV64_M8_OUTER_FAULT_ORDINAL=4`): node 4 (a fold) fails `M8OuterInjectedFault`, the
request fails closed, no root is published, the window parks and stops, the service exits with status 1 (before the fix:
-6, `host budget heap underflow`). The 11 leaves published before the failure are byte-identical to the golden.

## Persistent window and graph replay [M]

One boot per service (`startParked`), `unpark` per request ([M] 22-135 ms across the runs), `park` at
request end. Provers (graph caches) persist; window 2 reported `moved=true` (arena base changed) and replay stayed
correct because every warm node re-records and rebinds (`cudaGraphExecUpdate`).

`26235156-r3-p6` (this source, with GPU timing):

| request | wall | recursion after native | node bodies replayed | FIXED jobs replayed | max host launches / node (node + FIXED) | node GPU time sum / median / max (events) | FIXED GPU time sum |
|---|---|---|---|---|---|---|---|
| 1 (cold) | 39.80 s | 26.48 s | 0/15 | 6/15 | 1405 | 6.24 / 0.41 / 1.11 s | 0.131 s |
| 2 | 18.69 s | 12.96 s | 10/15 | 13/15 | 918 | 5.40 / 0.41 / 0.53 s | 0.099 s |
| 3 | 17.30 s | 12.06 s | 12/15 | 15/15 | 1359 (direct node) / **2** (replayed node) | 5.46 / 0.40 / 0.52 s | 0.099 s |

A replayed node issues 2 host launches (node graph + FIXED graph), inside the <= 50 target; its graph holds 1055-1993
kernel nodes. Nodes still direct on request 3 landed on a device whose graph cache had not yet seen their class (the
capture threshold is 2 sightings per device; the scheduler does not pin a class to a device). Host waits: 1 per node job
and 1 per FIXED job. Per-node peak (worker arena): leaves 0.76e9-4.55e9 words (3.1-18.2 GB), folds/root 5.38e9-5.46e9
words (21.5-21.8 GB) [M].

`24628607-r3-p5` (previous build, no GPU timing): request 49.89 / 22.77 / 20.25 s, recursion after native
31.40 / 15.13 / 13.34 s, node bodies replayed 0 / 9 / 12 of 19.

[D] GPU time does not change under replay (median 0.40-0.41 s either way): the node bodies are kernel-bound, the graph
removes host enqueue time (large direct nodes 119-173 ms, replayed 8-31 ms, request 3). Warm node GPU time (5.4 s summed over two
GPUs, about 2.7 s per GPU) against 12.1 s recursion after native puts the hybrid recursion critical path on the host
side of each lane (prestage, legacy host prep, FIXED precommit, assembly and verify), one node per lane per device at a time.
This is slower than the legacy recursion (5.7 s on 24628607); the hybrid path stays default-off.

## Gates [M]

Pod run `runs/m8-outer-fold-p3/g1`, source f5eb1beae (`gates.json`):

- default `rv64_gate.sh` (26235156): **PASS** (cold + warm byte-identical to the frozen D2 golden, 32/32 artifacts each;
  fresh CPU receivers; negative corpus).
- `--env STWO_RV64_M8_OUTER_JOBS=1` (+ addon / outer-fs / pinned-cap envs) on 26235156: **PASS** (complete root,
  32/32 artifacts byte-identical on both requests, receivers, corpus); all 30 node proofs were OuterNodeJobs.
- same on 24628607: **PASS** (39/39 artifacts on both requests); all 38 node proofs were OuterNodeJobs.

Gate request walls are diagnostic, not canonical measurements: 26235156 42.57 / 17.64 s, 24628607 49.68 / 20.87 s (cold / warm).
