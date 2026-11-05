# RV64 M6 stream enqueue: where a recursion node's time goes, and the enqueue-only contract

Branch `codex/rv64-m6-enqueue` (from `95d40063d`). Proof format: **unchanged**. Every change in this stream is
scheduling-only and must stay byte-identical to the M5 default receipts on 26235156 and 24628607.

## 1. Measured baseline (M5 integrate binaries, resident service warm, tracer on) [M]

`tools/rv64-sync-trace` (LD_PRELOAD, pass-through, proofs byte-identical with it loaded) records every
`cu{Stream,Event,Ctx}Synchronize` and blocking copy by call stack and every launch by `CUfunction`, with
timestamps; `window.py` cuts the recursion window of each request out of a daemon run.
Receipts: `vectors/reports/rv64-m6-20261105/enqueue/trace0-m5-baseline-*.json`.

| 24628607 recursion (18.18 s, 33 nodes, 2 GPUs) | value |
|---|---:|
| blocking calls | 5,674 = **171.9 / node** (gate 10) |
| kernel launches | 170,518 = **5,167 / node** (gate 500) |
| of which `circuit_assignment::level` + `narrow_run` (hint-tape) | 132,454 (78%) |
| blocked host time (GPU thread waits for its GPU) | 14.3 s over 2 threads |

Blocking calls per node by host call site (607): outer_fixed adopt 40, composition (`resident_composition`) 28,
interaction 44 (two joins + two staged readbacks per component x 11), staged-D2H/PCS pipeline 37,
trace commit 7, assignment 3, MAIN 2.

**The syncs are not where the time goes.** M5 platform already measured `STWO_RV64_EXEC_SYNC=device` (every
context join becomes a device barrier, `cuStreamSynchronize` 6,559 -> 0) at the same request time. The tracer's
timestamps show why: per GPU thread on 607

- **~1.9 s idle before the first node** of the recursion window (both GPUs): the first leaves are not ready when
  native proving ends (host prep is not overlapped with native). Owner: sched / hint-tape.
- **~40 ms idle between nodes** mid-run (fine), then **1.3-1.9 s dependency waits** in the fold tail and one GPU
  idle for the last ~2 s (binary fold chain). Owner: sched / canon-vk (k-ary).
- **in-node host gaps ~0.3 s / node** (host work between two device waits while that GPU is idle): this is the
  enqueue stream's lever. The largest: host geometry rebuilds in the PCS (3 x ~0.48 s per 607 request, see 3.2),
  interaction per-component joins (0.74 s / thread), composition setup (0.6 s / thread, arena-owned file),
  assignment launch overhead (~70k launches, 0.6 s / thread, hint-tape).

So "enqueue-only" pays only where the host has work to overlap: each Fiat-Shamir readback (MAIN root, INTER
claims + root, composition root, PCS) drains the GPU, and whatever host work follows it is GPU idle time.

## 2. The contract (M6-INTERFACES.md enqueue EQ1-EQ3)

Inside one outer node prove: every stage enqueues on a lane of the node's context; stage ordering is a stream
property (same lane, or an event between lanes), not a host join; status words are OR-accumulated on the device
and read once at the next Fiat-Shamir readback; allocation is stream-ordered (arena ranges are fenced on the
device on release, so a temporary may be released right after the enqueue that reads it). The static lint
(`scripts/rv64_sync_lint.py check`, test `tests/scripts/rv64_sync_lint_test.py`) ratchets the host-blocking sites
on the outer-node prove path; the runtime arm (`... runtime WINDOWS.json`) checks blocking calls and launches per
node from a tracer run.

## 3. Changes in this stream (all byte-identical by construction; receipts prove it)

### 3.1 Lane-0 ordering + one readback per stage
- `outer_source_interaction.zig`: the 11 components' copies, clears and kernels all run on lane 0 (the context
  stream that also carries staged uploads), claims + the shared status word live in one 89-word lease, read by ONE
  staged D2H after the last component (was: 2 joins + 2 readbacks + 1 join per component). Kernels only OR into
  the status word, so sharing it is exact; claims are the same words.
- `outer_source_main.zig`: gate kernels on lane 0 behind the staged uploads (the assignment returns joined;
  immutable uploads join themselves): the ingress join and the pre-readback join go.
- `trace_commit.zig` (stream and legacy paths): LDE/hash/tree kernels on lane 0 behind the staged twiddle/
  descriptor uploads and coefficient copies: the ingress join and the pre-readback join go. The root readback is
  ordered after the last layer on the same lane; the trailing join finds idle lanes (no driver sync).
Why exact: kernel lane choice and readback batching do not change any input, any kernel, or any order of
dependent work; only host waits are removed. Errors still surface (status checked after the single readback).

### 3.2 Host FFT/FRI geometry cache sized for the resident service
`pcs_native.zig`: the per-GPU immutable host geometry cache (no transcript/statement data enters it) is 512 MiB
instead of 128 MiB (env `STWO_RV64_PCS_HOST_GEOMETRY_BYTES`, 0 = M5 cap). At 128 MiB it held two shapes per GPU,
so a service alternating 26235156/24628607 rebuilt 42-63 MB of geometry (~0.48 s, on the device owner thread)
at the first leaf of each request. Cost: up to +0.4 GiB host RSS per GPU.

### 3.3 Measured (A/B, back to back, same harness: resident service, `--store none`, repeat 2, tracer on) [M]
Receipts `vectors/reports/rv64-m6-20261105/enqueue/ab1-{base,e1}-{daemon,windows}.json`. Load 11-25 (not quiet-host
quotable; single observations). All 8 requests byte-identical to the M5 default; fresh receiver accepted e1 (first of
each block).

| warm request (2nd of each block) | M5 control | e1 (3.1 + 3.2) |
|---|---:|---:|
| 26235156 request / recursion | 19.15 / 12.43 s | **18.11 / 11.51 s** |
| 24628607 request / recursion | 28.11 / 18.76 s | **27.01 / 17.67 s** |
| 24628607 blocking calls per node | 173.5 | **122.5** |
| launches per node | 5,167 | 5,167 (unchanged: hint-tape's lever) |

Replicates of the e1 behaviour (same code path, other binaries with the e2/e3 flag off; load 17-36):
warm 24628607 recursion 17.56 s (ab2-e2off) and 18.09 s (ab3-e3off, load 29-36); 26235156 10.93 / 11.24 s.

### 3.4 Tried and reverted: resident twiddles for outer trace commits (negative) [M]
Uploading each height's half-coset twiddles once into the outer immutable cache (borrowed under the commit's
request scope; a first version pinned them under a constant scope and was rejected by the block-end audit,
`ImmutableSetupStillBorrowed`, see `ab2-e2-failure-excerpt.txt`) is byte-identical and receiver-accepted, but
measured no gain against the same binary with the path off (`ab3-e3*`: warm 607 recursion 18.27 vs 18.09 s,
156 11.49 vs 11.24 s, load 15-36) and raised immutable-cache evictions (3,713 vs 3,331 on GPU0). Reverted.

Finding for the owner of the immutable budget (resident_batch manifest `combined_immutable_device_bytes`, 2 GiB):
the outer immutable cache THRASHES in the resident service: per GPU over 4 requests ~1,000-1,200 uploads and
~3,000-3,700 evictions at a full 2 GiB (`GPU_RESIDENT_SETUP` lines in the ab3 producer logs). Each miss is an
upload + host join inside `outer_source_main` (28 gaps of ~32 ms per 607 request). The 27 leaf classes x
0.2-0.5 GB FIXED forests + 0.15-0.43 GB schedules do not fit; class-keyed canonical leaves (canon-native) or a
larger budget are the levers.

## 4. What is not done here (precise)
- Device transcript for the outer prove (Fiat-Shamir on the GPU or `cudaLaunchHostFunc`): not started. The PCS
  part (OODS -> DEEP -> FRI -> decommit) already runs inside one native call with the device channel
  (`pcs_pipeline.cuh`); the host channel still drives MAIN/INTER/composition mixing in `Engine.prove`.
- CUDA graph per recursion class: not started; launches/node is dominated by the hint-tape assignment DAG
  (78%), which hint-tape replaces with ~11 fill kernels. Graph capture is worth doing after that lands.
- Transcript parity GPU vs CPU per class: not applicable yet (no device transcript change).
- Recursion kernel efficiency (ns per LDE cell): not touched.
- Composition (`resident_composition.zig`, no M6 owner on the pod) has the same lane-0/one-readback pattern
  (28 blocking calls/node, ~0.7 s of in-node host gaps per 607 request): same treatment as 3.1 recommended.
- Gates: syncs/node 122 (gate 10), launches/node 5,167 (gate 500), GPU busy ~40% (gate 70%): NOT met.
