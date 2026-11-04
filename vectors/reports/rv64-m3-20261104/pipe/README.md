# Stream pipe: pipelined recursion with host prep ahead of the GPU lanes (M2a)

Branch `codex/rv64-m3-pipe`, based on `fbb6c6c76`. The reported code is `40e4860d5`. Hardware: 2x RTX 5090 on pod
`cps13bvat3xhdo`. All runs use the accepted runtime `library.so` (`25295868…`), profile `conjectured128_b2_q108_p20_fold4`
and the full15 harness requests. Every number here is **measured** from one ordered run. These are not medians; repeat
runs of the same config differ by about ±1 s.

## Result (block 24628607, 2 GPUs)

| Config (same driver binary `92d24751…`) | Request | Recursion | Native prove | Native verify | Capture | Host sys CPU | Peak RSS |
|---|---:|---:|---:|---:|---:|---:|---:|
| Lane path, page-allocator budget child (= accepted config) | 98.02 s | 63.62 s | 10.33 | 5.66 | 5.11 | 85.5 s | 13.9 GiB |
| Lane path, smp budget child | 78.91 s | 54.94 s | 6.03 | 1.56 | 3.41 | 58.1 s | 14.2 GiB |
| **Pipelined + smp child (reported)** | **57.88 s** | **32.75 s** | 6.06 | 1.67 | 3.71 | 74.4 s | 22.9 GiB |

The accepted reference run measured 98.92 s / 63.62 s. The lane-path control of this binary reproduces it: 98.02 s / 63.62 s.

Attribution, all measured on the same binary:
- Pipelining alone, with the allocator held fixed, cuts recursion from 54.94 to 32.75 s (−22.2 s).
- The allocator change alone, on the lane path, cuts recursion from 63.62 to 54.94 s. It also cuts native prove, verify and capture together by about 10 s.

Block 26235156: unmodified head gives 64.90 s request / 41.03 s recursion. The reported pipeline gives **38.46 s / 21.33 s**.

**Parity.** Every run is byte-identical to the accepted-v7 controls in `source-authority.json`: all `*.bin`, `bundle.json`, every leaf, fold and root `.proof`, and `tree.json`. The change is scheduling-only.

## GPU busy

Two measures, both measured:

| Measure | Lane path | Pipelined | Notes |
|---|---:|---:|---|
| Lane device-stage occupancy (`pipeline.json`) | not recorded | 0.72 | Wall time a lane spends in the device stage (precommit, authority, device proof), divided by 2 × DAG wall. Upper bound on kernel busy. |
| Summed outer CUDA event spans / (2 × recursion wall) | 21.1 / 127 = 17% | 21.1 / 65.5 = 32% | Spans: PCS device 7.46 s, composition 5.78 s, assignment 7.89 s. Lower bound. |

The leaf phase is now device-stage bound: the ready queue holds 4–8 s of prepared leaves (`wait_rdy` in `pipeline.json`).
The rest of the recursion wall is:
- the 5-level fold tail: about 2.2 s per level (prep 0.95 + device 1.1 + finish 0.1), with only one GPU usable;
- the ~1.3–2.0 s ramp before the first device start.

## What changed (architecture)

1. **Three-stage nodes** (`om31_native/outer_wrap.zig`: `prepareHost`, `proveDevice`, `finishProved`). The monolithic
   `wrapGraphOrLoadWithFactory` is split into the same operations, in the same order, on the same graph:
   - **prep** (any host thread, no device): graph, exact `padToTargets`, PP columns, the root-independent device authority (pinned AIR parse, layout, bind), and the device assignment plan, pack and hash.
     - PP columns plus the authority run on a side thread, concurrently with the plan. Both only read the padded graph.
   - **device** (one lane per GPU, one active proof per device, as before): FIXED precommit, `DevicePrepared.finish(root)` → authority, staged-plan handoff, device proof.
   - **finish** (host pool): digest check, fresh native `Outer.verify` capture, durable publication, prover-data retirement, DAG completion.
2. **Assignment plan off the single-active section.**
   - `Factory.prepare_host`, `stage_host` and `unstage_host` were added (`device_prove.zig`).
   - `outer_source.Context.prepareHost` builds the exact `Assignment.Prepared` with no mutex and no device. `stageHost` moves it into the device Context (`staged`, `staged_graph`). `prepareImpl` consumes it only for the identical graph pointer: a mismatch is an error, never a silent substitution.
   - `Prepared.rebind` re-resolves kernel entry points against the adopting device's library.
3. **Pipelined executor** (`execution_wrap.zig`, `Pipelined`).
   - 8 host workers share a 24-worker prep `WorkPool`. 2 device lanes keep their own pools.
   - Leaves are prepared eagerly, bounded by prep-ahead (6 leaves taken but not yet on a device).
   - Folds are prepared as soon as both children publish.
   - The device lanes pick the widest ready parent first, then the lowest leaf id.
   - Admission uses the unchanged `Dag.Queue`: same 17-slot authority limit, plus a new parent-only `takeFiltered`.
   - `pipeline.json` records a per-node timeline.
4. **Root metadata check once, concurrently.**
   - The lane path runs `Root.check` before dispatch and again before publication.
   - The pipelined path runs the identical check once on a side thread during the DAG. It must succeed before `root.proof`, `tree.json` or `report.json` are written.
5. **Allocator** (`resident_batch.zig`, review M1 1a).
   - The combined host budget's child is now `std.heap.smp_allocator`, not `page_allocator`.
   - With the page allocator, every allocation under 256 KiB was an mmap under the budget mutex. That made the 8 parallel preps 8–10x slower (run p1: leaf graph 8–11 s instead of ~0.8 s).
   - Byte accounting against the same 48 GiB limit is unchanged.

Selectors: `STWO_RV64_RECURSION_PIPELINE=0` restores the lane path, and `STWO_RV64_HOST_BUDGET_PAGE_CHILD=1` restores the page child.
Tuning knobs: `STWO_RV64_RECURSION_HOST_WORKERS` (default 8), `_PREP_POOL_WORKERS` (default 24) and `_PREP_AHEAD` (default 3 × lanes).

## Soundness argument

- Nothing a proof or verifier depends on changes:
  - node ids, Fiat–Shamir ordinals, the binary-carry tree, graphs, padding targets and PP columns;
  - the FIXED precommit, authority identity, assignment plan bytes and device proving calls;
  - the native verification of every node before durable publication;
  - the children-retained-until-parent-publishes rule;
  - the final fresh `Prove.verify` of the root, and `Root.check` before root publication.
- Only the executing thread and the time at which each operation runs change.
- The device-authority split computes the same fields and the same identity hash (`identityOf`, shared with `initImpl`). The root comes from the same trusted device precommit.
- The staged plan is bound to its graph by pointer identity. Any mismatch is rejected.
- The one behavioral difference is fail-fast timing: an invalid native bundle is now rejected when the concurrent `Root.check` joins, not before the first leaf. It is still rejected before anything is published.
- Byte parity on both development blocks is the empirical check. Acceptance by the independent receiver carries over from the accepted-v7 controls through byte identity. See `receiver-*` below if present.

## Memory (integration note for stream mem)

- A prepared node that is not running owns **host memory only**: graph, PP, authority and plan. It never holds a device lease. Device admission is unchanged: `stage_host` requires no active proof, and precommit and `prepareImpl` keep the single-active checks.
- Host budget peak (scheduler.json): 7.5 GB → 18.9 GB of the 48 GiB limit.
- Process max RSS: 13.9 → 22.9 GiB.
- `peak_authority_slots` reaches 16 of 17. A new admission test covers concurrency up to 16 active nodes under the 17-slot limit (`ready_dag.zig`).

## Negative and neutral results

- p5, a ramp that limits prep to one leaf per lane until the first device start, moved the first device start from 2.0 to 1.33 s. The first device stage got slower, and the net change was +0.75 s, within noise. It was not kept.
- `recursion_worker_budget` 16 (8 per lane) gave 32.62 s against 32.75 s, within noise.

## Next levers (estimates, not measured)

- **Device stage host work**: 46.9 s of lane device-stage wall against 21.1 s of CUDA event spans. The assignment launches are enqueue-bound (`levels_enqueue` 7.76 s ≈ stream 7.89 s), which is narrow runs, M2d. Two proofs per GPU need device-memory admission (stream mem, M2b).
- **Fold tail**: about 0.64 s per level is the serial `witness_plan` build. It is on the critical path 5 times.
- **Streaming native proofs into the recursion ready queue** is not done. Leaf graphs need the sealed stage-one manifest, and `runImpl`'s inventory and words need the full bundle. That requires splitting `C.produceWithAuthority` completion and the manifest seal. Estimated −2 to −3 s (first-device ramp plus native verify overlap).

## Files

- `<block>-<run>.json`: per-run receipts. Each holds stages, rusage, parity, and the full per-node `pipeline.json` timeline.
- Run order: base-head, p1 (pipeline with the page child), p2 (+ smp), p3 (+ concurrent PP/authority), p4 (+ concurrent root check; reported), p5 (ramp; rejected), A/B lanes-page and lanes-smp, p4-workers16.
