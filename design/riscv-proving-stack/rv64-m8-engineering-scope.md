# RV64 GPU prover: engineering scope from here (M8 onward)

Status: 2026-11-05. Baseline: `codex/rv64-cuda-ethereum` @ M6 (26ca20793) plus this branch, `codex/rv64-m7-integrate` @ 0c5e2b423.
It builds on `codex/rv64-4gpu-realtime-design` (`design/riscv-proving-stack/rv64-4gpu-realtime.md`, "the 4-GPU doc"), which holds the lever map, the budget model and the frontier research.
Labels: **[M]** measured, **[D]** derived from measured numbers, **[E]** estimate.

Current owner status (2026-11-06): **P0 gate PASS**. All 29 development
streams are reviewed/closed; 25 clean historical worktrees and 29 local branch
refs are removed, with pinned remote history retained. The full pod gate
builds and tests, matches both small-block proofs against 32 frozen artifacts,
gets two fresh CPU accepts, and passes all 19 required corpus cases. See
`m7-handoff/P0-CONSOLIDATION.md` and
`vectors/reports/rv64-m8-20261105/p0/summary.json`. No performance improvement
or exact memory pass is claimed. Default D2/coalescing, automatic arena,
one lane and security parameters remain unchanged. P1 is next.

---

## 0. The rule that matters most: one working tree

**All feature work is composed on one integration branch and one working tree: `codex/rv64-m7-integrate`, renamed to `codex/rv64-main` once consolidated.**

- A new feature lands there behind a flag, default off, and is measured **in the composed stack**, against the current default, before the next change lands.
- The work behind today's gains was spread across **29 remote branches with commits that never reached integrate**; see §7.
- Each was A/B-tested alone against a moving baseline, so nothing composed. Every measurement read "no win", and features that only pay off together (memory admission + footprint + 2 lanes + early recursion) were only run together at the very end.

**Single-owner, single-tree practice:**
- **One engineer or agent at a time owns the tree.** No parallel agents on the same codebase.
- Today we had half-finished edits in one worktree, commits that depended on uncommitted files (`59864b2b3` imported an untracked `outer_progress_cost.zig`), and two sessions building the same fix.
- Parallelism belongs in *experiments* (pod runs, measurement), not in concurrent code edits.

---

## 1. Where we are

| 24628607 (headline), warm, 2×RTX 5090 | M3 | M6 | **M7 default (D2 + truth coalescing)** |
|---|---:|---:|---:|
| request | 51.1 s | 17.1 s | **12.9 s** (single profiled run) |
| recursion stage | 27.3 s | 10.3 s | **5.7 s** |
| recursion cells | 53.4 G | 35.8 G | **21.7 G** [D, exact census] |
| kernel GPU-s | — | 14.05 | **10.58** |
| leaves / nodes | 17 / 33 | 17 / 23 | **14 / 19** |
| tail after last leaf | — | 2.74 s | **1.72 s** |
| root proof | 708 KB | 709 KB | 750 KB |
| device peak | — | 31.5 GB | 31.6 GB |

- 26235156: 10.5 s.
- Root-only verify: 1.4 s.
- Committed native work per gas is already about 2× below ZisK's. Our recursion is what puts us behind (4-GPU doc §2.2).

**The combined stack** (22 GiB arena + global admission + recursion sessions + 2 lanes per GPU), state as of 0c5e2b423:
- **Cold request:** it now produces a complete root. All 30 artifacts are byte-identical to the baseline [M].
- **Fixed on the way:**
  - retirement-aware memory futures, which cleared the fold-9 bound of 30.30 GB against 23.09 GB;
  - the runtime now enforces the 28 GB whole-process gate, not the 4 GiB planning split.
- **Warm request:** fails at fold 13 (`NativePostGlobalDrainUnavailable`) under `capacity_pressure`.
- **Cold wall time:** 66.4 s against about 28 s for the baseline (single run, loaded pod).
- **Diagnosis [D]:** one recursion node peaks at about 22 GB live, so a second lane has no room in a 22 GiB arena. Admission turns concurrency into waiting.
- **Conclusion:** concurrency is blocked by **per-node memory footprint**, not by scheduling.

---

## 2. Priorities, in order

Each item lists the goal, the work, the gate, and the expected effect [E] on 24628607 at 2 GPUs.

### P0. Consolidate onto one tree (first, before any new feature work)

- Merge or close every branch in §7 into `codex/rv64-m7-integrate`. Branches that are only receipts are merged for the receipts, and branches that are superseded are closed with a note.
- Keep the current default preset: D2 + coalescing, automatic arena, one lane.
- Delete dead flags and experiment-only code paths. Prefer one obvious path per stage.
- Write a single `scripts/rv64_gate.sh` with these steps, in order:
  1. build;
  2. unit tests;
  3. small-block prove;
  4. byte identity against the frozen default;
  5. fresh CPU receiver;
  6. negative corpus.

  Nothing is pushed unless this passes. See §5.
- Gate: one tree, default byte-identical to today's accepted D2/coalesced receipts, gate script green.

### P1. Per-node GPU memory to ≤ ~11 GB (the enabler for every concurrency win)

**Why.** Two lanes per GPU, early leaf work during native, and 2→4 GPU packing all need a node to fit in about half the 22 GiB arena. Today's peak live is about 22 GB per node [M].

**Work**, largest allocation first, using the `GPU_DEVICE_PEAK` and `OUTER_CLASS_PROGRESS` lines already emitted:
- **Stream the INTER trace commit** (304 columns, 4.7 GB coefficients + 3.8 GB scratch on node 13 [M]) and the MAIN commit, keeping only one chunk of LDE plus one tree bank live (the ZisK streaming-commit pattern).
- **Chunk-bound the composition and GKR workspace,** so workspace scales with the chunk size, not the instance. The 15 GB modelled outer GKR workspace has to become a bounded constant.
- **Make retirement immediate:** free each evaluation set at its last use, which the retirement-aware futures now allow.
- **Shrink long-lived caches** (2.5–3.1 GB live-long [M]) to a byte budget per class.

**Gate:** exact process peak per node ≤ 11 GB on both dev blocks, byte-identical.

**Then re-run the composed stack** (it is now functional) with 2 lanes and early leaf admission. Expected: recursion 5.7 s → 3.5–4 s, with a measured rise in recursion-window GPU busy above today's ~54%.

### P2. Poseidon2 recursion leaves (the biggest cell lever)

- **Measured so far:**
  - full CPU leaf 554.8 M → **106.3 M padded cells (×0.19)** with Poseidon2-M31-W24; mixed variant 247.8 M [M];
  - GPU hashing 11.7–13.4× slower than Blake2s per element [M].
- **Judge it on net GPU-seconds:** about +0.5–1.5 GPU-s of native hashing against several GPU-s of recursion removed [D].
- **Work:**
  - one focused session on the Poseidon2 W24 kernel: fused rounds held in registers, one thread or warp per permutation, row packing;
  - then the all-Poseidon native profile;
  - then the in-circuit verifier;
  - then outer/fold/root, as stages S2–S4 in 4-GPU doc §7.4.
- **Smaller nodes help P1 directly.**
- **Gate:** fresh receiver, corpus, net GPU-s, and request time on the composed tree.

### P3. The capture + native window (7.0 s at 31% busy, now the largest chunk)

- **Early native stage 1, done properly.** Compute each segment's LDE and Merkle root as soon as its records are captured, then mix the roots into the transcript in the original order after inventory.
  - Allocate in the final proof scope (no promote-and-copy), seal content once at capture, and admit all segments, not only CPU0.
  - The first implementation copied 224 MB, re-hashed metadata (≈400 ms) and covered CPU0 only, and measured negative [M]. Don't repeat it.
  - Gate: stage-1 start ≤ 1.4 s (from 2.55 s) [M baseline].
- **GPU witness widening** from compact records (17.5 B/row already landed) to all native columns on device. Target ≤ 80 B per instruction host-to-device.
- **Native GKR v2-gkr in production** (CUDA cap of 128 oracles; source-bound mass gate). Native lookup cells ×0.5 [D].
- **Expected:** native window 7 s → 4–4.5 s.

### P4. Fewer leaves

- **Keccak-shard family batching:** early and late batches at b16 q27 p20 (the policy exists on `keccak-batches` and needs GPU qualification).
- **CPU23 canonical rungs** once clock/range authority closes. On the largest block this takes CPU leaves 49 → ~25.
- Recursion time tracks leaf count (fit R² 0.997, 4-GPU doc §1.2).

### P5. Large blocks and 4 GPUs

- **Parallel capture:** fast pass with checkpoints, then parallel traced replay. Capture is 16 s serial on 26235159; the model fails without this (4-GPU doc §1.5).
- **4-GPU placement:** key affinity, root-critical-chain priority, comb aggregation (a running accumulator).
- **One profiled scale probe per milestone** on 24697070, then the ordered scale-up.

### P6. Later

- Proof size: two-stage compression, ≤120 KB.
- q102 / grinding.
- The device Fiat–Shamir residue: the PCS path is already on GPU; four host draws remain.
- The megakernel (4-GPU doc §8), only once concurrency is the remaining lever and nodes fit.

**Expected path [E]:**
- P1 + P3 + P4: 24628607 from 12.9 s to about 8 s on 2 GPUs.
- With P2: about 5–6 s on 2 GPUs.
- With 4 GPUs and P5: the 4-GPU doc's central model of about 3 s on the headline block and about 6 s on 26235159.

---

## 3. End to end without wasted time

Every request second that isn't proving should be removed:

- **Resident service only for timing:** no per-request process start, image load or class build.
- **Install-time artifacts:** native FIXED per strict class, recursion PP/plans/templates and VK tables persisted per image. A never-seen block's first request should cost ≤ 3 s of setup, against 8.6–10.7 s today [M].
- **Streaming overlap:** capture → native → leaf → fold → root (→ compress) as one pipeline, so latency is the slowest stage plus the tail.
- **No host round trips on the GPU critical path:** challenges and claims stay on device; one sealed readback per node.
- **Bounded host memory:** RSS ≤ 20 GiB, with no unbounded caches.
- **The receiver is off the request path.** Root-only verify at 1.4 s [M] runs asynchronously.

---

## 4. How we measure

- **One canonical runner,** `scripts/rv64_m7_integration_stack.py`:
  - interleaved arms (baseline/candidate ×3), with medians and spread;
  - a quiet-pod gate;
  - byte parity and fresh receivers checked *after* timing.
- **Report critical-path and GPU-seconds alongside wall time:** native window, recursion after native, tail, GPU busy, per-node peak memory.
- **Proof-size-only and sub-noise changes** (for example −5% queries) are not timed for latency; record their bytes and move on.
- **A change counts only when measured in the composed default.** No isolated-branch speed claims.

---

## 5. Engineering practice

Standard practice, applied consistently:

1. **One tree, one owner at a time.** One integration branch; topic branches only if they merge back before the next change starts. No parallel agents editing the codebase; parallel work is runs and measurements.
2. **Every commit builds and passes the gate script.** Never commit code that depends on uncommitted files. Push at the end of each working block.
3. **Small, reviewable commits** with the measured result in the message (headline numbers plus the receipt path).
4. **Feature flags default off, and composed.** A flag is either promoted to default once its matched timing is positive, or deleted. Test the flags that matter together, in one tree.
5. **Measure the critical path first, then design for it.** Before building, write down which measured seconds the change removes; after building, show it.
6. **First matched timing before more machinery:** each change reaches a matched timing in the composed default before any further gates or infrastructure are built for it. If it isn't positive, write down why before continuing.
7. **Keep correctness gates proportional:**
   - byte identity + fresh receiver for scheduling changes;
   - a named profile + soundness note + tamper corpus for proof-format changes;
   - no extra qualification layers beyond those without a specific risk.
8. **Simple first.** Prefer removing work (smaller nodes, fewer leaves) over coordinating it (permits, custody, ledgers). Admission machinery exists now; don't grow it until P1 makes concurrency possible.
9. **One milestone document** with targets and status, updated as results land, plus the progress ledger.
10. **Careful pod operations:**
    - one GPU lock;
    - no `pkill -f` on patterns that match your own shell;
    - unique run directories per attempt;
    - prune build and run copies after each milestone (disk has filled three times).

---

## 6. Execution order

Run the items as one sequence on one tree. Each step's exit is the entry condition for the next. Steps that don't touch the same code (for example, a Poseidon2 kernel benchmark on the pod) may run as *measurements* in parallel, but code changes land one at a time.

| step | work | exit |
|---|---|---|
| 1 | P0 consolidation + gate script | one tree; default byte-identical; gate green |
| 2 | P1 footprint: INTER/MAIN streaming commit, bounded composition/GKR workspace, immediate retirement | node peak ≤ 11 GB; composed stack (2 lanes) warm 3+3 run on 24628607 |
| 3 | P3 early stage 1 redone (compute early, mix in order, no copy, one seal, all segments) | stage-1 start ≤ 1.4 s; matched timing in the composed default |
| 4 | P2 Poseidon2 kernel pass + native profile S2 | GPU-s per block measured; go/no-go on net GPU-s |
| 5 | P4 Keccak batches GPU qualification, then CPU23 rungs | leaves 14 → ~11, then fewer |
| 6 | P5 parallel capture + 4-GPU placement + scale probe | 26235159 measured on 4 GPUs |

---

## 7. Branches to consolidate (commits not yet in `codex/rv64-m7-integrate`, 2026-11-05)

| commits | branch |
|---:|---|
| 53 | codex/rv64-m7-native-gkr |
| 47 | codex/rv64-m7-outer-gkr |
| 8 | codex/rv64-m7-owner-cleanup |
| 8 | codex/rv64-m7-device-fs |
| 7 | codex/rv64-m7-rc-workspace |
| 7 | codex/rv64-m7-rc-sparse |
| 5 | codex/rv64-m7-stage1-cost |
| 5 | codex/rv64-m7-admission |
| 4 | codex/rv64-m7-native-witness, graph-checkpoint, early-recursion, device-fs-p2, callback-retire, blake-inputs |
| 3 | codex/rv64-m7-projection-cost, keccak-batches, device-lanes-checkpoint, device-graph |
| 2 | codex/rv64-m7-device-fs-p1, critical-chain |
| 1 | codex/rv64-m7-native-inter-retire, native-capture, memory-census, keccak-stream, graph-shape-checkpoint, fold-expanded, fold-circuit, cpu-prestage, capture |

Several of these hold *WIP checkpoint* commits made on 2026-11-05 to preserve uncommitted work. They are unqualified, so review them before merging. After P0, delete merged branches and their worktrees under `~/Coding/ge-wt/rv64-m7-*`.
