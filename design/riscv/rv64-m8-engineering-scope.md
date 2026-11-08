# RV64 GPU prover: engineering scope from here (M8 onward)

Status: 2026-11-05. Baseline: `codex/rv64-cuda-ethereum` @ M6 (26ca20793) plus this branch, `codex/rv64-m7-integrate` @ 0c5e2b423.
It builds on `codex/rv64-4gpu-realtime-design` (`design/riscv/rv64-4gpu-realtime.md`, "the 4-GPU doc"), which holds the lever map, the budget model and the frontier research.
Labels: **[M]** measured, **[D]** derived from measured numbers, **[E]** estimate.

Current owner status (2026-11-06): **P0 gate PASS**. All 29 development
streams are reviewed/closed; 25 clean historical worktrees and 29 local branch
refs are removed, with pinned remote history retained. The full pod gate
builds and tests, matches both small-block proofs against 32 frozen artifacts,
gets two fresh CPU accepts, and passes all 19 required corpus cases. See
`m7-handoff/P0-CONSOLIDATION.md` and
`vectors/reports/rv64-m8-20261105/p0/summary.json`. No performance improvement
or exact memory pass is claimed. Default D2/coalescing, automatic arena,
one lane and security parameters remain unchanged.

**P1 in progress (2026-11-06):** the refreshed small-block composed stack
passes cold and warm with the pinned V2 runtime; both arms are byte-identical
and all four fresh CPU receivers accept. The headline interleaved run then
reproduced `NativePostGlobalDrainUnavailable` on the second fullstack service's
warm request. Its first completed pair was 12.690 s default versus 13.630 s
fullstack [M, single pair, not a final median]. All six proofs from completed
services have fresh CPU acceptance. The run stopped before 3+3 completion or
profiling. See `vectors/reports/rv64-m8-20261106/p1/refresh-summary.json`.

The first coset prototype passed units/build but was statically rejected: it
required a 4x domain, while the measured largest Blake roles use 2x. Its patch
and receipt are retained in `vectors/reports/rv64-m8-20261106/p1/rejected-coset-v1/`.
The next default-off full-domain column-packing candidate passed units/build,
and its completed cold proof was byte-identical and freshly CPU-accepted.
Its warm small-block request stalled until the 120 s watchdog [M]; headline
measurement was skipped. Actual requested arenas were 7.82 GB and 5.34 GB [M]
for 116 and 79 selected columns [M], versus 167 original columns [M]. These are
role allocations, not whole-node peaks. The remaining INTER commit admission
requested 25.30 GB against 23.09 GB capacity [D, model]; all completed proofs
were freshly accepted, while the failed warm request has no root. See
`vectors/reports/rv64-m8-20261106/p1/columns-v1-result.json`. No usable end-to-end
gain or exact per-node memory qualification is claimed. A second default-off
candidate reused owned INTER evaluations in place, passed units/build, then
failed its cold small-block request with `InvalidPcsBorrowPromise`: multiple
component leases violated PCS's contiguous sorted borrow contract. No candidate
root was produced; both baseline proofs were freshly CPU-accepted. See
`vectors/reports/rv64-m8-20261106/p1/inter-reuse-v1-result.json`. The corrective
revision generates one sorted INTER slab with a bounded scratch tail and keeps
the existing PCS checks. It passes units/build, completes both small-block
requests byte-identically, and has all four fresh CPU accepts [M]. Warm smoke
is 14.435 s baseline versus 14.897 s fullstack [M, unqualified correctness
walls with capture hashing]. The quiet headline 3+3 primary services completed:
median 12.332 s baseline versus 12.401 s fullstack [M, 0.56% slower]. Median
recursion fell from 5.538 s to 4.652 s [M], while native proving rose from
4.434 s to 5.116 s [M]. All 12 timed payload sets match and all 12 fresh CPU receivers accept [M]. The separate profiler first failed before READY with an Nsight
process-probe timeout. After correcting profiler preload/child ownership,
the baseline profile completed both requests, while the candidate completed
cold then stalled warm at INTER generation. Its required 23.153 GB exceeds
23.085 GB capacity [D, admission model]; it was stopped after 161.3 s [M].
All three completed profiled proofs are byte-identical and freshly CPU-accepted [M].
The baseline warm profile reports 10.584 kernel GPU-seconds [M] and 52.36%
after-native kernel busy [D, two GPUs; exclusive native end plus a 5 ms
uncertainty band]. The candidate warm request has no root. Its CUPTI records
also stop 12.856 s before the completed cold request ends [M], so its raw
helper GPU-seconds and completeness flags are invalidated by the retained
metrics audit. No complete candidate GPU-seconds/busy result is available.
Exact per-node peak also remains open. No matched request-time
gain or P1 exit is claimed. See
`vectors/reports/rv64-m8-20261106/p1/inter-reuse-v2-result.json`.
The full P1 checkpoint commit gate passes build, unit tests, both frozen
small-block proofs, both fresh CPU receivers, and all 19 corpus cases [M].
See `vectors/reports/rv64-m8-20261106/p1/CHECKPOINT.md`. The next candidate is a 32-column composition cache over unchanged root
groups. Its companion generator and CUDA module build on the pod, and both
exported parent/plan/code identities match [M, host identity checks only].
Role 4 uses eight groups and 126 fills for 116 columns [D]; role 5 uses five
groups and 79 fills for 79 columns [D]. The runtime passes all five unit targets and the production build [M].
Both small-block cold/warm requests match the paired baseline payloads and
capture SHA256; all four fresh CPU receivers accept [M]. Logs record 60
chunked role invocations and a 2.181 GB requested arena per affected role [M,
allocation size, not node peak]. The canonical headline attempt completed five services, then the final
candidate cold request failed with `NativePostGlobalDrainUnavailable` at
node 14 witness. Its admission demand is 28.622 GB against 23.085 GB
capacity [D, model]. There is no complete 3+3 median. All ten completed proofs passed fresh CPU verification [M]; the original
gate/profile controllers stopped before work. The independent preservation
gate passes build, unit tests, frozen-default proof parity, fresh CPU
receivers and all 19 corpus cases [M]; it does not qualify the failed
headline experiment. See `OUTER-CHUNKS-CHECKPOINT.md` in the P1 reports. No request-time gain, exact node-peak qualification or P1 exit
is claimed. See `outer-chunks-hypothesis.json` in the P1 reports.
The next prototype adds explicit-capacity compact eager Blake2s state
storage. Its companion builds, matches frozen eager and unchunked hashes
in 64 numerical cases across both GPUs, rejects 384 invalid calls, and
passes Compute Sanitizer with zero errors [M, kernel ABI tests only].
The default-off trace and PCS integration builds and passes all unit targets [M].
Its intended two-lane small-block cold request stalls at admission until the
120 s watchdog, without a root [M]; headline timing is skipped. The largest
logged INTER scratch falls from 3.825 GB to 2.953 GB [M, requested allocation],
but the remaining admission demand is 24.562 GB against 23.085 GB capacity
[D, model]. Both completed baseline proofs match the prior reference and
32 frozen default payloads, with fresh CPU accepts [M]. A separate one-lane
correctness diagnostic retains the other composed flags, 22 GiB arena, global
admission and physical guard; its two proofs preserve payload/capture identity
and are freshly CPU-accepted [M]. Both trace and late PCS compact paths activate
[M]. This diagnostic does not qualify the failed two-lane configuration.
The preservation gate passes build, units, frozen-default parity, fresh CPU
receivers and all 19 corpus cases [M; V04 size cap only]. The integrated
300-file archive is hash-verified and all 8,483 source hashes match [M].
No headline speed, exact node peak or P1 exit is claimed. See
`COMPACT-STATE-CHECKPOINT.md` and `stream-compact-state-hypothesis.json`
in the P1 reports. The read-only `pcs-phase-lifetime-audit.json` identifies
existing DEEP/FRI retirements and composition buffers retained beyond last use;
it changes no bound or admission behavior.

The phase-bound/direct-INTER candidate completes intended two-lane small proofs and the quiet headline 3+3 [M]: request median 13.465 to 13.131 s [M, 2.48% faster D], recursion 6.230 to 5.379 s [M], native proving 4.785 to 5.239 s [M]. All 12 primary proofs and four separate profile proofs match and pass fresh CPU verification; the full preservation gate passes [M]. Kernel-duration sum is essentially flat, 10.579 to 10.597 GPU-s [M]; occupied kernel union falls to 10.312 GPU-s [M]. After-native busy falls from 53.54% to 47.01% [D], below the exit requirement. Exact per-node peaks remain unmeasured. P1 remains open and defaults remain unchanged. See `INTER-CONTRIBUTIONS-CHECKPOINT.md` in the P1 reports.

Owner correction from the latest user instruction: **measure all 19 headline nodes by stage/lane on one lane before further footprint changes**, then calibrate the planner and fix the native regression with a single-lane composed comparison. Two lanes require measured <=11 GB peaks or calibrated two-node fit. The user now authorizes parallel engineering across disjoint files in the one worktree for P1, P3/P5 and P2/P4; GPU qualification remains ordered. Commit only compact summary JSON/Markdown under about 1 MB per checkpoint; retain raw artifacts outside Git with SHA-256 references. Existing raw receipts are scheduled for a follow-up removal, without history rewriting.

The timing preset
explicitly allows at most 0.5% cgroup CPU pressure in five idle intervals, with
zero throttling. Absolute-zero and 0.1% admission attempts are retained; they
refused idle services, and GPU inventory probes themselves caused pressure.
Probe pressure is recorded separately; background sampling pauses only during
admission. No prover feature has changed default.

---

## 0. The rule that matters most: one working tree

**All feature work is composed on one integration branch and one working tree: `codex/rv64-m7-integrate`, renamed to `codex/rv64-main` once consolidated.**

- A new feature lands there behind a flag, default off, and is measured **in the composed stack**, against the current default, before the next change lands.
- The work behind today's gains was spread across **29 remote branches with commits that never reached integrate**; see §7.
- Each was A/B-tested alone against a moving baseline, so nothing composed. Every measurement read "no win", and features that only pay off together (memory admission + footprint + 2 lanes + early recursion) were only run together at the very end.

**One integration owner, one tree, explicit file ownership:**
- **One integration owner coordinates the tree.** The latest user instruction permits parallel agents across explicitly disjoint files; shared files require coordination and GPU builds use frozen source.
- Today we had half-finished edits in one worktree, commits that depended on uncommitted files (`59864b2b3` imported an untracked `outer_progress_cost.zig`), and two sessions building the same fix.
- Parallel engineering follows explicit file ownership. Pod GPU runs remain serialized under the harness lock.

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

- **One canonical runner,** `scripts/rv64/rv64_m7_integration_stack.py`:
  - interleaved arms (baseline/candidate ×3), with medians and spread;
  - a quiet-pod gate;
  - byte parity and fresh receivers checked *after* timing.
- **Report critical-path and GPU-seconds alongside wall time:** native window, recursion after native, tail, GPU busy, per-node peak memory.
- **Proof-size-only and sub-noise changes** (for example −5% queries) are not timed for latency; record their bytes and move on.
- **A change counts only when measured in the composed default.** No isolated-branch speed claims.

---

## 5. Engineering practice

Standard practice, applied consistently:

1. **One tree, one integration owner.** One integration branch, no additional worktrees or feature branches. Parallel agents may edit disjoint assigned files under the latest user instruction; freeze source before builds and GPU qualification.
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

Run the items as one sequence on one tree. Each step's exit is the entry condition for the next. Steps that don't touch the same code (for example, a Poseidon2 kernel benchmark on the pod) may run as *measurements* in parallel, while engineering may proceed in parallel across assigned files. Qualification and promotion remain ordered.

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
