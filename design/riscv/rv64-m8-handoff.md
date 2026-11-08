# RV64 GPU prover: M8 handoff (2026-11-07)

Read the active-work checkpoint first. The original M8 sections below remain
historical context and acceptance requirements for future performance claims.

## Active work — GPU hygiene (2026-11-08, in progress)

The active phase is consolidation and productionisation under the
[resource and development contract](rv64-gpu-hygiene.md). It includes measured
subtractive cleanup and the ordered GPU-native promotion gates: canonical
3+3 against default on 24628607 and 26235168, new-block setup-miss, the native
15-block basket, then the default flip and held legacy deletion. Subsequent
performance work starts with late feeding and section 5 below. Historical
estimates do not establish a qualified speedup.

The [current receipt](../../vectors/reports/rv64-productionisation/current.json)
is the status authority. There is one canonical checkout at
`/Users/theodorepender/Coding/stwo-zig`; the
[archive index](rv64-archive-index.md) records published historical refs,
off-laptop recovery and the completed literal-list branch retirement.

The candidate is `codex/rv64-gpu-hygiene`. Initial four-gate evidence is in
[checkpoint-7.json](https://github.com/teddyjfpender/stwo-zig/tree/archive/pre-restructure-20261108/vectors/reports/rv64-gpu-hygiene-20261108/checkpoint-7.json)
and the linked pod receipts. All four bounded gates now pass: default and
native paths on 24628607 and 26235156, each with frozen cold/warm parity, two
fresh isolated CPU accepts and complete semantic coverage of the selected
19-case corpus. Native 24628607's shared CUDA activity analysis is complete:
two final ordinary readbacks, zero private job-slab readbacks, no request event
creation, seven capture-release callbacks and 48 complete native enqueue ranges
per request. Peer transport remains separately counted. The hardware source snapshot
was unchanged throughout. Checkpoint 7 separately records two final EOF-only
Python formatting fixes, AST equivalence and the repeated 178-test Python
gate. These are correctness and ownership observations,
not a controlled latency comparison.

The broader productionisation goal remains incomplete: the static tier is not
green. The 150 unreachable scripts and their exclusively historical consumers
are deleted in the pending first subtraction batch; its validation status is
in the current receipt. Inherited oversized owners remain explicit work.
The [delivery audit](https://github.com/teddyjfpender/stwo-zig/tree/archive/pre-restructure-20261108/vectors/reports/rv64-gpu-hygiene-20261108/delivery-audit.md)
records the open completion gates.

The historical host-only owner-boundary follow-up is in
[checkpoint-8.json](https://github.com/teddyjfpender/stwo-zig/tree/archive/pre-restructure-20261108/vectors/reports/rv64-gpu-hygiene-20261108/checkpoint-8.json).
It separates the installed recursion registry from request-job custody and fixes
pin teardown order and failed-registration state. The regressions failed before
the fixes and pass afterwards: 105 focused tests and 305 broader host tests
(with one skipped), plus actual check-only execution and 16 routing tests.
These counts overlap. The current delivery subsequently passed default and
native gates on 24628607: 39 frozen artifacts per cold/warm proof, two fresh
CPU accepts and the complete selected 19-case semantic corpus per gate. The
current receipt pins the shared source manifest, runtime and binaries. This
extends bounded correctness evidence to this follow-up; it does not qualify
the canonical comparison or basket. The source audit still has 138 failing
paths, with no new baselines or ceiling changes. Hosted CI and the broader
Python suite retain unresolved failures, recorded in the current receipt.

No default promotion or new speed/physical-peak result has been established.
Global formatting and targeted CI contract tests passed at the initial
checkpoint, while repository-wide provenance and source-layout debt remains
explicit in the current productionisation receipt.
Do not suppress those checks or call the repository-wide static tier green.

## Continuation checkpoint — 2026-11-08 02:35 UTC

The original handoff below records the state at 2026-11-07. This checkpoint
supersedes its GPU-native completion and install-failure statements; its
remaining acceptance and architectural requirements still apply to the
historical performance/production objective described there.

- **[M] GPU-native now completes cold and warm requests on block 26235156.**
  `gn-bind/gate-28/gate.json` is PASS: build and host units, frozen artifact
  parity (32/32 twice), and two strict fresh CPU receiver harnesses accepted.
  The rejection harness reports 19/19, with an explicit limitation:
  `V04-cross-block-root` rejects with resource `FileTooBig`, not a semantic
  proof rejection. Source and receipt hashes are in
  [checkpoint-0130.json](https://github.com/teddyjfpender/stwo-zig/tree/archive/pre-restructure-20261108/vectors/reports/rv64-m8-20261107/gn-finish/checkpoint-0130.json).
- **[M] Current default gates pass on both development blocks.** Gates 26
  and 27 preserve frozen parity (32 and 39 artifacts respectively, twice
  each) and two fresh receiver checks each. Gate 26 has the same V04
  resource limitation; gate 27 has no nonsemantic rejection.
- **[M] Block 24628607 now completes both native requests.** Gate 35 is PASS:
  frozen parity (39/39 artifacts twice), two strict fresh CPU receiver
  harness accepts and the 19-case corpus (no nonsemantic rejection). Correctness-run request walls are 10.458 and 10.710 s
  [M], excluding 145.197 s initialization [M]. These are not canonical
  performance results or production new-block latency.
- **Memory changes:** shared canonical twiddle suffixes reduce logical
  persistent words by 273,821,696 bytes per GPU [D]. Install-only truth
  probes replace the estimated guard with measured allocation high-water
  plus the maximum compact span. The batch pipeline now applies the ordinary
  pipeline's pair-fit check before staging a neighbour. Both completed
  requests defer one neighbour on GPU 1 [M], through device-event ordering,
  with one driver host wait and two D2H transfers per request [M]. These
  counters are not a CUDA API census or physical per-node peak measurements.
- **Current native gate 36 on 26235156 is also PASS [M]:** 32/32 frozen
  artifacts twice, two fresh CPU receivers, and the 19-case harness, with
  V04's resource rejection limitation. Gates 35/36 use the same pinned driver
  SHA-256 `72cf8b9cd3435c20ce812d231fac8de049ec91523f736528b3b82b9f7e95efd3`.
  Default gates 37/38 also passed. Host run 21 passes 744
  tests, with 16 skipped [M].
  [Checkpoint 0235](https://github.com/teddyjfpender/stwo-zig/tree/archive/pre-restructure-20261108/vectors/reports/rv64-m8-20261107/gn-finish/checkpoint-0235.json)
  records receipts and source freezes.
- **Benchmark hygiene [M]:** 42 Python tests pass on Python 3.12. Offline
  replay of the completed native run discards its nested legacy install
  marker and produces exactly two request rows. Driver counters and event
  spans stay separate from unavailable stage partitions. Profiling may use
  a separate raw-trace filesystem through `--nsys-root`, preserving the
  standard per-run `nsys` link. Exact-commit gate 39 passed; core checkpoint
  `0941244f0` is pushed to integration, the PR branch and the original stream branch.
- **PCS retirement falsifier [M]:** the source-built experimental addon and
  control each pass 99 tests (1 skipped), PCS image parity, and a candidate
  memcheck run with zero errors. Both allocation-side high-waters are
  identical between arms. The prototype is set aside as a saved patch;
  P1 and end-to-end performance remain open. See
  [the negative receipt](https://github.com/teddyjfpender/stwo-zig/tree/archive/pre-restructure-20261108/vectors/reports/rv64-m8-20261107/gn-finish/pcs-retire-1/result.json).
- **No new performance qualification.** Core checkpoint `0941244f0` is
  pushed and default-off. The retained native profile has two fresh CPU
  accepts [M]. The guarded canonical comparison failed during class
  construction (`CudaAllocationFailed`); it produced no qualified ratio. Canonical
  interleaved timing, warm-request Nsight, the basket, new-block setup cost,
  whole-node graph replay and the larger architectural steps remain open.
  Same-block setup-excluded request times do not establish production
  new-block latency. The user replaced that campaign with the
  [GPU hygiene and developer contract](rv64-gpu-hygiene.md); do not resume
  the previous performance scope automatically. Keep the full scope in
  [progress.json](https://github.com/teddyjfpender/stwo-zig/tree/archive/pre-restructure-20261108/vectors/reports/rv64-m8-20261107/gn-finish/progress.json).

**Labels:** [M] measured, [D] derived from measured numbers, [E] estimate.
**Hardware:** one RunPod pod `rv64-resident-2x5090` (id `cps13bvat3xhdo`; 2× RTX 5090 32 GB, sm_120, PCIe Gen5 **x8** ≈ 24.6 GB/s per GPU; 48 vCPU; 80 GB disk).
**Branches named below are on origin.**

---

## 0. Where things stand

### Goal (unchanged)

| Target | Today | Status |
|---|---|---|
| 24628607: 12.9 s → ≤ 5 s on 2×5090 | **11.64 s** warm [M] | not met |
| 26235159: ≤ 10 s on 4×5090 | never measured | not met |

### Landed: PR #314 head `codex/rv64-cuda-ethereum` = integrate `codex/rv64-m7-integrate`, all gates byte-identical to the frozen D2 golden

- **T1–T10 kernel and capture work.** T5/T7/T8/T9 are on by default. 24628607 warm request went 12.869 → 11.644 s (−9.5%) and kernel time 10.61 → 8.48 GPU-s (canonical 3+3) [M]. Native prove is 3.82 s and recursion 5.44 s.
  - Receipt: `vectors/reports/rv64-m8-20261106/opt-combined/`.
  - T10 (narrow capture recorder, `STWO_RV64_M8_CAPTURE_RECORDER`, default off): 12.914 → 12.600 s [M].
- **Source-built default runtime** (lib `25d0e62f`), so the default flips actually run in gates.
  - Receipt: `.../m-runtime/`.
  - Build recipe: `.../opt-combined/compose_image.py` plus `scripts/rv64/rv64_m8_native_relink.py`.
  - The old frozen-line relink no longer reproduces: 4 objects are gone, 6 have been overwritten.
- **`STWO_RV64_M8_TRUTH_SPLIT` (default off).**
  - The D2 coalesced-truth profile refused 9 of the 15 basket blocks (`OneTruthPerFamilySourceCapacity` ×5, `V3TruthShapeExceeded` ×4).
  - With the flag, those blocks prove and fresh receivers accept 18/18.
  - Receipt: `.../p-truth-split/`.
- **bench15-1, default path, 6/15 blocks.**

  | Block | Warm s [M] |
  |---|---:|
  | 26235156 | 9.55 |
  | 24647140 | 11.46 |
  | 24628607 | 11.77 |
  | 25229957 | 12.51 |
  | 24628608 | 17.03 |
  | 24697070 | 25.14 |

  - 0.262× of M3 on those six blocks; GPU busy 34–37%.
  - Receipt: `.../bench15/` on `codex/rv64-m8-gpu`.

### GPU-native (the M8 architecture)

- **Branch:** `codex/rv64-m8-gn-bind` @ `7bbe1c5c0`, which is also this handoff branch's base.
- **Pieces merged in:** gn-shape, gn-pack, gn-s2, gn-node, gn-truth.
- **Flags:** `STWO_RV64_M8_JOBS=1 STWO_RV64_M8_GPU_NATIVE=1`, both default off.
- **Gates:** default gates and the `JOBS=1` gates pass byte-identical on 26235156 and 24628607 (gn-bind gates 7, 8, 9) [M].
- **It has never completed a request.** Details in §1.

### M9 prep (design and prototypes only, nothing wired into requests)

- **Finding:** no 2×5090 lever set reaches the owner's >60% cut. The reviewed best central sets are −43% to −48%, and the most aggressive set (column stacking) is −58%. See §4.
- **Docs carried on this branch** (`design/riscv/`): `rv64-m9-plan.md` (rev 4), `rv64-m9-io-streaming.md`, `rv64-m9-frontier-gap.md`, `rv64-m9-segment-shape.md`, `rv64-m9-native-cells.md`, `rv64-m9-recursion-arch.md`, `rv64-m9-proof-params.md`.
- **Receipts:** under `vectors/reports/rv64-m9-prep/` and `vectors/reports/rv64-m9-io-design/`.

---

## 1. Finishing GPU-native: exact next steps, in order

The design of record is `rv64-m8-gpu-native.md`:
- §2 lists host work H1–H28 with the replacement for each;
- §3.4 is the slab contract and §3.5 the device checks;
- §3.6 covers peer exchange and the device seal;
- §3.7 is the two-phase memory plan;
- §6.3 holds the acceptance tests.

The contract is `src/integrations/riscv_cuda/rv64/jobs/gpu_native.zig`.

### What already works on real data [M]

| Piece | Evidence | CPU work it removes |
|---|---|---|
| gn-pack: Stage-1 device witness from compact `TraceChunk` v2 | MAIN byte-identical on 11/11 segments (34,788 columns) of 24628607 and 26235156; witness 149 GPU-ms per request | H2D 7.376 → **1.376 GB** per request |
| gn-shape: install-time per-class `Spec` and `ClassFraming` builder | default gate passes; class-miss path works on a block it never warmed | removes `GpuNativeNativeShapeHookMissing` |
| gn-s2: Stage-2 device OODS check, seal consumes `Exchange.truthRoot` | parity on all segments; faults rejected | — |
| n-stage2: device `ProofEncoder` | 8/8 proofs byte-identical, 76 faults rejected | 1.07–1.92 ms on the GPU vs 131–233 ms on the host per proof |
| gn-truth: truth encoder and OODS on device | 14/14 truths byte-identical, 40/40 negatives | truth assembly, 652–680 ms per request |
| gn-node: recursion node job with device seed fill, chaining and encoding | 24628607 38/38 and 26235156 30/30 nodes byte-identical cold+warm; full requests 39/39 and 32/32 identical | **7 host launches per node** (target ≤ 50) |

### Where it stops now [M, `vectors/reports/rv64-m8-20261106/gn-bind/REVIEW.md`]

- **Passing so far:** install gets through warm capture (block 26235156, 4 segments), the class build (8 classes) and capacity measurement.
- **Failure:** it then fails `GpuNativeMemoryPlanPhaseA`.
  - Phase-A peak: 6.365G words (25.5 GB).
  - Cap: 7.516G words, after class_cache 0.28G, main_resident 0.87G, slab, graph and reserve.
- **Cause:** `native_device_stage1.Class.jobWords` **sums** phases that run one after another: `gkr_enqueue` 3.812G + `main_device` (LDE) 2.213G + `image` 0.307G + `resident` 0.420G.
- **Fix in flight:** commit `7bbe1c5c0` budgets MAIN commit and local GKR as max(), not sum. With max() the class is about 4.5G words [D], which fits.
- **Gate 10** (GPU-native on 26235156 with that fix) was mid-run at handoff. Read:
  - `/workspace/m3/runs/m8-gn-bind/gate-10.log` and `gate-10.done`;
  - gates 11 and 12, the default gates at the same head, which follow automatically.

  The script is `/workspace/m3/runs/m8-gn-bind/int-gates.sh`, running in tmux `gnint-gates`.
- **Make jobWords LIFO-true:**
  - drop the v1 `image_words` term for v2 compact witnesses and use `Spec.compact_words` instead;
  - or use a measured peak, as `truth_factory`'s `measured_peak_words` does;
  - then pin the plan in a layout unit test.

### Gate 10 result (after handoff, 18:20Z) [M]

`/workspace/m3/runs/m8-gn-bind/daemon-26235156-r2-gate-gate-10-00-baseline/producer.stderr`:
- **The memory-plan fix works.** Per-class Stage-1 `arena_peak_words` are 3.03G to 3.28G (`phase_b=false`), with `main_resident_words` 0.28G to 0.43G, so `GpuNativeMemoryPlanPhaseA` is gone.
- **The next failure is `GPU_RESIDENT_SERVICE install_stage=driver error=CudaEnqueueFailed`.** At terminal, `GPU_PROCESS_MEMORY` shows 2.17 GB free per device.
- **Likely cause:** the plan regions or driver allocations come from the CUDA default pool instead of inside the `STWO_RV64_DEVICE_ARENA=auto` carve, which has already taken the device.
- **Next:** carve the `MemoryPlan` regions *out of* the exec-context pool (`stwo_exec_context_pool_current`), or size the arena carve to leave the plan's non-arena regions. Then rerun `int-gates.sh` (gate 10 GPU-native, then default gates 11 and 12).

### Still unbound after the memory plan, in this order

From the REVIEW.md list:

1. **`NativeFactory.pack`:** the gn-pack `Packer` plus a `RequestSource`.
   - The legacy `early_segments.build` needs three things: the segment-0 initial RAM, the last segment's terminal RAM, and the block Keccak total (sponge first ids). With `STWO_RV64_FIRST_PASS_RAM=0` none of these exist before capture ends.
   - Minimal route: a per-block install-time copy from the warm capture, checked against the request at `captured`.
   - Also needs `Registry.setRequest` (seed, prefix and publics: `binding.begin(config, localCpuExpected)`, `childPrefix`) and `Registry.roms`.
2. **Stage-2 `Factory.beginRequest`:** roster, flat entries including truth statements, and per-segment boundary tuples and public inputs.
   - `Factory.segment_class` is keyed by segment only, so two in-flight requests for different blocks collide. Key it by (block class, segment).
3. **Truth `Factory.begin`; recursion `shape`, authority registration and `NodeClasses`; non-proof publish files.**
4. **Merge the newer piece reviews into gn-bind.**
   - gn-bind has gn-pack `533226abe`, but gn-pack is at `5823e729d`.
   - gn-bind has gn-node `cb410ff73`, but gn-node is at `03cb0a6a7`.

### Acceptance, in order (stop polishing once met)

1. `rv64_gate.sh` default, plus `--env STWO_RV64_M8_JOBS=1 --env STWO_RV64_M8_GPU_NATIVE=1`, PASS on 26235156 and 24628607: byte-identical cold and warm, fresh receivers.
2. One nsys trace of a warm 24628607 GPU-native request:
   - host waits per request (target 1);
   - host compute on the critical path, excluding capture;
   - GPU busy, launches per node, and the top idle gaps with their causes.
3. Canonical 3+3, default vs GPU-native, on 24628607 and 26235159. The runner's non-dev-block rule needs the explicit opt-in that m-runtime added.
4. The 15-block run (`scripts/rv64_m8_bench15.py`, with `--tolerate-arm-failure` and `STWO_RV64_M8_TRUTH_SPLIT=1`):
   - the GPU-native arm on all 15 blocks;
   - the default arm only where no current-runtime number exists.
5. Land on integrate, then fast-forward `codex/rv64-cuda-ethereum`. Flip `GPU_NATIVE` on only if it wins on every block.

### Production blocker to plan for now

- **Every real request is a new block.** Leaf classes are keyed by per-segment authority and change per block. The contract treats a request-path class miss as an error (`GpuNativeClassNotWarmed`, `gpu_native.zig:622`). gn-shape has a miss path, but it charges the class build to the request.
- **Cost:** host class build is about 5.6 s at the median block [E]. A cold request today spends 13.2 CPU-s on plan builds and 2.72 CPU-s on PP pack [M].
- **Production p50** is therefore about 13.6–17 s against a bench of 8–11 s [E].
- **Options:** class-stable (canonical) outer shapes, or a miss path that overlaps capture. Wave 1 found canonical leaf classes as designed lose: a ×1.55 padding tax on held-out blocks, and 79% of folds still miss. Measure E8 (warm requests over *different* blocks) first.

---

## 2. GPU residency: the complete picture

Sources:
- `rv64-m9-io-streaming.md` (reviewed; receipts `vectors/reports/rv64-m9-io-design/`);
- census2 (`codex/rv64-m8-census2` @ `6724cf2ce`, summaries at `/workspace/m3/runs/m8-census2/summary/`);
- `rv64-m8-gpu-native.md` §3.1 and §3.7.

### 2.1 What crosses PCIe per warm 24628607 request today (default path)

| Data | GB | Share | Notes |
|---|---:|---:|---|
| Recursion class statics: FIXED forest 8.61 + assignment task tables 7.26 | ≈ 15.8 [D] | 56% | unpacked on the host and uploaded **per node, every request** |
| Deterministic geometry: twiddles, composition denominators/masks/logs, PCS metadata, native owner geometry | ≈ 9.4–10.4 [D] | 33–37% | regenerated or re-sent per request |
| Block-derived compact capture (facts, events, `CompactRecord`s) | ≈ 1.9 [D] | 7% | already compact; expanded on the GPU by the `*_witness` kernels |
| Per-request recursion seed tapes | 0.22 [M] | < 1% | |
| D2H, everything back including proofs | 0.062 [M] | 0.2% | about 3 ms; not worth optimising |
| The block input file itself | 0.0027 [M] | — | |

- **Cold and warm move the same total:** 28,270,666,064 B [M]. **Nothing stays resident across requests.**
  - The 2 GiB immutable device setup cache cap at `outer_source.zig:351` keeps evicting and refilling.
  - On the same-block warm request the host class store hits (19 `unpack`, 0 plan builds [M]), but the bytes are re-uploaded anyway.
- **Copy time:** 0.614 s on dev0 and 0.541 s on dev1 [M], summed per GPU.
- **Overlap:** **0%** of H2D overlaps a kernel on its device [M]. The serializer is twofold:
  - **host join:** the host `Context.join()` after metadata ingress, at `session_context.zig:72-75`, which calls `join_lanes` at `context.cu:134` and `:542` (default `STWO_RV64_EXEC_SYNC=host`);
  - **ring-wrap waits:** `cudaEventSynchronize` at `device_arena_runtime.cuh:1139,1163`.
- **Already pinned:** every upload goes through a pinned 4×16 MiB staging ring. More pinning, GPUDirect Storage or RDMA, and unified memory will **not** help: the source is a CPU emulator in host RAM.
- **D2D:** 167 GB per request, 0.214 copy-s. Mostly trace-commit coset copies (88 copies of at least 1 GiB) and 22.0 GB of explicit `final_coefficient_copy_words` [M].
- **The link runs at x8.** Fixing x16 on the host would halve link time, but that is pod placement, not code.

### 2.2 What the GPU-native design makes resident (§3.1, §3.7 of rv64-m8-gpu-native.md)

- **`ClassCache`**, built at install/warm and resident per GPU in the `class_cache` region: FIXED trees, twiddles, GKR/binding plans, Stage-2 framing (H9), outer node plans/tapes/stream plans/PCS framing (H16–H21), captured whole-node graphs (H24) and the slab directory prefix.
- **`main_resident`:** MAIN stays on the device from witness to PCS. There is no legacy replay (H5/H12), and the segment's region is freed after its PCS.
- **One `MemoryPlan` per GPU, fixed at install.** Regions in order: `class_cache` (2.5–3.1 GB long-lived today [M]), `graph_exec` (256 MB/worker), `main_resident` (4.15 GB dev0 / 3.23 GB dev1 on 24628607 [M]), `arena` (one job in flight + one staged), `truth` (0: truth jobs are arena classes), `exchange_slab` (≤ ~24 MB per GPU [E]), `reserve` (1 GiB).
- **Two phases:**
  - **phase A**, the native window: `main_resident` is live, and the arena runs Stage 1/2, truths and the leaves that fit (leaf peaks 3.1–18.2 GB [M]);
  - **phase B**: once a GPU's last Stage 2 has freed its MAIN, the arena grows over `main_resident` for folds and the root (fold/root peak 21.5–21.8 GB [M]).
  - The boundary moves only at a phase change, stream-ordered.
- **Invariant:** no `cudaMalloc` on the request path outside the plan. The allocation observer enforces it in acceptance tests. The legacy 14.75 GB truth-composition lease (which caused the 24628607 OOM against retained MAIN) becomes an arena job.
- **Arena gotcha:** with `STWO_RV64_DEVICE_ARENA=auto` the carve leaves `cudaMemGetInfo` near 0. Capacity must count the unused carve, `stwo_exec_context_pool_current` (fixed in gn-bind).

### 2.3 Residency work still to do

In order of value; flags are default-off, per rv64-m9-io-streaming.md §5.

1. **L0, compact ingress:** done in gn-pack (v2 `TraceChunk`). Make sure v1 is never on the request path.
2. **Upload packed class statics** (`STWO_RV64_M9_CLASS_PACKED_INGRESS`), 0.455 GB instead of 15.86 GB, and decode on the device.
   - Prototype: `codex/rv64-m9-packed-ingress` @ `805d1a105`. Decoder 4.48 ms per 1.03 GB node [M]; parity on both GPUs; compute-sanitizer clean.
   - Worth only about 1% of wall *today*, because about 46% of copy time is exposed. It matters more once the host join is gone and after GPU-native, and it saves 3.70 CPU-s of host unpacking per request [M].
3. **Copy lane** (`STWO_RV64_M9_H2D_STREAM`): a dedicated copy stream, `cudaStreamWaitEvent` only into the consuming lane, and uploads issued ahead of the consumer. **Remove the host `Context.join()` after ingress.** A separate stream without removing the join hides nothing.
4. **Geometry residual:** whatever M8's `ClassCache` still re-sends, ≤ 1.07 GB after M8 [E]. Measure with nsys `cuda_gpu_mem_size_sum` (experiment E1 in the IO doc) before building.
5. **D2D in place:** in-place coset switching, and writing INTER and final coefficients in place. ≤ 0.11 s per GPU on 24628607 [D].
6. **Residency across requests:** about 0.23 GB per GPU of packed classes kept in `class_cache`. Only worth the class hit rate, which is about 0 for new blocks unless shapes are class-stable (§1, production blocker).
7. **Memory to unlock occupancy and bigger segments (P1 items):**
   - chunk-bounded GKR workspace: today 64.3 B/fact, so a 2^23 fold needs 16.6 GB; route B measured **32.15 B/fact** on the dev 5090;
   - freeing PCS planes as they retire;
   - streamed commit with partial trees.
   - Post-P1 a native 2^22 job is about 4.3 GB and a 2^23 job about 6.6 GB [E]. Two jobs per GPU fit at p50 but not at p95.
   - At p95, resident MAIN is 22.6 GB per GPU at any segment size, so large blocks need a MAIN spill policy. Its cost is unmodelled.

---

## 3. Process and infrastructure notes (learned the hard way)

### Pod access

- **Main pod:**
  - `~/Coding/ge-ops/bin/{pod,podsync,podget}`;
  - GPU only through the harness or `flock -w 3600 /workspace/m3/locks/gpu.lock` (≤ 15 min holds; never wrap a gate in `gpu.lock`);
  - builds under `build.{1,2,3}.lock`;
  - long jobs in uniquely named tmux sessions, with logs polled.
- **Protocol:** `~/Coding/ge-cache/rv64-m4/PROTOCOL-M8.md`.
- **Leftovers on the main pod:** tmux `gnint-gates` (gates 10–12), the `devseed-*` scripts under `/workspace/m3/runs/devseed/`, and `/workspace/m3/GPU-PRIORITY.md`. The priority rule there is void now.
- **Dev pods:** the two 1-GPU dev pods (RTX 5090, RTX PRO 4500 Blackwell) were deleted at handoff.
  - Only Blackwell (sm_120) GPUs run the build unchanged.
  - Seeding a new dev pod from the main pod takes about 40 min (`/workspace/m3/runs/devseed/seed.sh`, about 23 GB) using the main-pod key `/root/.ssh/devpod_ed25519`.

### Hygiene that cost hours

- **Leftover `combined-serve` services.** Services left running after an agent stops (PPID 1, about 30 GB per GPU) blocked every gate for 7 h once. Stop services with `spool/inbox/STOP` and check `nvidia-smi --query-compute-apps` before leaving.
- **Don't SIGSTOP a lock holder.** A frozen build that held `build.1` stalled the GPU-native gates. Only freeze processes that are *waiting* on a lock.
- **Pod disk (80 GB):**
  - each stream's src+build is about 1.5–3 GB;
  - prune superseded `src/m8-*` and `build/m8-*` by explicit name;
  - frozen assets are read-only: `build/m7-*`, `runs/m7-fold-v3`, `runs/m7-integrate`, `runs/integrate`.
- **Laptop disk (926 GB) filled up at handoff.** Each `~/Coding/ge-wt/*` worktree is about 1.6 GB plus its zig caches. Remove finished worktrees with `git worktree remove`, and delete `*/.zig-cache` periodically.
- **The canonical fullstack env fails on source-built images:**
  - admission v2 gives `NativePostGlobalDrainUnavailable`;
  - v1 deadlocks the warm request.

  The 3+3 uses the default env with a fixed 22G arena. Admission and the two-lane path are frozen (delta §4 item 2); don't fix them, delete them in the cleanup.

### Measurement

- **Request claims:** only from `scripts/rv64/rv64_m7_integration_stack.py` 3+3 runs with the quiet gate.
- **Kernel timings:** only from CUDA events or nsys NVTX GPU projection.
- **No hardware counters on RunPod:** `ncu` returns `ERR_NVGPUCTRPERM`.
- **Grinding:** the as-built PoW grind runs at about 1.1–2 G Blake2s/s. An engineered check-every-64 variant measured 19–25 G/s on the dev 5090 [M] and isn't landed.

### Agents

- **Partial pieces.** Rounds 1 and 2 returned "partial" pieces and an integrator that refused to wire them. Briefs must demand acceptance on **real recorded segments and nodes**, not hand-made specs.
- **Barriers.** A workflow barrier waiting on non-critical streams stalled the critical path. Keep the critical path in its own workflow.

---

## 4. M9: what the prototypes actually showed (reviewed numbers)

Baseline is post-M8 [E]: p50 block (29.1 M gas) 19.7 s, p95 block (55.8 M gas) 32.9 s, 15-block basket 294 s. Targets for −60%: p50 ≤ 7.9 s, p95 ≤ 13.2 s, basket ≤ 118 s. The mainnet gas sample: p50 29.1 M, p95 55.8 M; 24628607 sits at p4 and 26235159 at about p96. **Stop using 24628607 as the headline.** Use p50/p95 blocks: 26235168 (the median) for the 3+3, and 25229955 as the scale probe.

| Lever | Expected before | Reviewed result | Verdict |
|---|---|---|---|
| Poseidon2 leaves | big recursion cut | **net loss**, +8.7 GPU-s at p50; Poseidon2 ≈ 10× Blake2s per hash on GPU, transcript 24× slower [M] | drop (keep only as a memory/compression lever) |
| Canonical leaf classes | cross-block reuse | ×1.55 held-out padding tax; 79% of folds still miss | drop as designed |
| Packed class ingress | −15 GB | works, about 1% of wall today | do after GPU-native |
| Outer GKR in nodes | recursion ×0.57 | **×1.07, a loss**: ×0.57 was a cell factor; GKR prover 0.575–0.82 ns/fact, fused route measured **0.762 ns/fact** [M dev-5090] | kill unless a GKR kernel reaches ≤ 0.3 ns/fact *and* memory is chunked |
| Streaming commit (fused LDE→leaf) | ×0.70 | ×0.955; fused kernel 1.03–1.61× slower at log 22–24 [M] | take only the aligned-32-column plan |
| Witness without the task DAG | ×0.2 | ×0.70 (leaf ×0.513, fold ×0.760 [M]), class hits only | small |
| GPU capture replay | 160 MIPS | bounded by the serial first pass: 62.8 MIPS on 26235168 because curve services take 64% [M] | fix the service arithmetic first |
| Proof params at equal security | — | ×0.967 at best; every blowup change loses; Merkle caps in the parent circuit win a little | small |
| Native cells (V2SHARE, PAD, Zbb, …) | — | native ×0.945; best set −48% | small–medium |
| 2^23 segments | — | kernel ×0.877 with the best set; **needs P1 memory**; 2^24 infeasible | medium, after P1 |
| Recursion diet / batching | — | best −45 to −47%; batching jobs exceed memory | medium |
| **Column stacking (STACK)** | — | **−5.6 GPU-s at p50 alone**: a native segment opens 5,833 values per query against ~151 ideal | **largest lever** |

The best central set (plan best + STACK + Blake3 for leaf-opened trees + full native GKR + reverting D2 once stacked) reaches **−58%** at p50 and p95 and on the basket. In production, with new-block class misses, it is −53% [E]. With 4×5090 plus STACK and Blake3, p50 is about 5.6 s (−72%) [E].

---

## 5. Take large architectural steps, not small kernel tweaks

Almost all of the last two days' kernel micro-work returned 1–10%. FFT and Merkle already run at 1.4–1.6 TB/s against a 1.79 TB/s HBM peak, so tuning them further is wasted GPU time. Every prototype estimate came in 2–5× optimistic once measured. The remaining gap to the frontier is structural.

Ethproofs on the same 2×5090 [pub, 2026-11-07]: Airbender v3 3.4 s, ZisK 6.0 s, SP1 Twin Peaks 28.8 s. Ours is about 38 s p50 today.

- **Against ZisK:** the gap is execution and orchestration. Native LDE bits per instruction are about equal (23.9k vs 23.5k).
- **Against Airbender v3:** the gap is work, about 4× like-for-like [D/E]. It uses GKR+WHIR, with no committed lookup or composition columns and 40–58 columns per cycle.

Take these as whole steps, each behind one flag, each with its own proof-format and soundness note:

1. **Finish GPU-native as the request path** (§1), then delete the hybrids, admission and two-lane code (post-M8 cleanup). This removes the host from the critical path: about 6–8 s at p50 [E].
2. **Residency architecture** (§2.3): class statics packed and resident, geometry generated on device, a copy lane with no host joins, one memory plan, P1 memory. Make "no per-request upload except block data" an invariant tested by nsys `cuda_gpu_mem_size_sum`.
3. **Equal-height commitments.** Stack short columns into equal-height trees, so a query opens ~151 values instead of 5,833.
   - This is the biggest work cut available: −5.6 GPU-s at p50 alone.
   - It shrinks every leaf's opened-row hashing, which is 68% of leaf cells.
   - Pair it with **Blake3 (7 rounds) for every tree a leaf opens** (node 9,936 vs 14,840 cells, ×0.670 [M]) and **revert native blowup to b2** once stacked.
   - Design: `rv64-m9-frontier-gap.md`.
4. **Native GKR for all lookup columns**, not only the v2 strict classes. Cells ×0.798 with v1 [M], further with the full set.
5. **2^23 segments with fan-in-4 leaves.** Recursion cells ×0.513 at p50 [D]. Only after P1 memory.
6. **Recursion diet:** Merkle caps in the parent circuit, q102/p26 (needs the fast grind kernel, ≥ 17 G/s), coset FRI leaves, last layer 2^4, fold arity 6. About ×0.93 [D].
7. **Class-stable shapes**, so production new-block requests hit warm classes and the 5.6 s p50 class-build miss leaves the critical path.
8. **The bigger leap, M10+:**
   - an MLE/GKR+WHIR-style native argument, the Airbender v3 direction, estimated at −9.5 GPU-s at p50 (speculative);
   - 4×5090 placement, which is where 60% is comfortably reachable.

### Do not spend GPU time on

- more FFT or Merkle kernel tuning;
- Poseidon2 leaves;
- outer GKR as built;
- the fused LDE→leaf kernel;
- more pinning;
- GPUDirect;
- PoW above 24 bits with the as-built grind;
- canonical leaves as designed;
- re-measuring 24628607 alone.

### Rules that still apply to every step

- default-off flag;
- `rv64_gate.sh` byte-identical (or a named profile with fresh receivers and corpus);
- the canonical 3+3 on 26235168 and 24628607;
- bench15 after each wave.

---

## 6. Branch map (heads at handoff)

| Branch | Head | Content |
|---|---|---|
| `codex/rv64-cuda-ethereum` (PR #314) | this handoff commit | integrate + GPU-native (default off) + M9 docs |
| `codex/rv64-m7-integrate` | `1088a894d` | landed, gated default path |
| `codex/rv64-m8-gn-bind` | `7bbe1c5c0` | GPU-native integration (all pieces) |
| `codex/rv64-m8-gn-{shape,pack,s2,node,truth}` | `b638c6592` / `5823e729d` / `8adc06362` / `03cb0a6a7` / `dd3ac53db` | pieces; pack and node have review fixes newer than in gn-bind |
| `codex/rv64-m8-gpu` | `b289b021f` | bench15-1 receipts, `scripts/rv64_m8_bench15.py` |
| `codex/rv64-m8-k-merkle` / `-handoff` | `e86105e09` / `6b16aa0ec` | T6 fused-Merkle call sites (not gated) |
| `codex/rv64-m8-m-runtime` | `f86ae2b83` | runtime promotion, runner opt-in for non-dev blocks |
| `codex/rv64-m8-census2` | `6724cf2ce` | IO/kernel census receipts |
| `codex/rv64-m9-plan` | `5702d49e7` | M9 plan rev 4 and model (`scripts/rv64_m9/plan_model.py`) |
| `codex/rv64-m9-{io-design,packed-ingress,fewer-leaves,canon-leaf,poseidon2-leaves,outer-gkr,stream-commit,witness-rowpar,gpu-replay}` | see `git branch -r` | wave 1–2 prototypes with reviews |
| `codex/rv64-m9-{proof-params,native-cells,segment-shape,recursion-arch,frontier-gap,gkr-bench}` | `ed3e22169` / `9912c0852` / `2b0bd934f` / `f132ff5e0` / `06d8781d2` / `dced7ae3a` | wave 3. proof-params' last commit and gkr-bench are WIP at handoff (unreviewed) |
| `feeder-preview-nh`, `codex/rv64-m8-{native-job,outer-job}-handoff` | `3dbcc7e33` etc. | preserved WIP, superseded by GPU-native |

