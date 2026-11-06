# What ZisK and Airbender do on the GPU that we don't: code-level analysis and the explicit delta

Status: 2026-11-06. Read-only analysis of the shipped code. Nothing was built or run.

Sources (shallow clones):

| repo | commit | date |
|---|---|---|
| `matter-labs/zksync-airbender` | `0decdcd` | 2026-11-04 |
| `matter-labs/airbender-platform` | `fba618d` | |
| `matter-labs/zksync-airbender-prover` | `ea89b32` | v0.8.2 |
| `0xPolygonHermez/pil2-proofman` | `27b2fc2` | includes pil2-stark C++/CUDA |
| `0xPolygonHermez/zisk` | `64a1f16` | |
| `0xPolygonHermez/zisk-ethproofs` | `5a72736` | |
| `0xPolygonHermez/sppark` | `17278d7` | |

Our baseline: `codex/rv64-m7-integrate` @ `fe9d85b4a`/`898a38bfe`, with the M7/M8 receipts.

Labels:
- **[code]** read in source, with a path;
- **[M]** measured in our receipts;
- **[D]** derived from measured numbers;
- **[E]** estimate.

---

## 0. Verdict

Neither team wins on clever kernels. Airbender's kernels are plain (radix-2 complex NTT, one-thread-per-leaf Blake2s, an interpreted quotient), and ZisK's are sppark-style standard. **They win on the execution model and on memory planning. Our time goes to exactly those two places.**

| | Airbender | ZisK | us |
|---|---|---|---|
| Host waits per proof | **1** (`ProofJob::finish`) [code] | **0** inside the proof path; finished proofs found by `cudaEventQuery` [code] | **~105 per recursion node** [M] (916 event + 1,078 stream syncs over 19 nodes) |
| Fiat–Shamir | `cudaLaunchHostFunc` callbacks write challenges to pinned memory, then an async H2D **on the same stream**; the host thread never waits [code] | **On device** (`TranscriptGL_GPU`) [code] | Native PCS on device; outer recursion FS **on host** by default; 4 host OM31 draws per node [M] |
| Launch overhead | 2–3 launches per NTT for all columns; one launch per quotient; no graphs [code] | **Every proof phase captured as a CUDA graph** (after 100 sightings, ~7 ms per capture, budgeted, blacklist) [code] | ~1.8k launches per node [M]; graphs only for the MAIN-assignment chain, 14 re-instantiations per warm request (0.218 s) [M] |
| Proofs per GPU | **One proof in flight, plus the next proof's inputs uploading** (3-stage pipeline) [code] | **One planned buffer per GPU**: "phase A" big AIRs, then the buffer re-split into 2 recursion streams; up to 2 queued proofs per stream; 2 commit slots [code] | One lane by default; 2 lanes stall on memory [M] |
| Memory | **One static 28 GiB arena (21.5 GiB fallback)**; stream-ordered frees at enqueue time; Top/Bottom placement alternation; a **sweep-generated** per-circuit recompute-vs-keep policy that fits 2^24-row circuits **plus the next job's inputs** in 21.5 GiB [code] | **One `cudaMalloc`, carved by a Rust planner** into const/late/prefetch/slots/recursive/aggConst regions; the layout is a unit test [code] | VMM arena (auto ≈27.3 GB, or 22 GiB) plus a 1.6k-line admission/permit layer; per-node peak ≈22 GB and **never measured exactly** [M] |
| Concurrency mechanism | none needed: the GPU is never idle because the host is never on the critical path | **time-multiplexing one buffer** (phase A/B), not co-resident full contexts | co-resident full contexts behind admission, which serialises |
| Witness | host replay writes compact ~50 B/instruction records **straight into pinned 64 MB chunks**; one generated row-parallel kernel per circuit; **no dependency DAG** [code] | indexed rows + per-program instruction table, unpacked on device; memory-family witnesses on GPU; compact recursion witness, with gate interiors rebuilt on GPU [code] | CPU metadata 17.5 B/row [M]; partial device widening; recursion witness is a 146k→73k-level task DAG [M] |
| Commit memory | partial Merkle trees (bottom 5 layers dropped, rebuilt with one warp per query); `CacheSingle` in-place coset switching; **setup not resident** (re-uploaded from pinned memory, LDE recomputed) [code] | **streaming commit** (chunked LDE folded into a carried sponge state; never materialises NExt×nCols); **Merkle without the leaf level**; const tree rebuilt on device [code] | streaming chunked LDE→Merkle exists (2^27-word chunks) [code]; full trees; large resident caches (2.5–3.1 GB long-lived) [M] |
| Emulation | JIT simulator + 8 replay threads [code] | **AOT x86 asm emulator** in a separate process over shared memory; minimal trace per 2^18 steps; **each Main segment is published during emulation**, so its witness and commit start before emulation ends [code] | fast pass 148 MIPS, then 8 traced walks; capture 2.1 s at ~12.5 MIPS effective; native stage 1 starts at 2.55 s, although inputs are ready at 1.32 s [M] |
| Code size | **~10k lines CUDA + ~40k Rust** in `gpu_prover` | ~39k CUDA (pil2-stark) + 144k Rust (proofman) + 6k zisk CUDA | **51.5k CUDA + 37.6k Zig RV64 integration + 179 distinct `STWO_RV64_*` env flags** |

**The delta in one sentence.** They structure a proof as *enqueue everything, then wait once*, inside *one statically planned allocation per GPU that is measured offline*. We structure it as *many synchronous owner-thread callbacks*, inside *a dynamically admitted arena whose peak we haven't measured*, and we then try to recover the lost GPU time with concurrency that the memory can't hold.

---

## 1. Airbender: how the GPU prover works

All paths are under `zksync-airbender/gpu_prover/` unless noted.

### 1.1 Execution model: enqueue-only, one wait per proof

- **Three streams per device context** (`src/prover/context.rs:87-89,145-147`): `exec` (all compute), `h2d` (input upload) and `aux` (used only for L2 ping-pong in the LDE). No CUDA graphs.
- **Fiat–Shamir runs in `cudaLaunchHostFunc` callbacks** (`src/prover/callbacks.rs:13-24`). Each challenge follows the same pattern (`stage_3.rs:128-206`):
  1. Allocate a pinned host buffer.
  2. Schedule a callback that runs `Transcript::draw_randomness(seed)` and computes the powers on the CPU, writing them into the pinned buffer.
  3. Enqueue `memcpy_async` pinned→device on the same stream.
  4. Enqueue the kernels that use them.

  Tree caps come back by D2H into pinned memory (`trace_holder.rs:1065-1075`) and are absorbed by a later callback (`get_update_seed_fn`). PoW (`pow.rs:36-51`) grinds on the GPU, copies the nonce back, then a callback verifies it. NVTX ranges ride the same mechanism (`device_tracing.rs`).
- **`prove()` enqueues everything and returns a `ProofJob`** (event + callbacks + `Box<Option<Proof>>` filled by the last callback; `proof.rs:353-360,497-563`). **The only wait is `finish()` → `event.synchronize()`** (`proof.rs:53`). Every other `synchronize()` in non-test code is a one-time setup step.
- **Per-GPU 3-stage software pipeline** (`src/execution/gpu_worker.rs:94-379`). Each iteration does three things:
  1. upload inputs for job k (H2D);
  2. enqueue the whole of job k−1;
  3. `finish()` job k−2.

  Allocation placement flips between Top and Bottom on even and odd iterations (`context.rs:242-250`), so the next job's inputs sit at the opposite end of the arena from the running job.
- **Cross-stream ordering uses events only** (`transfer.rs:25-85`): an `allocated` event on exec gates H2D, a `transferred` event on h2d gates exec, and an end-of-proof event gates the next H2D (`proof.rs:330-337`).

### 1.2 Memory: one arena, measured policies

- **Arena** (`gpu_memory.rs:7-62`):
  - `NORMAL_ARENA_BYTES = 30_064_771_072` (28 GiB), `LOW_ARENA_BYTES = 23_085_449_216` (21.5 GiB), and `Auto` falls back on allocation error.
  - 1 MiB chunks, BTreeMap free lists, BestFit/Top/Bottom placement, and a nested 2 MiB/256 B small pool (`allocator/*`).
  - **Freed on Drop at enqueue time.** That is safe because all compute is on one stream.
- **Per-circuit recompute-vs-keep** (`memory_policy.rs`, `trace_holder.rs:44-47,378-403,980-998`). There are four knobs (setup, witness, memory, stage 2), each `CacheFull` (keep both LDE cosets) or `CacheSingle` (one buffer, switched in place by iNTT→NTT).
- **The policy table is generated by measurement** (`src/memory_sweep/*`, `src/bin/gpu_memory_sweep.rs` → `low_vram_policy.rs`).
  - For each circuit it tries 16 policies at an exact arena size, **including worst-case overlap with the next job's inputs**, and records fit, high-water mark and time.
  - Tests assert the table is complete (`gpu_memory.rs:72-102`).
- **Partial Merkle trees** (`trace_holder.rs:33,1027-1063`; `native/blake2s.cu:168-248`): the bottom 5 digest layers are not stored (1/32 the size). At query time, one warp rehashes 32 neighbouring leaves and reduces them with `__shfl_xor_sync`.
- **Setup is not resident** (`setup.rs:137-160`): it is cached in pinned host memory, re-uploaded per proof, and its LDE recomputed on device. Only the tree caps are memoised. **This trades PCIe bandwidth for VRAM.**
- **Pinned host pool:** 64 MB `cudaHostAlloc` buffers, 256 per job and 128 per device (`execution/prover.rs:190-194,384-397`). Replayers write records **directly into pinned chunks**, so H2D is a direct DMA with no staging copy (`transfer.rs:52-75`).

### 1.3 Witness, kernels, recursion

- **Witness:**
  - Host replay produces compact per-instruction records of about 50 B each, plus a decoder table indexed by pc (`native/witness/trace_unrolled.cuh:15-59,332-340`).
  - **One generated kernel per circuit, one thread per row** (`witness_generation.cuh:409-421`, generator `gpu_witness_eval_generator/src/lib.rs`).
  - Multiplicities come from CUB sort, run-length encode and scatter.
  - **There is no dependency DAG anywhere.**
- **NTT:**
  - "Two-for-one" packs two M31 columns into a complex (E2) column, then runs a radix-2 FFT (`ntt/ntt.cuh`).
  - **2–3 launches per NTT across all columns**, using `grid.y` column batches.
  - Factored on-the-fly twiddles held in `__constant__`.
  - **L2-persistence ping-pong** across exec and aux when the working set fits half of L2 (`ntt/mod.rs:482-850`).
- **Quotient:** an interpreter over flattened metadata passed as a `__grid_constant__` kernel parameter (`native/stage3.cu:17-62`, max 2,208 terms). One launch.
- **Recursion has no special GPU path.** The verifier is a RISC-V program run on the "unified reduced machine" circuit (2^23 rows). Each layer is just more chunk proofs in the same queue (`docs/philosophy_and_logic.md`; `circuit_defs/unrolled_circuits/unified_reduced_machine`).
- **Multi-GPU** (`execution/gpu_manager.rs:74-284`):
  - one worker thread per device;
  - rendezvous channels with each worker's queue primed with two slots;
  - a single FIFO with biased select;
  - **no runtime admission at all**, because memory fit is guaranteed statically by the sweep.
- **Scope caveat:** this snapshot is DEEP-FRI with LDE factor 2 and Blake2s, with no GKR or WHIR. Airbender Prime (GKR + WHIR, one RTX PRO 6000) isn't in this repo, and no sm_120 build target exists here.

### 1.4 Airbender in production (`zksync-airbender-prover`, `airbender-platform`)

- **A stateless pull worker** (`crates/zksync_os_fri_prover/src/lib.rs:147-249`):
  - it calls `POST …/FRI/pick?supported_vk_hashes=…`, then proves, then submits; `204` means no job;
  - the sequencer owns job state and backpressure;
  - setup and the GPU context stay resident ("constructed once and reused across batches").
- **A compile-time protocol identity table** (`crates/protocol_version/src/lib.rs`). Each entry records vk_hash, airbender/os/wrapper versions, the guest binary hash, the program commitment and the security level. The prover:
  - refuses to start on a mismatch;
  - advertises its supported VKs when it picks a job;
  - rejects a mismatched job **before** spending GPU time.
- **Warm-up is an explicit, metered stage,** with eager VK computation so setup errors appear at boot (`snark lib.rs:95-104,302-312`).
- **Device ownership:** one process owns all VRAM. FRI and SNARK time-share the GPU by dropping and recreating the FRI prover, so the GPU is released before SNARKing (`service lib.rs:160-258`).
- **Fixture test against a real proof, not against the derivation code.** `program_commitment.rs` was added after a tautological test passed while production disagreed with every proof.
- **CI and release:**
  - the GPU end-to-end check proves, generates a VK and verifies against the expected output, at both security levels (`airbender-platform/.github/workflows/test-gpu.yaml`);
  - `ZKSYNC_USE_CUDA_STUBS` compiles GPU code on CPU-only hosts;
  - reproducible guest builds with digest-pinned images and a manifest of SHA-256 + commit + dirty flag;
  - one-revision dependency pinning across all consumers (`Cargo.toml:27-37`).
- **Agent rules** (`airbender-platform/AGENTS.md`):
  - stay in scope;
  - no new dependencies without approval;
  - run targeted tests first;
  - "if it only works with workaround X, report it as a project issue";
  - stop and ask on ambiguous crypto changes.

---

## 2. ZisK: how the GPU prover works

Paths are under `pil2-proofman/` (and `pil2-stark/src/…`) unless prefixed `zisk/`.

### 2.1 Execution model: graphs, device transcript, zero syncs

- **The proof path makes no host synchronisation calls.** `gen_proof.cuh`, `starks_gpu.cu` and `stir_gpu.cu` contain no `cudaStreamSynchronize`, `cudaDeviceSynchronize`, `cudaEventSynchronize` or synchronous `cudaMemcpy` [code].
  - Transcript (`transcript/transcriptGL.cu`), grinding and query sampling all run on device.
  - Proof parameters and publics go through **per-stream pinned slots** with `cudaMemcpyAsync`.
  - Results are collected with a non-blocking `cudaEventQuery` (`starks_api.cu:2128-2190`).
- **Every phase is a cached CUDA graph** (`utils/cuda_graph_cache.cuh`; used throughout `gen_proof.cuh:275-505`: WEXP, CM1, STD2, IMPL, CM2, QEXP, CMQ, EVAL, FREX, FRI, GRIN, QUY, STIR):
  - a graph is captured after 100 sightings of a key;
  - capture plus instantiate costs about 7 ms;
  - graph memory has its own budget (`PROOFMAN_GPU_HEADROOM_MB`);
  - non-replayable keys are blacklisted.
- **The GPU witness plug-in contract** (`zisk/gpu-witness/src/lib.rs:1-50`, `starkpil/gpu_witness.hpp:22-30`): "Enqueue-only… no allocation, no sync, no new stream, exactly one launch on `stream`". That keeps every plug-in legal inside graph capture.

### 2.2 Memory: one planned buffer, re-split over time

- **One `cudaMalloc` per GPU**, carved into `const | late | prefetch | aux/slots | mops | recursive | aggConst | snarkPad` (`starks_api.cu:419-594`).
- **The layout is planned in Rust** (`common/src/buffer_plan.rs`, `gpu_stream_layout.rs`):
  - "large" and "regular" stream size classes;
  - a recursive pool only when it pays;
  - a prefetch zone of 6 units (the comment records the measured A/B: "6 units matched 8 on the RTX 5090… 4 lost 1.9%");
  - a 10-slot LRU cache for aggregation constants.
- **The RTX 5090 layout is pinned in a unit test** (`goldilocks/tests/test_unified_buffer_layout_cpu.cpp:7-19`):

  | region | size |
  |---|---|
  | basic constant pols | 1.17 GB |
  | late region | 651 MB |
  | witness prefetch zone | 3.5 GB |
  | one basic stream (incl. 2 × 2.4 GB commit slots) | 22.9 GB |
  | aggregation constant cache | 2.67 GB |
- **Phase A/B** (`common/src/proof_ctx.rs:1639-1730`, `starks_api.cu:2235-2272`):
  - on a 5090 with one basic stream per GPU, phase A proves the AIRs too big for half the buffer;
  - when the phase-A countdown reaches zero, the stream closes and **its buffer halves become two recursion-class streams**;
  - a "phase-A alias" stream past the largest basic AIR runs recursion *during* phase A.

  **Concurrency comes from time-multiplexing one buffer, not from co-resident full-size contexts.**
- **OOM handling:**
  - the plan is built from `cudaMemGetInfo`, with 256 MiB headroom retries (`proof_ctx.rs:1581-1606`);
  - an AIR that can never fit fails fast (`never_fits_for`);
  - the planned late arena treats an overrun as a hard error, never a silent `cudaMalloc`;
  - "never implicitly touch GPU 0", because each stray context costs about 300 MB (`starks_api.cu:328-335`).
- **Streaming commit** (`goldilocks/src/stream_commit.cuh:13-36`): per column chunk, unpack → LDE in place → fold into a carried sponge state per extended row. It never materialises NExt × nCols.
- **Merkle without the leaf level** (`merkle_noleaves.cuh`): queried rows are rehashed at query time.
- **The const tree is rebuilt on device** and reused when the stream's previous AIR matches. **Prefetch:** the next witness uploads on a copy stream while the current proof runs (`starks_api.cu:1541-1620`, `scheduler.rs:290-307`).

### 2.3 Pipeline, emulation, scheduler, distribution

- **Emulation:**
  - AOT ELF → x86 asm (`zisk/core/src/zisk_rom_2_asm.rs`) in a separate process over shared memory;
  - minimal trace (start state + memory reads) per 2^18 steps (`zisk/common/src/emu_minimal_trace.rs`);
  - parallel chunk replay (`state-machines/main/src/main_sm.rs:163`);
  - **an `on_chunk` hook publishes each Main segment while emulation is still running**, so its witness and GPU commit start early (`zisk/executor/src/executor.rs:384-412`).
- **Witness:**
  - indexed rows plus a per-program instruction table, unpacked on device (`unpack_indexed_device.cuh`, `prover-backend/src/prover/backend.rs:230-252`);
  - memory-family witnesses on GPU (sort / scan / pack in `zisk/state-machines/mem-cpp/cu/`, with CPU fallback);
  - the recursion witness ships as a compact buffer, and Poseidon/Blake3 gate interiors are rebuilt on GPU (`recursion_trace/witness_widen_gpu.cu`). **Hash interiors never cross PCIe.**
- **Constraints:** **setup-time codegen** of straight-line per-AIR CUDA, loaded with `dlopen` (`setup/exps-codegen`). It is autotuned to zero register spill and enforces STACK=0, because a spilling kernel makes the driver size local memory for the whole device. A bytecode interpreter is the fallback.
- **Scheduler** (`proofman/src/scheduler.rs`, 920 LOC):
  - one lock picks a witness and a stream together;
  - REUSE (stream already holds this key's constants), then FRESH, then REDUNDANT reload;
  - priority compressor > recursive2 > basic; LPT and deepest backlog first;
  - RAII `StreamReservation`.

  **There is no permit or custody layer.**
- **Distributed** (`zisk/distributed`):
  - every worker replays emulation;
  - instances go to the least-loaded partition;
  - **the global challenge is an additive EC-point sum of per-instance roots**, so partitions commit independently, and the coordinator is only a barrier (`challenge_accumulation.rs`, `coordinator/.../contributions.rs`);
  - an aggregation tree keeps folds on the worker that already holds the set (`agg_tree.rs`).
- **Live deployment** (`zisk-ethproofs`): a WebSocket block subscription; one block in flight, newer blocks overwrite the pending slot; Prometheus; `time_to_proof = time_to_input + proving_time`, against a 12 s target.
- **Practice:**
  - every tuning constant carries its measured A/B result in a code comment;
  - CPU-oracle gtests for every GPU kernel, plus `assert_matches_cpu`;
  - `PROOFMAN_SUMCHECK=1` writes per-stage buffer checksums to localise divergence between runs;
  - per-PR emulator cycle tracking on fixed mainnet blocks;
  - a RunPod GPU test cluster.

---

## 3. The explicit delta: what we do differently, and what it costs

Each row: their approach → ours → evidence → what it costs us.

1. **Host round trips inside a proof.**
   - Theirs: Airbender makes 1 wait per proof and ZisK makes none.
   - Ours: ~105 blocking calls per recursion node; owner-thread synchronous callbacks (229 `callconv(.c)` callbacks in `riscv_cuda/rv64`); outer FS on host by default; 18 `api.sync` sites in the Zig integration [code, M].
   - **Cost:** recursion-window GPU busy is 52–54% and the native window 31% [M]. In the owner-gap audit, 3.64 s of non-kernel thread time sat inside owner ranges after native [M].
2. **Concurrency strategy.**
   - Theirs: one proof per GPU plus prefetched next input (Airbender), or one buffer time-multiplexed through phase A/B (ZisK).
   - Ours: co-resident full-size contexts (2 lanes) behind a 1.6k-line admission/permit layer.
   - **Cost:** the two-lane stack stalls or runs slower (cold full stack 66.4 s against about 28 s baseline [M]). A whole M7/M8 workstream went into admission machinery that neither frontier system has.
3. **Memory is measured and planned offline, not admitted at runtime.**
   - Theirs: Airbender's sweep tool generates per-circuit policies that fit inside 21.5 GiB including the next job's inputs; ZisK's layout is a unit test.
   - Ours: the exact per-node peak is **still unmeasured** in every P1 checkpoint, and the admission model's 23–28.6 GB figures are model outputs [M].
   - **Cost:** we tune allocations blind, and runtime refusals are the first sign of trouble.
4. **Commit memory techniques.**
   - Theirs: partial trees with the bottom 5 layers dropped (Airbender); Merkle without leaves (ZisK); in-place coset switching; setup not resident; ZisK's streaming commit folds the LDE straight into a hash state.
   - Ours: full trees, resident setup and caches (2.5–3.1 GB long-lived [M]); streaming LDE→Merkle exists, but node peak is still about 22 GB [M].
   - **Cost:** this is exactly the footprint P1 is trying to cut by hand.
5. **Witness and recursion design.**
   - Theirs: generated row-parallel witness kernels with no DAG (Airbender); recursion as a guest program on the same pipeline (Airbender); compact recursion witness with GPU-rebuilt hash interiors (ZisK).
   - Ours: the recursion witness is a task-interpreter DAG (146k→73k levels); per-node host prep; leaf tape and class caches as patches on top [M].
   - **Cost:** host prep latency and serial depth, plus a large surface of caching code.
6. **Launch overhead.**
   - Theirs: ZisK graph-captures every phase; Airbender uses very few wide launches (2–3 per NTT across all columns, one per quotient).
   - Ours: ~1.8k launches per node; graphs only for MAIN assignment, re-instantiated 14× per warm request [M].
7. **Capture overlap.**
   - Theirs: ZisK publishes each segment during emulation.
   - Ours: native stage 1 waits for full capture plus global inventory (1.32 s → 2.55 s) [M]. The first R1 attempt copied 224 MB and re-hashed metadata, and measured negative [M].
8. **Operational model.**
   - Theirs: a stateless pull worker; a compile-time identity table checked at startup and per job; measured warm-up; Prometheus per stage; one pinned revision; CPU-stub builds; a GPU end-to-end CI that proves, generates a VK and verifies.
   - Ours: a file-spool daemon, tmux and `flock`, a per-change qualification campaign, 179 env flags, and 14.6k committed report files (157 MB in one day) [M].
   - **Cost:** iteration speed. Every experiment pays for qualification.
9. **Complexity.**
   - Theirs: Airbender delivers its whole GPU prover in about 10k lines of CUDA.
   - Ours: 51.5k lines of CUDA, 37.6k lines of RV64 Zig integration, 179 env flags.
   - **Cost:** most of the extra code is coordination (admission, permits, custody, caches, flags), not proving.

**Where we are level or ahead:**
- composition is AOT-generated CUDA (on par with ZisK codegen, ahead of Airbender's interpreter);
- native PCS/FRI/PoW/decommit is already one device pipeline with on-device transcript;
- committed native bits per gas are about 2× below ZisK's [D, 4-GPU doc §2.2];
- our correctness gates are stronger than both (fresh receivers, tamper corpus, byte identity).

---

## 4. What to change

These revise the M8 scope (`rv64-m8-engineering-scope.md`, on `codex/rv64-m7-integrate`). In order:

1. **Adopt Airbender's proof contract for every prover (native and outer).**
   - `prove()` only enqueues and returns a job holding an event, the callbacks and an output slot; `finish()` is the only wait.
   - Do Fiat–Shamir either on device (ZisK) or in `cudaLaunchHostFunc` callbacks that write to pinned memory followed by an async H2D on the same stream (Airbender).
   - Delete the owner-thread synchronous callback model.
   - Add a lint or test that fails on any sync reachable from `prove()`.
   - **Study:** `zksync-airbender/gpu_prover/src/prover/{callbacks.rs,proof.rs,stage_3.rs,pow.rs}`, `src/execution/gpu_worker.rs`; `pil2-stark/src/starkpil/gen_proof.cuh`, `transcript/transcriptGL.cu`.
2. **Stop pursuing two co-resident lanes per GPU.** Use instead:
   - one proof per GPU, with the next proof's inputs uploading in a 3-stage pipeline (Airbender), and Top/Bottom arena placement;
   - for recursion overlap, ZisK-style **phase A/B re-splitting of one planned buffer**.

   Freeze the admission/permit layer, then retire it once (1) and (3) land.
3. **Measure, then plan.**
   - Build a sweep tool like Airbender's `memory_sweep`. For each node class it tries the recompute-vs-keep options at a fixed arena (22 GiB), including next-input overlap, and emits a generated policy table plus a per-class high-water mark.
   - **Pin the GPU layout as a unit test,** as ZisK does.
   - This replaces the unmeasured P1 exit with a measured one.
4. **Bring in the frontier's memory techniques:**
   - partial Merkle trees (drop the bottom 5 layers; rebuild with one warp per query) or ZisK's no-leaf trees;
   - in-place coset switching;
   - setup and class constants not resident (re-upload from pinned memory, recompute the LDE);
   - commit folded straight into the hash state.

   These are well-understood and directly attack the 22 GB node.
5. **Graph-capture every recursion phase** (ZisK `cuda_graph_cache.cuh`: threshold, budget, blacklist), and **widen launches** (column-batched NTT with `grid.y`; one quotient launch). Target ≤ 50 launches per node.
6. **Release segments during capture** (ZisK `on_chunk`), and prefetch the next witness during the current proof.
7. **Recursion witness without a DAG.** Two options:
   - Airbender's: the verifier as a guest program, so its witness is ordinary row-parallel generated kernels;
   - ZisK's: a compact witness plus GPU gate-interior expansion.

   Either removes the task DAG and host prep. This decision should be made together with the Poseidon2 recursion change (4-GPU doc §7).
8. **Operations:**
   - a compile-time identity table (guest ELF hash, VK/statement hash, profile, security level, library SHA), checked at service start and per request;
   - a measured warm-up stage;
   - Prometheus per stage;
   - one pinned revision for every build;
   - a CPU-stub build of the CUDA layer;
   - a GPU end-to-end CI that proves, generates a VK and verifies;
   - every tuning constant carries its measured A/B result in a comment;
   - receipts are summaries only, with raw captures kept off git;
   - a short AGENTS.md modelled on `airbender-platform/AGENTS.md`.
9. **Simplify as you go.** A target: halve the env flags and delete the coordination code each step makes obsolete. Their throughput comes from fewer moving parts.

**Do not copy:**
- crash-on-error as the only retry (Airbender `.expect`);
- an unpinned bellman-cuda `main`;
- md5 guest identity;
- no GPU coverage in the prover repo's CI;
- ZisK's job-wide failure with no work stealing;
- ZisK's latency metric that excludes witness fetch and queueing (`proving_time` in `cluster-common/src/types.rs:444-450`).

## 5. Could not determine

- Airbender Prime's GKR/WHIR GPU code and its RTX PRO 6000 configuration: not in these repos.
- ZisK's exact hardware and MPI layout behind the 9.62 s p99.
- Measured GPU-busy percentages for either system.
- Polygon's sppark fork changes (the checkout is `main`, not the `zisk` branch).
- The OP Mainnet (`op.zisk.build`) deployment code: not in any of these repos.
