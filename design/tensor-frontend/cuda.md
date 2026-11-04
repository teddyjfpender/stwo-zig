# CUDA backend for the tensor prover

Status as of branch `codex/tensor-cuda` (2026-11-04). **No NVIDIA device and no
nvcc were available while this was written.** Everything below that says
*measured* or *verified* was run on the M4 Max development Mac, either in the
CPU emulation of the CUDA kernels or with LLVM's NVPTX backend. Nothing here has
run on a GPU. All GPU timings are **projections**.

## 1. What exists, what is verified, what is not

| piece | where | state |
|---|---|---|
| M31/CM31/QM31 with lazy reduction | `src/tensor/cuda/tc_field.cuh` | emulation-verified vs the Zig field (20k random + edge limbs) |
| Blake2s (plain, as the tensor PCS uses it) | `tc_blake2s.cuh` | emulation-verified (Merkle roots and every node equal the CPU's) |
| sumcheck round: fused fold of the previous round + {s(0), s(2), s(3)}, multi-term, deg <= 3, <= 4 factors, last-block device reduction | `tc_kernels.cuh` `tc_sc_round`, `tc_sc_fold` | emulation-verified: proofs, points, finals and transcripts equal `sc.proveActive` (6 shapes, partial `active`, grids up to 128 blocks; the 1024-block cap is not exercised) |
| implicit factors built on the device (int32 vectors, sums of gamma*eq at offsets, eq-prefix broadcast) | `tc_eq_halves`, `tc_eq_expand`, `tc_int_to_qm`; `tc_sc_begin_specs` | emulation-verified vs `accel.proveFactors(null, ...)` |
| eq tables (2 launches for any length) | `tc_eq_halves` + `tc_eq_expand` | emulation-verified vs `f.eqTable` (n = 0 .. 14) |
| int8 / int32 x QM31 weight fold (combine rows), int8 row dots | `tc_combine_rows`, `tc_sum_chunks`, `tc_row_dots_i8` | emulation-verified vs `pcs.combineRows`, `linalg.rowDots` |
| int matmul accumulators (int64-exact reference kernel) | `tc_matmul_i32_i8` | emulation-verified vs `protocol.matmulAcc` |
| MLE of int32 vectors | `tc_mle_i32` | emulation-verified vs `f.mleEvalI32` |
| RS encode (stwo circle FFT), column-major codeword, column leaves, Merkle | `tc_rs_expand`, `tc_rs_layer`, `tc_rs_tail`, `tc_rs_leaves`, `tc_merkle_level`, `tc_merkle_top` | emulation-verified: codeword bytes, all 2E-1 nodes, roots equal `pcs.commit` (9 shapes incl. multi-chunk) |
| batched LogUp-GKR fraction layer (all instances, one launch) | `tc_gkr_layer` | emulation-verified against the fraction sum only. **Not wired** into `accel.gkr_prove`; GKR stays on the CPU |
| C ABI host layer (stream, pool, mailbox, pinned weights, counters) | `tc_host.cu`, `tc_api.h` | the same file runs in the emulation (CPU memory instead of CUDA calls); the CUDA branches are compiled for the host side only by clang (see below) |
| Zig accelerator (`accel.Accel`, the Metal interface) | `cuda/backend.zig` | emulation-verified end to end (whole proofs below) |
| build: `-Dcuda=true` (nvcc -> `libtensor_cuda.so`), default off | `src/tensor/build.zig` | **untested** (no nvcc here). `zig build` without the flag is unchanged |
| GPU scripts | `scripts/tensor_cuda_{build,test,prove,ptx_check}.sh` | `prove.sh` dry-run against the emulation build; `ptx_check.sh` run here; build/test scripts untested |

Whole-proof evidence (`zig build test-cuda-emu`, 14 tests, all pass):
* product toy, small MLP (weights committed on the device, matmuls on the
  device), decoder layer (**the pinned golden digest `837b19ac…` of the Metal
  suite**), 2-request serving batch (dense + MoE stack, LM head, greedy check).
  Each has an identical proof digest to the CPU prover, and the CPU verifier
  accepts each.
* `scripts/tensor_cuda_prove.sh small` against a `-Dcuda-emu=true` bench: product
  14, mlp 6/10/12, layer 6/9/11/3 and a 2-layer MoE model all print `SAME`
  (CPU digest == `--cuda` digest).
* Mutation check: four injected kernel bugs each fail tests. The bugs were a
  circle twiddle, a dropped last-block partial, a sign in `qm_mul` and the
  Blake2s final flag. They failed 5, 6, 10 and 3 of 14 tests.

Device-path evidence without a device (`scripts/tensor_cuda_ptx_check.sh`):
with `__CUDACC__` defined, all 19 kernels lower to PTX for **sm_90 and sm_120**
through Homebrew clang 22 / NVPTX with `-Wall -Werror`. The host side parses
against a minimal runtime stub (`cuda/tools/stub/cuda_runtime.h`). This is
clang's CUDA dialect, not nvcc's. nvcc may still reject something, and the
stub only declares the runtime API.

The PTX shows four kernels with local-memory frames:
* `tc_sc_round` uses 224 B. Its factor arrays are indexed by runtime term
  tables.
* `tc_rs_leaves`, `tc_merkle_level` and `tc_merkle_top` use 64 B each. The
  Blake2s message is indexed through the sigma table.

Both are known performance fixes (§4). They do not affect correctness.

**Not done:** GPU execution of anything; nvcc build; device GKR; the int8
tensor-core matmul; CUDA graphs; multi-GPU; device transcript.

## 2. Design

### 2.1 One source, two compilers (the verifiability plan)

Every kernel is written once against `tc_prelude.cuh`.

* **Under nvcc**, the macros are plain CUDA: `TC_LAUNCH` becomes
  `<<<grid, block, 0, stream>>>`, `TC_SYNC` becomes `__syncthreads`, and
  `TC_ATOMIC_INC` becomes `atomicAdd`.
* **Without nvcc**, the same bodies are C++. A launch loops over blocks. A
  `TC_THREADS … TC_END_THREADS` phase loops over `threadIdx.x`. A phase
  boundary is the barrier, so shared-memory trees, the in-tile FFT layers and
  the last-block reduction run with their real indexing and data movement.
  Blocks run in order, which models the ticket counter exactly.
* `TC_PRIV` holds thread-private state across a barrier. In CUDA it is
  registers. In the emulation it is one row per thread.

The same host layer (`tc_host.cu`) is compiled into the emulation library
(`tc_emu.cpp`), and the same Zig backend links it. The only code that differs
between the two builds is the handful of `#if __CUDACC__` runtime calls
(cudaMallocAsync, memcpy, sync, managed memory).

The test file `cuda/test.zig` is shared too. `zig build test-cuda-emu` runs it
on the emulation, and `zig build test-cuda -Dcuda=true` runs the identical
assertions on the device. FlashProve uses the same trick at a smaller scale:
`LAZY_HD` in `prover/field/field_lazy.cuh` compiles its field code for host and
device.

The emulation does **not** model:
* warp-level behaviour (there are no shuffles, by rule);
* data races between blocks that are not ordered by a launch boundary or by
  the ticket;
* memory-model subtleties of the last-block pattern beyond the
  `__threadfence` + `volatile` read the kernels use;
* timing.

`compute-sanitizer --tool racecheck/synccheck/memcheck` on the device is
therefore part of the GPU test plan (§7).

### 2.2 Build integration (vs RV64 PR #314)

PR #314 (`origin/codex/rv64-cuda-ethereum`) compiles a large AOT-registered
.cu tree through Python build scripts into authenticated archives
(`scripts/rv64_cuda_native_library_build.py`,
`build_support/backends/cuda*.zig`, source-closure and authority gates). That
suits a product with many generated kernels.

The tensor backend has one translation unit, so it uses the simplest
dependable route:
* `-Dcuda=true` adds a Zig `Run` step: `nvcc -O3 -std=c++17 -arch=$cuda-arch
  -Xcompiler -fPIC -shared tc_host.cu -o libtensor_cuda.so`. Its inputs are the
  headers, so Zig caches and rebuilds it correctly.
* The module links the `.so` with an rpath. Exposing only the C ABI avoids any
  libstdc++/libc++ mixing between nvcc's host compiler and Zig.
* Options are `-Dcuda-arch=sm_90|sm_120` and `-Dnvcc=…`.
* `-Dcuda-emu=true` links the emulation into `tensor-bench` so that `--cuda`
  runs the emulated kernels. This is how `tensor_cuda_prove.sh` was
  dry-run here.

### 2.3 Residency plan (target) and where the current increment stands

Target, one proof:

```
host:   transcript (Blake2s channel), challenge draws, statement, proof bytes
PCIe:   per round 48 B up (3 QM31), 16 B down (challenge); per opening t column indices down, t columns + Merkle paths up
device: weights (int8, pinned once per serving session), witness tensors,
        eq/factor tables, sumcheck tables (folded in place), GKR layers,
        RS codewords (+ leaf states), Merkle nodes, weight-fold partials
```

| data | target | this increment (measured in the emulation's byte counters) |
|---|---|---|
| committed weights (int8) | uploaded once, `tc_pin` | `tc_pin` implemented and tested (second row-dots pass uploads only the 16·C-byte vector). The Zig side does **not** pin automatically. A serving loop must call `Cuda.pin(ws data)` and `unpinAll()`; addresses are not tracked across frees |
| witness tensors | produced on device by the forward pass | produced on the CPU; matmul accumulators computed on device, but X is uploaded and the int64 accumulators downloaded per matmul |
| sumcheck factor tables | built on device, folded in place | rounds are resident (one launch + 48 B per round; test-enforced budget: factors in once, `rounds x 48 B` + folded tail out). Materialised factors are uploaded from the host; `sc_begin_lazy` builds int/eq factors on the device (eq never crosses, test-enforced) |
| GKR layers | device, batched | CPU (accel.gkr_prove = null) |
| RS codewords | device; openings gather t columns | encoded on device into **managed** memory: the CPU's opening reads column-major columns, so only the opened columns' pages migrate. Merkle nodes are copied to the host (2E x 32 B) because `pcs.Merkle` owns host nodes |
| weight-fold partials | device | device; the result vectors (G x C QM31) come back |

Measured (emulation counters, `tensor_cuda_prove.sh small`):

| shape | launches | H2D | D2H | host syncs |
|---|---:|---:|---:|---:|
| product 14 | 49 | 1.3 MB | 2.3 MB | 13 |
| mlp 6/10/12 | 91 | 51 MB | 27 MB | 20 |
| layer 6/9/11/3 | 313 | 31 MB | 18 MB | 29 |
| model t=6 d=9 f=11, 2 layers, MoE e=2 | 755 | 98 MB | 51 MB | 65 |

The current increment is **not** "only transcript bytes cross PCIe". The
remaining traffic is the accel interface's host-owned tables:
* witness tensors;
* materialised sumcheck factors that the prover builds on the CPU;
* matmul in/out;
* Merkle nodes.

To close it, the protocol layer must keep tensor handles instead of host
slices. Concretely: `Accel` grows `DeviceTensor` handles, the forward pass runs
on the device, and the witness commitment reads the device witness. That is
the next increment (§6). At 1-4 GB of witness per decoder layer, the present
H2D volume would cost ~0.05-0.2 s per layer on PCIe 5 (~25 GB/s effective).
That is about the size of the projected kernel time itself (§5), so residency
is not optional for the GPU to pay off.

### 2.4 Streams, memory, synchronisation

* **Context.** One context per device and prover thread. Each context holds:
  * one non-blocking stream;
  * the device's default memory pool with the release threshold at max, so
    freed blocks are reused without driver calls. This gives the arena
    behaviour of FlashProve's `CardArena` without its manual lending, and a
    known peak after the first proof;
  * a 256-B pinned, host-mapped mailbox;
  * a device ticket counter;
  * a 1024-block partials buffer.

  All allocations, copies, launches and frees are stream-ordered
  (`cudaMallocAsync` / `cudaFreeAsync`).
* **Synchronisation.** The host blocks only where it needs a value: a round's
  3 QM31, an MLE value, or a call's final outputs. A sumcheck round is one
  kernel. Its last block writes the 3 QM31 straight into the mapped mailbox.
  The host then waits for the stream and reads 48 B: no memcpy launch and no
  second reduction kernel.
* **Failure.** Every launch is checked (`cudaGetLastError`). A failure poisons
  the context (`tc_ctx.failed`). Every later call returns an error, and the Zig
  hook surfaces `error.CudaFailed`. The proof fails. It is never published
  partially and there is no silent CPU fallback mid-proof. This mirrors PR
  #314's "launch or async failure poisons the job". Declines (shape outside
  kernel bounds) happen **before** any device work and fall back to the CPU
  for that call. They are counted (`declined`).
* **Several requests.** A serving prover proves several requests in parallel.
  It should run one context per request lane (separate streams) on a shared
  pinned weight copy. Pinned ranges are per context today, so sharing needs a
  device-level weight cache (§6). PR #314's credit ledger (per-job capacity
  charged against free device bytes) is the right admission policy once more
  than one lane runs per device.

## 3. Kernels, fusion and launch counts

| kernel | fusion | launches |
|---|---|---|
| `tc_sc_round` | fold of round k-1 + sums of round k, plus a grid-wide reduction (last block) | 1 per round |
| `tc_sc_fold` | last fold before the CPU tail | 1 per session |
| `tc_eq_halves` + `tc_eq_expand` | both half tables in one launch (block 0 / 1); expansion accumulates at offsets and broadcasts free bits | 2 per eq table / batch claim |
| `tc_int_to_qm` | int32 -> QM31 factor | 1 per int factor |
| `tc_combine_rows` + `tc_sum_chunks` | all G <= 4 groups per pass; int8 limbs exact in int64 | 2 per weight pass |
| `tc_row_dots_i8` | row per block, integer tree | 1 |
| `tc_mle_i32` | eq split hi/lo, inner sums lazily folded, grid reduction in the last block | 1 (+ 4 eq launches) |
| `tc_matmul_i32_i8` | 64x64 tiles, K step 32 | 1 per matmul |
| `tc_rs_expand` | the top log_b layers of a zero-padded row are copies | 1 per chunk |
| `tc_rs_layer` | one line layer, all rows | log_c - 11 per chunk (0 for log_c <= 11) |
| `tc_rs_tail` | layers min(log_c, 11)-1 .. 1 and the circle layer in shared memory (2^11-word tiles) | 1 per chunk |
| `tc_rs_leaves` | codeword transpose to column-major + Blake2s absorb (states carried across chunks) | 1 per chunk |
| `tc_merkle_level` / `tc_merkle_top` | levels above 2048 nodes one launch each; all lower levels in one single-block launch | log2(E) - 11 + 1 |
| `tc_gkr_layer` | **all instances of a layer in one launch** (binary search over output offsets) | 1 per GKR layer (not wired) |

**Per proof.** The emulation counts launches exactly:
* 313 for the small layer;
* 755 for the 2-layer MoE model.

Most of them are sumcheck rounds: one per device round, and device rounds run
while work >= `sc_min_work` (2^14 by default). Most of the rest are commit
chunks and eq builds.

**Projection for a 1024-token decoder layer** (counted from the stage
structure, not measured):
* about 40 sumcheck sessions x (14-18 device rounds + 1) ≈ 700 launches;
* eq builds 2 x ~60 claims ≈ 120;
* 3 commits x ~(4 + 9 Merkle) ≈ 40;
* matmuls / passes ≈ 20.

That is **≈ 900 launches**, or ≈ 2-5 ms of launch latency at 3-5 µs each.

**GKR.** The CPU GKR uses one fold and one sum per instance per layer. The
RV64 lesson: PR #314's Nsight full-block run recorded 88,171 kernel launches,
15-19k of them in GKR, because instances were launched individually. Fusing
fold and next-sum alone did not help (+1.8% wall), because mixed-height
instances split the batches. The tensor design avoids per-instance launches:
* one launch per GKR layer covers every instance, with a descriptor table of
  offsets;
* a GKR sumcheck round should likewise be one launch over all instances live
  at that round (an instance joins when the round index reaches its height).

With ~50 LogUp instances of heights 10-22 this gives about 22 layers x
(1 + 22 rounds) ≈ 500 launches, against ~50 x 22 x 22 ≈ 24k with
per-instance launches.

Next-level fusion, not done:
* **CUDA graphs.** A sumcheck session's launch sequence is fixed once its
  shape is known, so it can be captured as a graph. Only the challenge (16 B
  in the mailbox) changes between rounds. PR #314 deferred graphs, because its
  borrowed-lane custody forbade capture. Here a context owns its stream, so
  capture is allowed.
* **Device transcript.** FlashProve runs the Fiat-Shamir hash chain inside the
  kernel (`blocks/hash/lanes.cuh`, `chain_lanes.cuh`: one BLAKE2b compression
  by 4 lanes of a warp). A device Blake2s channel (our transcript is Blake2s,
  `transcript.zig`) would let a whole sumcheck run as one persistent kernel
  with no host round trip per round. It must produce byte-identical draws, and
  the host transcript would replay the mixed bytes to stay authoritative.

## 4. Acceleration ideas mapped from FlashProve (Goldilocks -> M31)

| FlashProve | what it does | tensor CUDA mapping |
|---|---|---|
| `field/lazy_gl64.cuh` (AccF/AccE, `reduce160`, MAC_ROOM) | sums of 64x64 products in 160-bit accumulators, one reduction | M31 is easier: a product is < 2^62, so 4 products sum in a u64 and are reduced once with the Mersenne fold `(x & p) + (x >> 31)`. `qm_mul` does 16 products with **6 reductions instead of 12**. The accumulators: `qacc` (2^33 canonical QM31 adds), `pacc` (running partial fold, unbounded count), `iacc` (signed int8 x QM31 in int64, 2^25 terms, exact) |
| `field/lazy_signed.cuh` (IAcc) | signed integer sums | `iacc`: int8 weight folds and row dots accumulate exact int64 limbs; the row-dots block tree adds integers, which is exact, and reduces once |
| `weights_commitment/unit_folds.cuh`, `fold_weights.cuh` | weights as balanced base-256 limb cells, column-major, grid-stride kernels | our committed cells are int8 already (one limb). Folds read the int8 table directly (1 B/weight from HBM) and never widen it. Column-major codeword so that an opened column is one contiguous R x 4 B run (also what lets managed memory migrate only opened pages) |
| `engine/fold.cuh` (CardFold, Gruen 2024/108 §5) | several sumcheck rounds from one pass over the table: build a Gram matrix G in one pass, run the rounds on the host from G, re-read once for the folded row | the analogue for our degree-2 weight-opening sumchecks: for k rounds, accumulate the 2^k x 2^k matrix sum_x f(b, x) g(b', x) in one pass. The rounds then cost no device passes, and one more pass folds at all k challenges (the Metal path's multi-round lazy fold is the same idea with corner weights). Not implemented in CUDA yet; for large first rounds it cuts k passes over the table to 2 |
| `hash/lanes.cuh`, `chain/chain_lanes.cuh` | BLAKE2b by 4 lanes per call; the hash chain inside kernels | (a) Merkle leaves: our column leaves are one long Blake2s per column (R words); a 4-lane-per-column split does not apply to a sequential chain, but node levels could use 4 lanes per node. (b) The device transcript (above) |
| `engine/arena.h` (CardArena) | all GPU memory taken at set-up and lent out; the peak is known before the first request | stream-ordered pool with an infinite release threshold (same steady state, no manual lending); a serving deployment should pre-reserve with `cudaMemPoolSetAttribute(ReservedMemCurrent)` and admit requests against the measured peak |
| `prover/weight_stream.cuh` | weights streamed from host memory (278 GB host RAM for Maverick on one H100) | for models whose int8 weights exceed HBM: per-layer double-buffered H2D from pinned host memory, overlapped with the previous layer's proving; amortised over the batch (§5.2) |
| `hash_commitment/hf_tree.cuh`, `hf_commit_*` | commitment trees with windows | Merkle top levels fused into one launch; leaf states carried across row chunks so the commit is streamable |

Known kernel-quality gaps, from the PTX:
* `tc_sc_round` keeps its factor arrays in local memory. The fix is to
  specialise on (n_factors, term shape) with templates. The prover uses about
  six shapes (`T_PROD2`, `T_EQ3`, `T_PRODUCT`, …), and specialising makes the
  term loops compile-time.
* Blake2s needs a compile-time sigma permutation (fully unrolled rounds), as
  the repo's `native/commitment/blake2s_core.cuh` already does.
* The tail FFT should use `__shfl_xor_sync` for the lowest 5 layers. That
  needs an emulated warp primitive first.
* The int8 matmul should use `dp4a` / IMMA tensor cores when the activations
  fit int8. The Metal path already splits int8 vs wide activations.

## 5. Projections (labelled; nothing here was run on a GPU)

### 5.1 Decoder layer, 1024 tokens

Method:
* Start from the measured Metal steady-state stage times (speed.md, M4 Max,
  410 GB/s unified memory).
* Scale the device-resident stages by the HBM bandwidth ratio at an assumed
  60% efficiency on the GPU: H100 SXM 3.35 TB/s, 0.60 x 3.35 / 0.41 ≈ 4.9x;
  RTX 5090 1.79 TB/s, ≈ 2.6x.
* Keep host-bound stages at their measured time unless the residency
  increment moves them.

| stage | Metal measured (s) | H100 projected, after full residency (s) | note |
|---|---:|---:|---|
| witness_commit | 0.233 | 0.05 | RS encode + Merkle, bandwidth bound |
| gkr | 0.448 | 0.09 | needs the batched device GKR (not wired) |
| op_sumchecks | 0.158 | 0.03 | |
| batch | 0.162 | 0.03 | |
| witness_open | 0.115 | 0.03 | column gathers from managed/device memory |
| ext_init + multiplicities + terminal | 0.061 | 0.06 | host today |
| transcript / host glue, launch latency (~900 launches) | – | 0.01 | |
| **prove** | **1.217** | **≈ 0.3** (range 0.2-0.5) | |

On an RTX 5090 the same method gives about 0.5 s. The current increment,
without the witness/forward residency, would be bound by the 1-4 GB of
witness and factor uploads: about +0.1-0.2 s per layer on PCIe 5.

### 5.2 Maverick-shaped request (1024 tokens), one H100

Inputs, from serving.md §4:
* witness per request n_w = 0.93-2.6e10 elements;
* CPU prove coefficient p = 40-55 ns per element on 12 threads.

The layer projection above is ≈ 4x faster than Metal and Metal is ≈ 1.4x faster
than the 12-thread CPU. That makes H100 ≈ 6x the CPU per element at full
residency, i.e. p_H100 ≈ 7-9 ns per element.
* **Witness proving:** 0.93-2.6e10 x 7-9 ns ≈ **65-235 s per request**.

**Weights.** int8 Maverick is 400.7 GB, which does not fit one 80 GB H100.
FlashProve streams its 4-bit weights from 278 GB of host memory. Streaming our
int8 table once per batch costs 400.7 GB / ~25 GB/s ≈ 16 s, or 0.7 s per
request at R = 24. The shared weight opening on the device is bandwidth bound
at ~0.2 s per pass.

**Result:** ≈ 70-240 s per request, or ≈ 4-15 tokens/s at R = 24, before any
algorithmic change. **FlashProve measures 9.2 s per request (111 tokens/s) on
one H100.** The gap is mostly witness volume, not kernel speed:
* our n_w per token is 10-25x FlashProve's committed request volume;
* we commit every int8 intermediate and keep per-table GKR instances unmerged
  (size.md §5).

A CUDA backend alone does not close that. It sets the floor for whatever
witness volume the protocol produces.

### 5.3 Memory budget (device bytes, per proof in flight)

The residency target, from the per-element costs in serving.md:
* about 130 B of working set per witness element;
* int8 weights 1 B per weight;
* codeword 4 B x 2^blowup per message element, kept only while openings are
  pending.

| shape | weights (int8) | witness working set | codewords (blowup 4) | total | fits |
|---|---:|---:|---:|---:|---|
| MLP 1024 tok, d=2^12, f=2^14 | 0.13 GB | ~1.5 GB | ~1.2 GB | ~3 GB | 5090 / H100 |
| decoder layer 1024 tok, D=4096 (tested shape class) | 0.2 GB | ~3-4 GB | ~2 GB | ~6 GB | 5090 / H100 |
| Maverick MoE layer (128 x 3 x 5120 x 8192 experts + shared + attention ≈ 16.3B weights) | 16.3 GB | ~55 GB (4.2e8 elements) | streamed | ~70 GB | H100 80 GB only with per-tensor streaming; not 5090 32 GB |
| Maverick dense layer (≈ 0.32B weights) | 0.32 GB | ~55 GB | streamed | ~56 GB | H100 |

At Maverick scale the witness, not the weights, sets the budget. A layer's
tensors must be committed and released tensor by tensor (the CPU recycler
already orders this), and the per-request memory admission must charge the
largest layer, not the model.

## 6. Next increments (in order)

1. **Run on a GPU host:** `scripts/tensor_cuda_test.sh sm_90` and
   `TENSOR_CUDA_SANITIZE=1`, then `tensor_cuda_prove.sh small|medium`. Fix
   whatever nvcc rejects.
2. Template `tc_sc_round` on term shapes, unroll Blake2s, then profile with
   Nsight (`nsys` launch/transfer counts against the emulation's counters).
3. Device GKR: `tc_gkr_layer` plus a batched multi-instance round kernel
   behind `accel.gkr_prove`, compared against `Fast.proveBatch` with the Metal
   GKR test.
4. Residency: device tensor handles in `Accel` (forward pass, witness commit
   and factor builders reading device tensors). This removes the H2D column of
   §2.3.
5. Gram-matrix multi-round folds for the weight-opening sumchecks; CUDA graphs
   per sumcheck session; device Blake2s transcript.
6. Device-level weight cache shared by request lanes; weight streaming for
   weights larger than HBM.

## 7. GPU test plan

On the GPU host (zig 0.15.2, CUDA >= 12.8, driver; RTX 5090 = sm_120,
H100 = sm_90):

```
scripts/tensor_cuda_build.sh sm_90           # nvcc .so + tensor-bench with --cuda
scripts/tensor_cuda_test.sh sm_90            # emulation suite, device suite, CPU suite
TENSOR_CUDA_SANITIZE=1 scripts/tensor_cuda_test.sh sm_90   # + memcheck/racecheck/synccheck
scripts/tensor_cuda_prove.sh small           # CPU vs --cuda digests: product, mlp, layer, MoE model
scripts/tensor_cuda_prove.sh medium          # 2^20-element / 1024-token class shapes
```

Pass criteria:
* every device test passes. These are the same assertions as the emulation:
  bit-identical proofs, transfer budgets, launch counts per sumcheck;
* the sanitizers are clean;
* every `prove.sh` line prints `SAME`.

Then record `nsys profile --stats=true` for `layer 10 12 14 5` and compare
its launch and memcpy counts with the `"cuda"` counters the bench prints.
