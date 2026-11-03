# Tensor prover on Metal (Apple GPU, unified memory)

Branch `codex/tensor-metal`. The Metal path is selected per proof by
`protocol.Config.accel` (`tensor-bench ... --metal`). It produces
**bit-identical proofs** to the CPU path: every proof field is identical, the
transcript is the same, and so is every byte the verifier sees.

## Design

### Hook

`src/tensor/accel.zig` defines `Accel`, a vtable that any entry may decline by
returning null. `protocol.zig`, `weight_key.zig` and `model.zig` call through
small dispatch helpers, and each helper falls back to the unchanged CPU code:

| helper | replaces | device work |
|---|---|---|
| `accel.commit` | `pcs.commit` (witness and weight tables) | row encoding, Blake2s leaves, Merkle tree |
| `accel.proveActive` | `sc.proveActive` (op sumchecks) | round sums, folds |
| `accel.batchProve` | the inline claim-batching block | F/E construction, round sums, folds |
| `accel.gkrProveBatch` | `gkr_prover_fast.proveBatch` (per batch and weight key) | layer build, round sums, folds |
| `accel.matmulAcc` | `matmulAcc` (prover accumulators and forward pass) | int8 matmul |
| `accel.mleEvalI32` | `f.mleEvalI32` (GKR terminal claims) | eq-weighted reduction |
| `accel.proveFactors` | product-op factor construction + `proveActive` | lazy round 0 over implicit factors |
| `accel.colCombine` / `accel.rowDots` | `linalg` weight passes in matmul ops | int x QM31 folds |
| `Committed.combine` (set by device commit) | `pcs.combineRows` in `pcs.open` | int x QM31 row combination |
| `Committed.enc_owner` (set by device commit) | `a.free(enc)` | codeword stays in a device buffer |

The CPU keeps all Fiat-Shamir work: channel mixing and draws, round-polynomial
assembly, interpolation, `correctSumAsPolyInFirstVariable`, and the PCS
opening. The device does the data-parallel passes. Field arithmetic is exact,
and the device computes the same functions (not merely equivalent ones), so a
reduction's order cannot change a result. The only exception is the fp32
matmul, which is exact by bound (see below).

The edits to shared files are one-line call-site swaps, plus a few defaulted
fields: `Config.accel`, `Mlp.accel`, `pcs.Committed.combine` and
`pcs.Committed.enc_owner` (both null unless a device commit sets them). Two
`Timings` fields are new, `prep_ns` and `terminal_ns`, for regions that were
not timed before.

### Runtime (`metal/runtime.m`, `metal/gpu.zig`)

The runtime is a minimal Objective-C layer with a flat C ABI: device, queue,
`newLibraryWithSource` (safe math, MSL 3.1), pipelines, shared buffers, and one
serial compute encoder per command buffer. It follows the conventions of the
stwo-zig Metal backend. It does not go through the backend's
admission/AOT-identity machinery, which is built around the RV64/Cairo
commitment engine.

**Kernel reuse.** The library is the backend's own MSL, embedded at build time:

* `include/{base, m31, extension_fields, blake2s, blake3, merkle, poseidon2_m31, circle}.metal`
* `core/{circle_transform, circle_transform_wide, commitments}.metal`

The tensor path dispatches the backend kernels `stwo_zig_circle_rfft_layer`
(global FFT layers) and `stwo_zig_blake2s_parents_plain_sparse` (Merkle
parents) directly. Its own kernels in `metal/kernels.metal` use the backend's
`m31_*`, `qm_*`, `blake2s_compress` and `circle_twiddle`.

**Unified memory.** `Gpu.view` wraps any host slice without copying, using
`newBufferWithBytesNoCopy` over the page span plus an offset. Inputs (witness
table, weights, QM31 vectors) and outputs (the codeword the opening reads)
alias host memory. Measured copies are 0.5 MB per MLP proof.

**Device memory.** The commitment codeword lives in a device buffer owned by
`Committed` (`enc_owner`). Large device scratch comes from a size-class pool:
8 classes per power of two, buffers up to 1 GiB, 3 GiB in total. After a
one-off huge GKR batch (the weight key) the pool is trimmed. `Gpu.trim()`
releases everything. The `Gpu` is single-threaded: protocol code calls it
from one thread.

### Commitment (priority 1)

Rows are circle-polynomial coefficients, zero-padded from C to E = C·2^lb.

1. **Expansion.** The top `lb` FFT layers of a zero-padded row only copy the
   low half, so `tm_expand_{i8,i32}` writes `2^lb` copies of the coefficients
   (int to M31).
2. **Global layers** `log C - 1 .. 12` use the backend's
   `stwo_zig_circle_rfft_layer`.
3. **Tail.** `tm_rfft_tail` does layers `11..1` and the circle layer in
   threadgroup memory, over 4096-value tiles. Its twiddle indexing matches
   `evaluateBufferWithTwiddles`.
4. **Leaves.** `tm_leaf_absorb` streams Blake2s over each column's M31 LE
   words. Its state survives across row chunks: each chunk is a multiple of 16
   rows, so message blocks never straddle chunks. The same pass writes the
   column-major codeword that `pcs.open` reads.
5. **Parents.** The backend's Blake2s parent kernel builds one level per
   dispatch.

All of this runs in a single command buffer. The row-major scratch is capped
at 256 MiB, so the 1.6 GB weight codeword streams through chunks.

### Sumchecks (priority 2)

* **Generic `proveActive`.** Device rounds run while `work >= sc_min_work`
  (2^14). Round k+1's kernel folds round k (in place, with disjoint index sets
  per thread) and computes the sums s(0), s(2), s(3) in one pass. Threadgroup
  partials are added on the host. The last fold leaves a small prefix, and the
  CPU prover finishes it.
* **Lazy factors** (`accel.proveFactors`, `tm_lazy_round0` / `tm_lazy_fold0`).
  Up to four factors are given implicitly. Each is either an int32 vector or a
  sum of eq tables placed at offsets, E(x) = Σ_c γ_c·pre_c[i >> lo]·suf_c[i & mask]
  with i = x − off_c. The prefix (x) suffix tables are built on the CPU, at
  about 2^12 entries each. Round 0 and its fold evaluate the factors on the fly
  and write half-size QM31 factors for the generic rounds, so no full-length
  factor is ever materialised. The claim-batching sumcheck is
  (F = witness table, E = batched eq), and the product op is
  (eq(ρ), a, b, c) with degree-3 terms.

### LogUp-GKR (priority 3)

`metal/gkr.zig` is a line-for-line port of `gkr_prover_fast.proveBatch`. It
makes the same channel calls in the same order, does the same poly
construction, and runs the same self-checks. The layers live in device memory.

* **Kernels.** `tm_gkr_next` builds the fraction tree (ones, base and secure
  numerators). `tm_gkr_sum` computes the round sums, generating the eq table on
  the fly from a prefix (x) suffix split of `ood`. `tm_gkr_fold` folds in place
  for owned layers. Borrowed inputs and base numerators fold into fresh
  buffers, so borrowed inputs are never written.
* **One command buffer per round.** A round's folds and the next round's sums
  share it.
* **Small layers stay on the CPU.** Layers of at most 2^9 terms are summed and
  folded by the CPU directly in the shared buffers. This saves a GPU round
  trip, and the sweep below shows the effect.

### Weight passes (priority 4)

* **`tm_combine_rows`.** Computes out[g][c] = Σ_i coeff[g][i]·m[i][c] over int8
  or int32 rows, for up to 4 groups. Row chunks run in parallel, and the host
  adds the partials. It serves `pcs.open` and the X(ρ_t, ·) fold of matmul ops.
* **`tm_row_dots`.** Computes out[k] = Σ_n m[k][n]·vec[n], the W(·, ρ_n) weight
  fold, with one threadgroup per row.
* **Exactness.** Accumulation is field-exact (`qm_mul_m31` / `qm_add`), so the
  values equal the CPU's int64 limb accumulation.

### Matmul and MLE evaluation

* **`tm_matmul_simd`.** This kernel runs on `simdgroup_float8x8` when
  |x| <= 128 (checked on the host). Each fp32 partial sum is an integer below
  2^23 (512-wide K chunks of |x·w| <= 2^14), and each chunk is flushed to int64.
  The test includes odd worst-case products that would round past 2^24, and a
  mutation that disables the flush is caught.
* **`tm_matmul_i32_i8`.** The fallback for |x| < 2^15 uses int32 chunk sums.
  Above that, the CPU kernel runs.
* **`tm_mle_i32`.** This evaluates the terminal claims, with eq factored as
  prefix (x) suffix.

## Verification

`zig build test-metal`, run under `memguard`, has 10 tests. They pass in Debug
and in ReleaseFast.

* **Commitment.** The encoded codeword, every Merkle node and the root match
  for i8 and i32 tables, lb = 1..3, odd `rows_used`, and multi-chunk streaming.
* **Sumcheck.** Rounds, points, finals and transcript state match for degree
  2 and 3 and for partial `active`.
* **Batch sumcheck.** Overlapping claims, a 0-variable claim and partial
  `active` are covered, both for many device rounds and for the lazy-round-0-only
  path.
* **Lazy factors.** Two overlapping eq claims plus three full-range int vectors
  under the degree-3 product terms, with full and partial `active`, and both
  many device rounds and a single lazy round.
* **Matmul.** Covered: int8 (fp32 units), wide (int32), unaligned weight views,
  and the decline path. The int8 case includes odd worst-case products whose
  unflushed fp32 sums would round, and a mutation that disables the flush is
  caught.
* **Weight passes.** `combineRows` (i8 through an unaligned view and i32,
  partial `rows_used`, 3 groups, multi-chunk) and `rowDots`.
* **MLE.** 0 to 17 variables, with zero, int8 and full-range values.
* **GKR batch proof.** Mixed instance sizes (2^1 to 2^15) and ones, base and
  secure numerators. Owned and borrowed inputs are both covered, and borrowed
  inputs are checked to be unmodified. Three CPU/device splits are tested,
  including all-device, each with the fold fused and unfused (24
  configurations).
* **Proof digest equal to CPU: product toy.** The GPU proof also verifies.
* **Proof digest equal to CPU: small MLP.** This test covers the GPU weight
  commitment, the GPU forward witness (identical tensors), the GPU weight-key
  proof (same `keyProofDigest`, and it verifies) and the GPU proof (verifies).

`digest.proofDigest` hashes every field of a proof. The bench prints
`proof_digest` and `key_proof_digest`, so full-scale runs are compared too. All
measured runs below have identical digests on both paths. The CPU suite
(`zig build test`) is unchanged and green, and `-Dmetal=false` builds and
tests without Metal.

## Measurements

Host: M4 Max (12 CPU threads used), AC power, `memguard`. The host was shared:
an active Chrome session (around 240% CPU), other builds, and memory pressure
(about 25 GB in the compressor, active swap-outs), so expect ±10–20% noise.
`TENSOR_REPS=3` reports the best of three proves; every rep must have the same
digest. Each row comes from 2 independent runs. Raw JSON is in
`~/Coding/ge-cache/tensor-metal/final/`.

### MLP block (`mlp 10 12 13 12 64 2 20`, 1024 tokens, 4096×8192, fused SwiGLU)

Proof digest `411de382…` and weight-key digest `9d1222b2…` on both paths;
proof size 7.50 MB; verify 27 ms.

| stage (s) | CPU | Metal | speedup |
|---|---:|---:|---:|
| prep (accumulators = 3 matmuls, multiplicities) | 0.51–0.58 | 0.079–0.097 | ~6× |
| witness_commit | 0.34–0.37 | 0.042–0.050 | ~7.5× |
| gkr (incl. ~20–35 ms CPU key/table denominators) | 0.26–0.28 | 0.103–0.113 | ~2.5× |
| terminal (GKR claims → MLE evals) | 0.38–0.39 | 0.004–0.006 | ~80× ¹ |
| op_sumchecks | 0.017–0.019 | 0.008–0.010 | ~2× |
| weight_fold | 0.014–0.016 | 0.004–0.006 | ~3× |
| batch | 0.36–0.46 | 0.032–0.036 | ~11× |
| witness_open | 0.021–0.026 | 0.012–0.015 | ~1.7× |
| weight_open | 0.018–0.020 | 0.010–0.020 | ~1.3× |
| **prove, best of 3** | **1.92–2.17** | **0.30–0.34** | **6.4×** |
| prove, first of 3 | 2.06–2.22 | 0.41–0.43 ² | ~5× |
| forward (witness generation) | 0.57–0.62 | 0.10–0.13 | ~5× |
| **forward + prove (best)** | **2.49–2.79** | **0.40–0.47** | **~6×** |
| commit weights (offline) | 0.68–0.69 | 0.11–0.13 | ~5.5× |
| weight-key proof (offline) | 1.17–1.30 | 0.46–0.60 | ~2.3× |

¹ The CPU terminal stage calls `f.mleEvalI32`, which is serial; a parallel CPU
version would take roughly 0.04 s. Not changed here, because the CPU path is
the reference.

² With the weight-key proof on the CPU (`TENSOR_KEY_CPU=1`). After a device
key proof, the first prove measured 0.72–1.22 s; best of 3 was 0.34 s. See
"What remains".

### Other sizes (`product <n> 12`: best of 3; `mlp 8 10 11`: `TENSOR_REPS=3`)

| statement | CPU prove (s) | Metal prove (s) | speedup | digest |
|---|---:|---:|---:|---|
| product 2^20 (FlashProve toy) | 0.059 | 0.0155 | 3.8× | `c8d2a728` = |
| product 2^22 | 0.214 | 0.040 | 5.4× | `4584420c` = |
| product 2^24 | 1.018 | 0.108 | 9.4× | `d7147780` = |
| mlp 8 10 11 (256 tokens, 1024×2048) | 0.122 | 0.047 | 2.6× | `923b4163` = |

### Progression (mlp 10 12 13; key proof on the CPU, best of 3 unless noted)

| step | prove (s) |
|---|---:|
| CPU | 1.85–2.17 |
| + commitments and sumchecks (single run) | 1.45–1.70 |
| + device batch factors | 1.45 |
| + matmul accumulators, terminal MLE evals | 0.76 |
| + LogUp-GKR | 0.55 |
| + fp32 matrix-unit matmul, lazy batch round 0, pool | 0.39 |
| + weight passes | 0.35–0.38 |
| + device-owned codeword, size-class pool | 0.30–0.31 |

### Tried and rejected (measured)

| experiment | outcome |
|---|---|
| 4 simdgroups × 32×32 matmul fragments (vs 8 × 16×32) | matmul 16 → 45 ms per call (register spill); reverted |
| lazy-reduction QM31 multiply (16 folded 64-bit products) instead of the backend's Karatsuba `qm_mul` | GKR device time 45 → 62 ms (64-bit ops are slow on the GPU); reverted |
| fused GKR fold + next-round sums (`gkr_fused_fold_sum`) | 50.5 vs 45 ms; kept as an option, off by default |
| spin-wait instead of `waitUntilCompleted` | no measurable change; reverted |

### GKR CPU/device split (`TENSOR_GKR_CPU_LOG=k`)

Layers of at most 2^k terms run on the CPU, inside the shared buffers.

| k | gkr stage (s) |
|---|---:|
| 0 (all device) | 0.196–0.198 |
| 4 | 0.171–0.190 |
| 6 | 0.169–0.170 |
| 8 | 0.165–0.167 |
| 10 | 0.152–0.171 |
| 12 | 0.171–0.185 |

The default is k = 9. These numbers were taken before the buffer pool existed.

## What remains

* **GKR inputs on the device.** `keyValues`/`tableDen` (about 20–35 ms) still
  build 740 MB of QM31 denominators on the CPU, which the device then wraps.
  The fix is a lazy input level, built on the device from witness tensors and
  accumulators. It needs a `protocol.zig` restructure: key kinds are protocol
  internals.
* **Multiplicities.** They are counted serially on the CPU (about 25 ms of
  `prep`). A device histogram needs a fallback that keeps the exact CPU error
  reporting for invalid witnesses, and the glu check needs `gluValue` on the
  device.
* **GKR rounds** are bound by QM31 multiplies on the device (about 45 ms over
  253 rounds), plus about 20 ms of per-round host work and latency.
  Challenges come from the CPU transcript, so rounds cannot be chained on the
  device.
* **Codeword layout.** The opening reads only `n_queries` columns, yet the
  commit writes the whole column-major codeword (now into device memory).
  Gathering the queried columns from the row-major scratch on demand would
  remove that pass. It needs a `pcs.Committed.column` hook.
* **First prove after the device weight-key proof.** It measured 0.5–1.4 s,
  while the best of 3 was 0.34 s. This happened on a host with heavy memory
  pressure, and trimming the pool did not remove it. Needs a quiet-host A/B.
* **A ReleaseFast-only CPU test failure.** `zig build test -Doptimize=ReleaseFast`
  fails `sumcheck product and triple roundtrip` already at the base commit
  `7e2fa9490`. Debug and ReleaseSafe pass, which points to undefined behaviour
  (the recent QM31 lazy-reduction change is a candidate). It is not caused by
  this branch, and the Metal suite passes in ReleaseFast. Device proofs match
  the CPU at full scale in ReleaseFast.
* **Zero knowledge.** The ZK stream (`codex/tensor-zk`) will add masking and
  salts. The device kernels are field-generic and will need the masked
  variants once that protocol lands.
