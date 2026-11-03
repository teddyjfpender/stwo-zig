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

The CPU keeps all Fiat-Shamir work: channel mixing and draws, round-polynomial
assembly, interpolation, `correctSumAsPolyInFirstVariable`, and the PCS
opening. The device does the data-parallel passes. Field arithmetic is exact,
and the device computes the same functions (not merely equivalent ones), so a
reduction's order cannot change a result. The only exception is the fp32
matmul, which is exact by bound (see below).

The edits to shared files are one-line call-site swaps, plus a defaulted
`Config.accel` and `Mlp.accel` field and two new `Timings` fields (`prep_ns`,
`terminal_ns`, for regions that were not timed before).

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
alias host memory. Measured copies are 0.5 MB per MLP proof. Large
device-allocated scratch comes from a power-of-two pool, capped at 2 GiB with
512 MiB per buffer.

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
* **Claim batching.** Neither factor is materialised at full size.
  `tm_batch_round0` and `tm_batch_fold0` evaluate F = wtab and
  E = Σ_c γ_c·pre_c[i >> lo]·suf_c[i & mask] on the fly. The prefix (x) suffix
  eq tables are built on the CPU, at about 2^12 entries each. The fold writes
  half-size QM31 factors for the generic rounds.

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

`zig build test-metal`, run under `memguard`, has 8 tests:

* **Commitment.** The encoded codeword, every Merkle node and the root match
  for i8 and i32 tables, lb = 1..3, odd `rows_used`, and multi-chunk streaming.
* **Sumcheck.** Rounds, points, finals and transcript state match for degree
  2 and 3 and for partial `active`.
* **Batch sumcheck.** Overlapping claims, a 0-variable claim and partial
  `active` are covered, both for many device rounds and for the lazy-round-0-only
  path.
* **Matmul.** Covered: int8 (fp32 units), wide (int32), unaligned weight views,
  and the decline path.
* **MLE.** 0 to 17 variables, with zero, int8 and full-range values.
* **GKR batch proof.** Mixed instance sizes (2^1 to 2^15) and ones, base and
  secure numerators. Owned and borrowed inputs are both covered, and borrowed
  inputs are checked to be unmodified. Three CPU/device splits are tested,
  including all-device.
* **Proof digest equal to CPU: product toy.** The GPU proof also verifies.
* **Proof digest equal to CPU: small MLP.** This test covers the GPU weight
  commitment, the GPU forward witness (identical tensors), the GPU weight-key
  proof (same `keyProofDigest`, and it verifies) and the GPU proof (verifies).

`digest.proofDigest` hashes every field of a proof. The bench prints
`proof_digest` and `key_proof_digest`, so full-scale runs are compared too. All
measured runs below have identical digests on both paths. The CPU suite
(`zig build test`) is unchanged and green.

## Measurements

Host: M4 Max (12 CPU threads used), AC power, `memguard`. The host was shared:
an active Chrome session (around 240% CPU) and another build were running, so
expect ±10–20% noise. `TENSOR_REPS=3` reports the best of three proves; every
rep must have the same digest. Raw JSON is in
`~/Coding/ge-cache/tensor-metal/final/`.

### MLP block (`mlp 10 12 13 12 64 2 20`, 1024 tokens, 4096×8192, fused SwiGLU)

Proof digest `411de382…` on both paths, 7.50 MB.

| stage (s) | CPU | Metal | speedup |
|---|---:|---:|---:|
| prep (accumulators = 3 matmuls, multiplicities) | 0.487–0.525 | 0.088–0.107 | ~5× |
| witness_commit | 0.326–0.329 | 0.062–0.068 | ~5× |
| gkr (incl. 35 ms CPU key/table denominators) | 0.250–0.304 | 0.107–0.167 | 2–2.5× |
| terminal (GKR claims → MLE evals) | 0.374–0.387 | 0.004–0.008 | ~60× ¹ |
| op_sumchecks | 0.017 | 0.016 | (CPU-sized) |
| weight_fold | 0.014 | 0.013 | (CPU) |
| batch | 0.355–0.367 | 0.045–0.058 | ~7× |
| witness_open | 0.019–0.022 | 0.019–0.029 | (CPU) |
| weight_open | 0.015–0.018 | 0.015–0.019 | (CPU) |
| **prove (best of 3)** | **1.85–1.98** | **0.39–0.45** | **4.4–4.8×** |
| forward (witness generation) | 0.49–0.53 | 0.11–0.13 | ~4.3× |
| **forward + prove** | **2.35–2.51** | **0.50–0.57** | **~4.5×** |
| commit weights (offline) | 0.66 | 0.11–0.12 | ~5.7× |
| weight-key proof (offline) | 0.94–0.97 | 0.48–0.49 | ~2× |

¹ The CPU terminal stage calls `f.mleEvalI32`, which is serial; a parallel CPU
version would take roughly 0.04 s. Not changed here, because the CPU path is
the reference.

### Other sizes

| statement | CPU prove (s) | Metal prove (s) | speedup | digest |
|---|---:|---:|---:|---|
| product 2^20 (FlashProve toy) | 0.059 | 0.023 | 2.6× | `c8d2a728` = |
| product 2^22 | 0.231 | 0.060 | 3.9× | `4584420c` = |
| product 2^24 | 1.043 | 0.216 | 4.8× | `d7147780` = |
| mlp 8 10 11 (256 tokens, 1024×2048) | 0.115 | 0.048 | 2.4× | `923b4163` = |

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

The default is k = 9. These numbers were taken before the buffer pool existed,
which brought the stage to about 0.11 s.

## What remains

* **GKR inputs on the device.** `keyValues`/`tableDen` (about 35 ms) still build
  740 MB of QM31 denominators on the CPU, which the device then wraps. Building
  them on the device (from witness tensors and accumulators) would remove both
  the host allocation and the pass.
* **Multiplicities.** They are counted serially on the CPU (about 25 ms of
  `prep`). A device histogram (atomics) needs a fallback that keeps the exact
  CPU error reporting for invalid witnesses.
* **GKR round latency.** About 250 rounds each pay one command-buffer round
  trip on the large layers. Chaining several rounds with on-device challenge
  derivation is not possible, because challenges come from the CPU transcript.
  Larger instance batching per round is possible.
* **Weight passes** (`weight_fold`, the `combineRows` in openings) remain on
  the CPU (priority 4). They are about 30 ms per batch, plus the combine inside
  the offline key proof.
* **Codeword layout.** The opening reads only `n_queries` columns, yet the
  commit writes the whole 537 MB column-major codeword to host memory. A
  `Committed` that keeps the row-major codeword on the device and gathers
  queried columns on demand would remove that write. It needs a `pcs.zig`
  change.
* **Open question.** After the offline weight-key GKR runs on the device, the
  next per-batch proofs measured 0.43–0.45 s (gkr 0.16 s) against 0.39–0.40 s
  (gkr 0.11 s) with the key proof on the CPU (`TENSOR_KEY_CPU=1`). Device time
  of the GKR rounds roughly doubles. Trimming the pool did not settle it
  conclusively on the shared host. Needs a quiet-host A/B.
* **Zero knowledge.** The ZK stream (`codex/tensor-zk`) will add masking and
  salts. The device kernels are field-generic and will need the masked
  variants once that protocol lands.
