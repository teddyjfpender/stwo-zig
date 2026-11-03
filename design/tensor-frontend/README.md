# stwo-tensor: provable integer inference on stwo-zig

A tensor frontend for stwo-zig that proves integer neural-network computations
(matrix multiplies, requantization, activations, attention) directly, instead
of running them through the RV64 zkVM. It targets the same statement class as
Anthropic's FlashProve ("the committed integer model, run on this prompt,
produces these outputs"), and is benchmarked against it.

Package: `src/tensor/` (standalone `build.zig`; `zig build test`,
`zig build -Doptimize=ReleaseFast` builds `tensor-bench`).

## Statement

* **Weights** are int8 matrices committed **once** (offline) in a multilinear
  commitment. Their proximity proof is also generated once and checked once by
  each client; it is part of the weight key.
* **Per batch**, the prover commits a **witness table** (activations, lookup
  multiplicities). It then proves a list of ops over committed tensors:

  | op | semantics |
  |---|---|
  | `matmul` | `Y = requant_s(X . W)`, with X and Y witness, W a weight |
  | `hadamard` | `Y = requant_s(A (.) B)` |
  | `lookup` | `Out[i] = table[In[i]]`, an int8 -> int8 public table (e.g. SiLU) |
  | `range8` | `In[i] in [-128, 128)` |
  | `product` | `c = a (.) b` over M31 (FlashProve's toy statement) |

  Attention, softmax, RMSNorm, RoPE and residual ops are added on the
  `codex/tensor-attn` stream; see `transformer.md`.
* `requant_s(acc) = floor((acc + 2^(s-1)) / 2^s)`, defined only when the result
  lies in [-128, 128). As in FlashProve, the integer model is undefined when an
  intermediate leaves its interval. Accumulators stay below 2^30 (int8 x int8,
  K <= 2^15), so M31 arithmetic never wraps.

## Protocol (v1)

1. **Multilinear PCS over M31** (Ligero/Brakedown style, `pcs.zig`).
   * Layout: tables are R x C. Rows are circle-polynomial coefficients,
     RS-encoded with stwo's circle FFT at rate 2^-lb.
   * Commitment: Merkle tree (Blake2s) over the encoded columns.
   * Opening: each claim group (claims that share the column part of the point)
     sends one combined row `u = sum_i a_i row_i`. The verifier checks
     `<u, eq(z_col)> = sum gamma_c v_c`, then checks t random columns against
     `Enc(u)`.
   * Proximity: weights are tested once at commit time. The witness is tested
     per batch.
2. **Virtual remainders.** The requant remainder `r = acc + 2^(s-1) - 2^s Y`
   is never committed. LogUp-GKR proves the range checks `r in [0, 2^s)` and
   `Y + 128 in [0, 256)`. Its terminal claim on r gives `acc(rho)` by linearity,
   and a matmul sumcheck (Thaler) reduces that to `X(rho_t, r_k)` and
   `W(r_k, rho_n)`.
3. **One batched LogUp-GKR** (stwo's fast GKR prover) covers every range and
   lookup relation of the batch. With a *multilinear* PCS, GKR's terminal claims
   bind directly to committed tensors. There are **no Eq/prefix binding
   columns**, which were the cost centre of the RV64 GKR-to-MAIN bridge.
4. **Claim batching.** All witness claims are reduced by one sumcheck to a
   single point, which gives one witness opening. All weight claims share their
   column point (the common GKR ood suffix), so the weights are opened with
   **one combined row per batch**. Every matmul in the batch shares one pass
   over each weight matrix.

## Metrics, driven like instructions/gas and bits/gas

| metric | meaning |
|---|---|
| prove ns per witness element | all-in prover cost per committed activation |
| committed bits per token | witness table size x 32 / tokens |
| weight-pass ns per weight | int8 x QM31 fold and combine kernels |
| proof bytes per batch / request | split into GKR, sumchecks, witness opening, weight opening |
| verify time | single thread |
| conjectured / proven security bits | `security.zig` sums every error term (bench `"security"`); see `security.md` |

## Benchmarks

`scripts/tensor_compare.py run|report` runs the matrix under memguard and
writes `COMPARISON.md`. FlashProve was measured on the same machine
(`vectors/reports/tensor-frontend-20261103/flashprove-cpu-baseline/`); its
published H100 figures are also listed.

Comparability rules:

* **Same statement, same machine.** FlashProve's CPU toy is
  `blocks/toy/product.h`, `a (.) b = c` over 2^L. We run the identical
  statement, and report security under two regimes:
  * *proven*: unique decoding, BCIKS20 correlated agreement;
  * *conjectured*: up to capacity.

  FlashProve's toy runs with hiding on. Our hiding mode (stream `zk`) is
  reported separately.
* **Model scale.** Maverick does not fit on this 36 GB laptop. We measure
  layers at Maverick-like dimensions and project per-request cost from the
  measured per-element and per-weight coefficients. Each projection lists its
  inputs explicitly. FlashProve's published numbers are per H100. We give the
  projection on this Mac, and any cross-hardware ratio is labelled as an
  estimate.

## Status and caveats

* v1 is **non-hiding**. Zero knowledge (salted leaves, masked encodings,
  masked sumcheck and GKR) is the `codex/tensor-zk` stream.
* The weight range proof (weights in [-128, 128)) is required for the
  accumulator-bound argument when the weight committer is malicious. Not yet
  added; tracked.
* Per-request proofs: v1 proves one batch per proof. A FlashProve-style variant
  (independent per-request proofs that share one weight opening) is planned.
