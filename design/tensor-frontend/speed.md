# Tensor frontend: prover speed, round 2 (stream `speed`)

Branch `codex/tensor-r2-speed`, based on `codex/tensor-frontend` at `61ba1ce6c`.
Host: M4 Max (12 P + 4 E cores), AC power, 12 prover threads, `memguard`.
Other agents shared the host throughout (load average 4–8); every number below
comes from base and new binaries run back to back with the same arguments, and
noisy outliers were re-run. Raw JSON is in `~/Coding/ge-cache/tensor-speed/final/`.

**Proofs are byte-identical.** Every change is prover-side, apart from one
verifier bug fix that rejects nothing the old verifier accepted (see §Bugs).
Base and new produce the same `full_digest` (proof digest plus ext part) at
every size, on CPU and Metal, in single-shot and steady-state runs. The
decoder-layer and recommended-config goldens were recorded on the unmodified
prover and are pinned in the tests.

## Results

Benches (recommended config, see §Defaults):

* decoder layer `L9` / `L10`: `tensor-bench layer {9|10} 11 12 4 12 54 2 20 2 1 0 {9|10} 1 2 54 [--metal]`
  (D = 2048, F = 4096, 16 q / 4 kv heads, 512 / 1024 tokens, pcs2 + batched matmuls).
* MLP `M10`: `tensor-bench mlp 10 12 13 12 64 2 20 2 54 2 20 [--metal]` (1024 tokens, 4096 × 8192, fused SwiGLU).
* single shot: one prove per process. Steady state: `TENSOR_RECYCLE=1 TENSOR_PROVE_REPS=3`, best of 3, and
  every rep must reproduce the first proof's digest.

| bench | path | mode | base prove (s) | new prove (s) | speedup | proof | verify |
|---|---|---|---:|---:|---:|---:|---:|
| layer, 512 tok | CPU | single | 1.51 | 1.09 | 1.38× | 460,328 B | 14 ms |
| layer, 512 tok | Metal | single | 1.02 | 0.69 | 1.48× | | |
| layer, 512 tok | CPU | steady | 1.06 | 0.67 | 1.58× | | |
| layer, 512 tok | Metal | steady | 0.82 | 0.52 | 1.58× | | |
| layer, 1024 tok | CPU | single | 4.16–4.38 | 2.71–2.82 | 1.54× | 513,456 B | 35 ms |
| layer, 1024 tok | Metal | single | 2.96 | 1.60 | 1.85× | | |
| layer, 1024 tok | CPU | steady | 3.08–3.15 | 1.75–1.76 | 1.78× | | |
| layer, 1024 tok | Metal | steady | 2.38–2.76 | 1.20–1.22 | 2.0–2.3× | | |
| MLP, 1024 tok | CPU | single | 1.05 | 0.76 | 1.38× | 423,344 B | 3.3 ms |
| MLP, 1024 tok | Metal | single | 0.60 | 0.50 | 1.21× | | |
| MLP, 1024 tok | CPU | steady | 0.82 | 0.51 | 1.60× | | |
| MLP, 1024 tok | Metal | steady | 0.33 | 0.31 | ~1.07× (noise) | | |

The forward pass (witness generation) also got faster: layer 1024 0.79 → 0.37 s on
the CPU and 0.81 → 0.24–0.27 s with `--metal` (GEMM einsums, device matmuls). The
prover no longer recomputes accumulators that the forward pass already has.

Digests: layer 512 `48cfb9d1…`, layer 1024 `925aad4a…` (`full_digest`;
`proof_digest` `0bdd02cc…`), MLP `fc34ba94…`. All base/new and CPU/Metal pairs
are equal.

### Per-stage, decoder layer 1024 tokens, single shot (s)

| stage | CPU base | CPU new | Metal base | Metal new |
|---|---:|---:|---:|---:|
| **prove** | **4.226** | **2.707** | **2.962** | **1.601** |
| accumulators (recompute) | 0.190 | 0 (forward) | 0.041 | 0 (forward) |
| multiplicities | 0.100 | 0.019 | 0.116 | 0.026 |
| ext_init (ext accumulators, key columns, lineq checks) | 0.977 | 0.145 | 1.006 | 0.144 |
| witness_commit | 0.584 | 0.604 | 0.272 | 0.273 |
| gkr | 1.244 | 1.202 | 0.674 | 0.664 |
| · input (key / table denominators, CPU) | 0.212 | 0.212 | 0.222 | 0.208 |
| · layer build | 0.333 | 0.324 | (device) | (device) |
| · layer sumchecks | 0.698 | 0.666 | (device) | (device) |
| terminal (GKR claims → MLE evals) | 0.138 | 0.007 | 0.042 | 0.007 |
| op_sumchecks | 0.366 | 0.154 | 0.377 | 0.143 |
| · of which ext einsum sumchecks + lineqs | ≈0.33 | 0.137 | ≈0.33 | 0.121 |
| batch | 0.363 | 0.349 | 0.232 | 0.142 |
| witness_open | 0.129 | 0.114 | 0.131 | 0.140 |
| weight_open | 0.027 | 0.025 | 0.028 | 0.029 |
| forward (not in prove) | 0.789 | 0.372 | 0.814 | 0.268 |
| peak RSS (GB) | 12.2 | 12.3 | 5.1 | 5.2 |

### Per-stage, decoder layer 1024 tokens, steady state (s)

| stage | CPU base | CPU new | Metal base | Metal new |
|---|---:|---:|---:|---:|
| **prove (best of 3)** | **3.150** | **1.745** | **2.763** | **1.217** |
| prove (first) | 3.848 | 2.422 | 2.763 | 1.526 |
| multiplicities | 0.097 | 0.015 | 0.105 | 0.016 |
| ext_init | 0.871 | 0.037 | 0.929 | 0.037 |
| witness_commit | 0.491 | 0.495 | 0.299 | 0.233 |
| gkr | 0.685 | 0.665 | 0.652 | 0.448 |
| terminal | 0.122 | 0.007 | 0.030 | 0.008 |
| op_sumchecks | 0.288 | 0.133 | 0.301 | 0.158 |
| batch | 0.258 | 0.256 | 0.239 | 0.162 |
| witness_open | 0.105 | 0.102 | 0.123 | 0.115 |

### Per-stage, decoder layer 512 tokens (s)

| stage | CPU base | CPU new | Metal base | Metal new | CPU steady base | CPU steady new | Metal steady base | Metal steady new |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **prove** | **1.507** | **1.092** | **1.020** | **0.689** | **1.057** | **0.667** | **0.819** | **0.518** |
| accumulators | 0.097 | 0 | 0.026 | 0 | 0.090 | 0 | 0.023 | 0 |
| ext_init | 0.225 | 0.046 | 0.210 | 0.046 | 0.191 | 0.011 | 0.192 | 0.011 |
| witness_commit | 0.185 | 0.180 | 0.093 | 0.089 | 0.143 | 0.143 | 0.070 | 0.065 |
| gkr | 0.511 | 0.512 | 0.339 | 0.334 | 0.280 | 0.276 | 0.237 | 0.246 |
| terminal | 0.060 | 0.004 | 0.012 | 0.004 | 0.059 | 0.003 | 0.009 | 0.006 |
| op_sumchecks | 0.108 | 0.058 | 0.110 | 0.054 | 0.086 | 0.048 | 0.088 | 0.051 |
| batch | 0.177 | 0.176 | 0.098 | 0.061 | 0.108 | 0.108 | 0.099 | 0.059 |
| witness_open | 0.054 | 0.055 | 0.056 | 0.055 | 0.048 | 0.049 | 0.047 | 0.049 |

### Per-stage, MLP 1024 tokens (s)

| stage | CPU base | CPU new | Metal base | Metal new | CPU steady base | CPU steady new | Metal steady base | Metal steady new |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **prove** | **1.054** | **0.762** | **0.600** | **0.495** | **0.820** | **0.514** | **0.328** | **0.307** |
| witness_commit | 0.133 | 0.135 | 0.091 | 0.096 | 0.119 | 0.130 | 0.057 | 0.053 |
| gkr | 0.270 | 0.274 | 0.225 | 0.193 | 0.179 | 0.183 | 0.117 | 0.093 |
| terminal (prove − stages) | ≈0.36 | ≈0.02 | ≈0.01 | ≈0.01 | ≈0.33 | ≈0.02 | – | – |
| batch | 0.155 | 0.174 | 0.093 | 0.061 | 0.080 | 0.081 | 0.031 | 0.034 |
| witness + weight open | 0.095 | 0.131 | 0.140 | 0.103 | 0.084 | 0.085 | 0.086 | 0.086 |

The MLP has no ext ops. Its CPU gain comes from the terminal MLE evaluations:
`f.mleEvalI32` was serial (metal.md, footnote 1) and is now parallel. On Metal,
the segment-indexed batch E cut the batch stage from 0.093 to 0.061 s.

## What changed (commit order)

1. **Bug fixes and pinning** (`9791c1927`), see §Bugs. Also adds
   `digest.extDigest`/`fullDigest` (`proofDigest` did not hash the ext
   proof part) and golden decoder-layer digests, flat and pcs2 + batch + MoE,
   with 1-vs-5-thread equality. `tensor-bench layer` now prints the digests,
   steady-state reps, prep and GKR sub-stages, ext op time and Metal stats.
2. **CPU ext ops** (`1dc96d396`).
   * `einsumAcc`, GEMM path: contractions of ≥ 16 terms gather both operands
     into contiguous `[batch][row][k]` i32 blocks and multiply them with 4×4
     tiles of 16-lane i32 dot products. The path is taken only when
     `max|A|·max|B|·K < 2^31` (checked at run time), so no partial sum can
     overflow; otherwise the bit-gather kernel runs. The PV accumulator went
     from 384 to ~20 ms. This also speeds up the forward pass.
   * `ExprEval`: parallel evaluation of linear expressions. SUM terms are
     reduced in parallel first, and identity-labelled terms are read directly.
     Lineqs are checked without materialising an i64 column (the 2^24 lineq
     went from 171 ms to a few ms). Key columns are built in parallel.
   * Einsum sumchecks with integer operands and no folded (operand-only)
     output vars: `eqsum.proveEqPrefix`. It splits eq over the batch vars,
     gives the contracted vars weight 1, and runs a base-field first round
     straight from the i32 operands, with no eq or QM31 factor tables. This
     covers `sel·sel = sel` and `Σ_j sel·D = 0` over H·T² (101 + 77 ms
     before).
   * MLE evaluations: `f.mleEvalI32Par` splits eq into a 2^12 low table and a
     high table and runs in parallel, with no full-size eq table. It is used
     for ext terms, exact-einsum outputs and the core terminal claims on the
     CPU path.
3. **Metal batch E segment index** (`b22ec879e`). `tm_batch_e` looped over
   *every* claim for every element (O(N·claims), and a layer has hundreds of
   claims). The host now cuts the table into disjoint segments, each listing
   only the claims that cover it, and the kernel binary-searches the
   segment. Batch device time went from 168 to 90 ms.
4. **Forward-pass accumulators and parallel multiplicities** (`20ec1aeaf`).
   `Builder.keep_accs` keeps the core and requant-einsum accumulators the
   forward pass computes anyway, and `proto.proveWithAllAccumulators` uses
   them (the default in the layer bench; `TENSOR_RECOMPUTE_ACC=1` turns it
   off, as for `mlp`). `Builder.accel` runs the forward matmuls on the
   device. Ext key multiplicities use per-task histograms.
5. **Recommended config as the bench default** (`604b473ca`, see §Defaults).
6. **Metal ext einsums** (`0f89bb6ad`). The new `FactorSpec.eq_prefix` (eq
   over the leading vars, broadcast over the trailing ones) maps onto one
   existing lazy claim, so no new kernel was needed. Ext einsum sumchecks run
   through `accel.proveFactors` / `accel.proveActive` when a device is
   attached: 0.161 → 0.116 s.

## Bugs found (pre-existing on the base)

* **`Builder.add` aliasing.** Callers pass `self.infos.items[x]` by value. Zig
  may pass struct parameters by reference, and the "copy" `const info = info_in`
  was elided, so `ensureUnusedCapacity` could free the memory `info` was read
  from. At D = 2048 the decoder-layer bench failed at 512 and 1024 tokens with
  `ExtStatement` (ReleaseFast) or an assertion (ReleaseSafe). The fix copies the
  bytes explicitly before the list grows.
* **Batched matmuls + MoE rejected by the verifier.** `verify` bounds-checked
  `op_i` before skipping the members of an already verified matmul class. A
  statement whose last remainder keys belong to an earlier class (the MoE
  experts) failed with `ProofShape`. The skip now comes first, and the bounds
  check still guards every index. Skipped members were already checked inside
  their class's sumcheck, so no check is weakened. The pcs2 + batch + MoE
  golden covers this case.

## Defaults

`proto.recommendedConfig(outer, inner)` builds pcs2 depth 2 with batched
matmul sumchecks. `tensor-bench product|mlp|layer` uses it when no pcs2
arguments are given (inner: 54 queries, the outer blowup and PoW). The flat
mode is still available through `TENSOR_PCS=flat`, and per-matmul sumchecks
through `TENSOR_BATCH_MATMULS=0`. It holds up at layer 512:

| config | prove (s) | proof | verify |
|---|---:|---:|---:|
| recommended (pcs2 + batch) | 1.11–1.13 | 460,328 B | 14 ms |
| flat | 1.20–1.22 | 5,258,576 B | 31 ms |

`protocol.Config`'s field defaults are deliberately unchanged. With
`two_level` set, `pcs` is ignored, so flipping the default would silently
change the parameters of every caller that sets `.pcs`: all tests, and the ZK
stream that will be ported on top. A new MLP golden pins the recommended
config (`9a5c2559…`, recorded on the unmodified prover). The flat MLP and
product goldens are kept for the flat mode.

## Soundness

No verifier check was removed or relaxed. The batched-matmul fix only reorders
a skip ahead of a bounds check. Prover-side arguments:

* **Exact arithmetic.** M31/QM31 arithmetic is exact, so splitting eq
  (`eq(ρ, x) = eq_hi(ρ_hi, x_hi)·eq_lo(ρ_lo, x_lo)`), reordering sums and
  using lanes or tiles cannot change any value. The device computes the same
  field products.
* **Integer GEMM.** It is used only when the run-time bound
  `max|A|·max|B|·K < 2^31` holds. Every partial sum is then an exact i32,
  so the result equals the i64 gather kernel's.
* **`proveEqPrefix`.** For a true claim, `q(1) = (claim − C·w(0)·q(0)) / (C·w(1))`
  is the true value. Free rounds have `w ≡ 1` and `C` stays fixed, so each
  transmitted round value equals the generic prover's on
  `{eq(ρ_B) ⊗ 1, A, B}`. When `C·w(1) = 0`, q(1) is summed directly. For a
  false claim the output differs, but standard sumcheck soundness applies and
  a test checks that such proofs are rejected.
* **Forward accumulators.** They are untrusted, as on the core path. A wrong
  value either moves a remainder out of `[0, 2^s)`, which the prover refuses,
  or makes the claimed `acc(ρ)` differ from `Σ A·B`, which the einsum
  sumcheck rejects. Exact einsums are still recomputed and checked.
* **Segment index / eq_prefix.** The same terms of the same sum are computed;
  the only claims skipped are those whose range excludes x, and they
  contributed 0 before.

## Tests (53 CPU, 12 Metal)

The Metal lazy-factor, batch and eq-prefix tests run for `lazy_rounds` 1, 2,
3 and 5 (clamped to 3).


* goldens, recorded on the unmodified prover: decoder layer flat
  `146ac6c3…`, decoder layer pcs2 + batch + MoE `4d247ffb…`, MLP recommended
  `9a5c2559…`, and the existing flat MLP and product goldens. Thread counts 1
  vs 5 must agree, and kept forward accumulators must reproduce the goldens;
* `eqsum`: prefix split-eq vs the generic prover for 8 (n, m) shapes,
  `ρ_0 = 0`, false-claim rejection, and 12-thread unaligned parallel chunks.
  A first version mis-handled chunks that are not lane-aligned; this test
  catches that mutation;
* `ext`: GEMM vs gather (permuted labels, FIX bits, a strided operand, the
  overflow decline), and ExprEval vs a direct reference (SUM, FIX,
  broadcast, permuted labels);
* `field`: `mleEvalI32Par` vs `mleEvalI32` (0 to 17 variables, full-range
  values);
* `transformer`: an off-by-one forward accumulator of every requant einsum
  is refused or rejected, including one that keeps its remainder in range.
  Wrong lengths give `AccumulatorShape`;
* `test-metal`: eq_prefix lazy factors vs the CPU (free bits 0 to 11, partial
  `active`, many and few device rounds), and a GPU decoder-layer proof
  (device einsums forced with `sc_min_work = 32`) equal to the CPU golden.

## Tried, measured, not kept

| idea | outcome |
|---|---|
| GKR `min_parallel` 2^12 / 2^14 for the layer mix | GKR sumcheck +15% / +75% at 512 tokens; 2^10 stays (`TENSOR_GKR_MINPAR` knob added to `layer`) |
| Metal multi-round lazy fold (`Gpu.lazy_rounds`, `TENSOR_LAZY_ROUNDS`): the first 1–3 batch / lazy-factor rounds evaluate the implicit factors folded at the earlier challenges on the fly (corner weights `eq(r_0..r_{j-1}, c)`), so the first materialised fold is 1/2^k the size | layer 1024 Metal batch stage 0.127–0.140 s (k = 1) vs 0.114–0.120 s (k = 3); prove time within noise. Earlier profiling attributed 373 ms to first touch of the 2 GiB fold buffers, but in the full prover the device pool usually recycles them. Kept as a tested option (k = 1, 2, 3 vs CPU in test-metal; a weight mutation fails 3 tests), default 1 (unchanged) |
| merge a requant op's remainder and `y_range` keys into `r + 2^s (y + off)` in `[0, 2^(s+ob))` | **unsound**: `r = acc + half − 2^s y`, so the merged key equals `acc + const` and no longer constrains `y`. A sound variant is a tuple lookup `(r, y)` against a 2^(s+ob) pair table, but S and P need s + ob = 23 / 27 > `MAX_TABLE_BITS`. Not pursued |

## Remaining hot spots and recommendations

1. **GKR (≈45% CPU, ≈40% Metal at 1024 tokens).** About 145 M leaves, 64 M of
   them from the S and P requant keys. The shared fast prover allocates every
   layer up front (≈48 B per leaf including the QM31 input). In single-shot
   runs, page faults are a large part of build + sumcheck: in steady state
   the CPU GKR is 0.67 s against 1.2 s single shot. Next steps:
   * a *lazy input layer*: build layer n−1 straight from the integer keys
     (`alpha − key` is one M31 subtraction), and run the last layer's first
     round in the base field. This saves the 16 B/leaf input and the 0.21 s
     input stage. It needs a hook in `gkr_prover_fast` and `metal/gkr.zig`;
   * on Metal, the 0.21 s input stage could become a device kernel writing
     into pooled buffers.
2. **Metal batch.** It is now 0.12–0.14 s at 1024 tokens. The multi-round
   lazy fold is available (`TENSOR_LAZY_ROUNDS=3`) but measured only
   ~15 ms better, so it is off by default.
3. **Witness commitment** (0.6 s CPU, 0.27 s Metal at 1024 tokens; 2^27
   table). It is unchanged; see metal.md ("codeword layout").
4. **Long-lived provers** should pass `recycle.Recycler.allocator()`. At 1024
   tokens, steady state is 1.75 s against 2.7 s single shot on the CPU, and
   1.2 s against 1.6 s on Metal.

## Reproduce

```
cd src/tensor
zig build test -Doptimize=ReleaseSafe          # 53 tests incl. goldens
zig build test-metal -Doptimize=ReleaseSafe    # 12 tests, CPU/GPU bit-identity
zig build -Doptimize=ReleaseFast --prefix <dir>
<dir>/bin/tensor-bench layer 10 11 12 4 12 54 2 20 2 1 0 10 1 2 54 [--metal]
TENSOR_RECYCLE=1 TENSOR_PROVE_REPS=3 <dir>/bin/tensor-bench layer 10 ...   # steady state
<dir>/bin/tensor-bench mlp 10 12 13 12 64 2 20 2 54 2 20 [--metal]
TENSOR_PCS=flat TENSOR_BATCH_MATMULS=0 <dir>/bin/tensor-bench layer 9 11 12 4 12 54 2 20 2 1 0 9 1   # flat comparison
```

Scripts used: `~/Coding/ge-cache/tensor-speed/scripts/{run.sh,matrix.sh,stages.py}`.
