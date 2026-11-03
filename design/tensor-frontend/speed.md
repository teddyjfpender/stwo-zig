# Tensor frontend: prover speed, round 2 (stream `speed`)

Branch `codex/tensor-r2-speed`, based on `codex/tensor-frontend` at `61ba1ce6c`.
Host: M4 Max (12 P + 4 E cores), AC power, 12 prover threads, `memguard`.
Other agents shared the host throughout (load average 4–8); every number below
comes from base and new binaries run back to back with the same arguments, and
noisy outliers were re-run. Raw JSON is in `~/Coding/ge-cache/tensor-speed/final/`.

**Status (2026-11-04, after the host crash).** The session before this one
crashed the host (36 GB, out of memory) at about 01:30. This round resumed
from `8970db7de`, ran only the allowed sizes (decoder layer `9 11 12`, MLP
`9 11 12`, one job at a time under `memguard --gb ≤ 8`) and added two
allocation-only commits: the recycling allocator is now the bench default
(§What changed 7) and it has a best-fit fallback (8). The final tables at the
allowed sizes are in §Allowed sizes, final head. The 1024-token tables below
are from the previous session: their single-shot "new" columns were measured
*without* the recycler (now `TENSOR_RECYCLE=0`), and nothing at 1024 tokens
was re-run this round.

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

### Allowed sizes, final head (`11daca15b`, round 3)

Base `61ba1ce6c` vs the final head, same host, columns alternated within each
round, 3 rounds, median per stage (raw JSON:
`~/Coding/ge-cache/tensor-speed/r4/`, script `scripts/matrix4.sh` and
`scripts/tables4.py`). "new, no recycler" is `TENSOR_RECYCLE=0`, which is how
the previous session measured single shot. "new (default)" is the bench as it
is now. Steady state is `TENSOR_RECYCLE=1 TENSOR_PROVE_REPS=3`, best of 3. The
host was shared with other agents (load average 5–8, at times another
`tensor-bench` at 800% CPU), so trust the alternated pairs, not the absolute
values.

| bench | path | base | new, no recycler | new (default) | base steady | new steady |
|---|---|---:|---:|---:|---:|---:|
| layer 512 tok (`layer 9 11 12 …`) | CPU | 1.575 | 1.081 (1.46×) | **0.990 (1.59×)** | 1.078 | **0.673 (1.60×)** |
| layer 512 tok | Metal | 1.049 | 0.710 (1.48×) | **0.678 (1.55×)** | 0.855 | **0.542 (1.58×)** |
| MLP 512 tok (`mlp 9 11 12 …`) | CPU | 0.278 | 0.205 (1.36×) | **0.179 (1.55×)** | 0.230 | **0.145 (1.59×)** |
| MLP 512 tok | Metal | 0.151 | 0.190 (noise, range 0.151–0.227) | **0.146 (1.03×)** | 0.125 | **0.115 (1.09×)** |

Digests on every run: layer `48cfb9d1fae7a8d5…` (`full_digest`), MLP
`a31527e0963a1f94…` (`proof_digest`; the MLP has no ext part). Proof sizes:
460,328 B (layer), 328,752 B (MLP). Bench lines:
`tensor-bench layer 9 11 12 4 12 54 2 20 2 1 0 9 1 2 54 [--metal]` and
`tensor-bench mlp 9 11 12 12 64 2 20 2 54 2 20 [--metal]` (D = 2048, F = 4096
for the layer; 2048 × 4096 for the MLP), `TENSOR_BATCH_MATMULS=1` (the
default anyway).

#### Decoder layer 512 tokens, per stage (s)

CPU (3 runs per column, median):

| stage | base | new, no recycler | new (default) | base steady | new steady |
|---|---:|---:|---:|---:|---:|
| **prove** | **1.575** | **1.081** | **0.990** | **1.078** | **0.673** |
| prove (first rep) | 1.575 | 1.081 | 0.990 | 1.365 | 1.001 |
| multiplicities | 0.032 | 0.008 | 0.008 | 0.029 | 0.006 |
| ext_init | 0.225 | 0.046 | 0.043 | 0.187 | 0.011 |
| witness_commit | 0.181 | 0.179 | 0.181 | 0.147 | 0.142 |
| gkr | 0.551 | 0.515 | 0.465 | 0.284 | 0.278 |
| · input (CPU) | 0.089 | 0.094 | 0.096 | 0.009 | 0.009 |
| · layer build | 0.159 | 0.158 | 0.141 | 0.053 | 0.052 |
| · layer sumchecks | 0.303 | 0.262 | 0.227 | 0.222 | 0.217 |
| terminal | 0.062 | 0.004 | 0.003 | 0.054 | 0.003 |
| op_sumchecks | 0.114 | 0.056 | 0.048 | 0.086 | 0.048 |
| batch | 0.179 | 0.167 | 0.155 | 0.109 | 0.108 |
| witness_open | 0.058 | 0.055 | 0.050 | 0.052 | 0.050 |
| weight_open | 0.028 | 0.027 | 0.021 | 0.021 | 0.021 |
| forward (not in prove) | 0.241 | 0.161 | 0.149 | 0.232 | 0.154 |
| peak RSS (GB) | 6.28 | 6.29 | 6.39 | 7.10 | 7.10 |

prove range: base 1.513–1.648; new, no recycler 1.075–1.170; new (default) 0.976–0.993; base steady 1.052–1.086; new steady 0.669–0.673
digests: ['48cfb9d1fae7a8d5']

Metal (3 runs per column, median):

| stage | base | new, no recycler | new (default) | base steady | new steady |
|---|---:|---:|---:|---:|---:|
| **prove** | **1.049** | **0.710** | **0.678** | **0.855** | **0.542** |
| prove (first rep) | 1.049 | 0.710 | 0.678 | 0.983 | 0.683 |
| multiplicities | 0.033 | 0.007 | 0.007 | 0.030 | 0.006 |
| ext_init | 0.217 | 0.044 | 0.042 | 0.193 | 0.012 |
| witness_commit | 0.095 | 0.095 | 0.096 | 0.073 | 0.072 |
| gkr | 0.339 | 0.340 | 0.329 | 0.249 | 0.258 |
| · input (CPU) | 0.096 | 0.094 | 0.097 | 0.011 | 0.014 |
| terminal | 0.012 | 0.004 | 0.004 | 0.009 | 0.004 |
| op_sumchecks | 0.112 | 0.055 | 0.053 | 0.089 | 0.052 |
| batch | 0.101 | 0.064 | 0.064 | 0.102 | 0.064 |
| witness_open | 0.062 | 0.055 | 0.055 | 0.049 | 0.049 |
| weight_open | 0.026 | 0.027 | 0.022 | 0.023 | 0.022 |
| forward (not in prove) | 0.243 | 0.078 | 0.074 | 0.237 | 0.076 |
| peak RSS (GB) | 2.18 | 2.17 | 2.13 | 2.26 | 2.23 |

prove range: base 1.042–1.057; new, no recycler 0.693–0.710; new (default) 0.673–0.685; base steady 0.829–0.859; new steady 0.517–0.543
digests: ['48cfb9d1fae7a8d5']

#### MLP 512 tokens, per stage (s)

CPU (3 runs per column, median):

| stage | base | new, no recycler | new (default) | base steady | new steady |
|---|---:|---:|---:|---:|---:|
| **prove** | **0.278** | **0.205** | **0.179** | **0.230** | **0.145** |
| prove (first rep) | 0.278 | 0.205 | 0.179 | 0.270 | 0.171 |
| multiplicities | 0.004 | 0.004 | 0.004 | 0.004 | 0.004 |
| witness_commit | 0.036 | 0.036 | 0.034 | 0.033 | 0.031 |
| gkr | 0.084 | 0.087 | 0.079 | 0.055 | 0.054 |
| · input (CPU) | 0.012 | 0.012 | 0.013 | 0.005 | 0.004 |
| · layer build | 0.027 | 0.026 | 0.024 | 0.010 | 0.010 |
| · layer sumchecks | 0.045 | 0.047 | 0.042 | 0.040 | 0.040 |
| op_sumchecks | 0.004 | 0.005 | 0.004 | 0.004 | 0.004 |
| batch | 0.026 | 0.026 | 0.021 | 0.021 | 0.021 |
| witness_open | 0.016 | 0.017 | 0.015 | 0.014 | 0.014 |
| weight_open | 0.021 | 0.023 | 0.018 | 0.017 | 0.017 |
| forward (not in prove) | 0.069 | 0.070 | 0.069 | 0.069 | 0.067 |
| peak RSS (GB) | 2.58 | 2.57 | 2.55 | 2.81 | 2.69 |

prove range: base 0.277–0.291; new, no recycler 0.193–0.232; new (default) 0.170–0.180; base steady 0.223–0.279; new steady 0.142–0.242
digests: ['a31527e0963a1f94']

Metal (3 runs per column, median):

| stage | base | new, no recycler | new (default) | base steady | new steady |
|---|---:|---:|---:|---:|---:|
| **prove** | **0.151** | **0.190** | **0.146** | **0.125** | **0.115** |
| prove (first rep) | 0.151 | 0.190 | 0.146 | 0.149 | 0.150 |
| multiplicities | 0.004 | 0.005 | 0.004 | 0.004 | 0.004 |
| witness_commit | 0.022 | 0.024 | 0.022 | 0.012 | 0.013 |
| gkr | 0.066 | 0.068 | 0.066 | 0.049 | 0.048 |
| · input (CPU) | 0.017 | 0.018 | 0.017 | 0.005 | 0.005 |
| op_sumchecks | 0.004 | 0.005 | 0.004 | 0.005 | 0.004 |
| batch | 0.011 | 0.010 | 0.011 | 0.010 | 0.010 |
| witness_open | 0.019 | 0.024 | 0.018 | 0.018 | 0.016 |
| weight_open | 0.025 | 0.037 | 0.022 | 0.022 | 0.018 |
| forward (not in prove) | 0.022 | 0.022 | 0.022 | 0.022 | 0.021 |
| peak RSS (GB) | 1.01 | 1.01 | 0.99 | 1.03 | 1.01 |

prove range: base 0.149–0.190; new, no recycler 0.151–0.227; new (default) 0.146–0.158; base steady 0.112–0.125; new steady 0.109–0.128
digests: ['a31527e0963a1f94']

The MLP bench does not report a terminal stage. On the CPU, prove minus the
listed stages is ≈0.09 s on the base and ≈0.01 s on the head: the serial
`f.mleEvalI32` terminal evaluations, now parallel (as at 1024 tokens). On
Metal the MLP was already device-bound in the base; the head is within noise.

### Per-stage, decoder layer 1024 tokens, single shot (s), previous session (no recycler)

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

### Per-stage, decoder layer 512 tokens (s), previous session (single shot without recycler)

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

7. **Recycler on by default in `tensor-bench`** (`116859b9a`, round 3).
   Large blocks freed by the weight commitment, the forward pass and earlier
   prover stages are reused instead of faulting in fresh zero pages.
   `TENSOR_RECYCLE=0` uses the system allocator; `TENSOR_RECYCLE=1` still
   works. CPU single shot: layer 512 1.08 → 0.99 s, MLP 512 0.205 → 0.179 s;
   Metal within noise (0.71 → 0.68 s). Peak RSS +0.1 GB at layer 512.
8. **Recycler best-fit fallback** (`11daca15b`, round 3). On an exact-size
   miss, the smallest cached block of at most 2× the rounded size is lent out
   and returns to its own size class on free. It removes the recycler's RSS
   overhead on the MLP (2.69 → 2.55 GB) and makes no measurable speed
   difference (layer 512: 0.956/0.957 vs 0.950/0.962 s on quiet runs).

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

The bench also uses the recycling allocator by default (§What changed 7);
`TENSOR_RECYCLE=0` turns it off. This is a bench-level choice: `prove` takes
whatever allocator its caller passes.

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

## Tests (54 CPU, 12 Metal)

The Metal lazy-factor, batch and eq-prefix tests run for `lazy_rounds` 1, 2,
3 and 5 (clamped to 3).


* `recycle` (round 3): best fit takes the smallest cached block within
  2×, declines blocks that are too small or more than 2× larger, returns a
  lent block to its own size class, and keeps the cached-byte count; the
  exact-size test pins `fit_ratio = 1`;
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
| parallel `tableDen` with β² hoisted (round 3) | no change: GKR input 0.093–0.096 s either way at layer 512. The tables are at most 2^20 entries. The input stage is the 52 key columns, 57.2 M leaves = 915 MB of QM31 written at ≈9 GB/s, which is page-fault bound (steady state: 0.009 s). Reverted |
| best-fit recycler for the GKR input stage (round 3) | input stage unchanged (no cached block of a fitting size is free at that point of the first proof). Kept for the RSS gain on the MLP, see §What changed 8 |
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

   Round 3 estimate. The input stage is fault bound (0.09 s single shot vs
   0.009 s steady at layer 512). A lazy input layer avoids writing the 16 B/leaf
   input, but the input layer is also the last GKR sumcheck's working set: the
   first round and the first fold would read the generator, and that fold
   (in place today, because key inputs are owned) would then write a fresh
   8 B/leaf half layer. So about half the input-stage faults go away, ≈45 ms
   (≈5%) at layer 512 single shot and nothing in steady state, at the cost of a
   change in the shared `gkr_prover_fast` round/fold loops and in
   `metal/gkr.zig`. It was not attempted this round. A Metal key-den kernel
   (no CPU faults, the device writes pooled buffers) is the larger win on
   that path.
2. **Metal batch.** It is now 0.12–0.14 s at 1024 tokens. The multi-round
   lazy fold is available (`TENSOR_LAZY_ROUNDS=3`) but measured only
   ~15 ms better, so it is off by default.
3. **Witness commitment** (0.6 s CPU, 0.27 s Metal at 1024 tokens; 2^27
   table). It is unchanged; see metal.md ("codeword layout").
4. **Long-lived provers** should pass `recycle.Recycler.allocator()` (the
   bench now does so by default). At 1024
   tokens, steady state is 1.75 s against 2.7 s single shot on the CPU, and
   1.2 s against 1.6 s on Metal.

## Reproduce

```
cd src/tensor
zig build test -Doptimize=ReleaseSafe          # 54 tests incl. goldens
zig build test-metal -Doptimize=ReleaseSafe    # 12 tests, CPU/GPU bit-identity
zig build -Doptimize=ReleaseFast --prefix <dir>
<dir>/bin/tensor-bench layer 10 11 12 4 12 54 2 20 2 1 0 10 1 2 54 [--metal]
TENSOR_RECYCLE=1 TENSOR_PROVE_REPS=3 <dir>/bin/tensor-bench layer 10 ...   # steady state
TENSOR_RECYCLE=0 <dir>/bin/tensor-bench layer 10 ...   # single shot without the recycler (previous-session numbers)
<dir>/bin/tensor-bench mlp 10 12 13 12 64 2 20 2 54 2 20 [--metal]
TENSOR_PCS=flat TENSOR_BATCH_MATMULS=0 <dir>/bin/tensor-bench layer 9 11 12 4 12 54 2 20 2 1 0 9 1   # flat comparison
```

Scripts used: `~/Coding/ge-cache/tensor-speed/scripts/{run.sh,matrix.sh,stages.py}`;
round 3: `scripts/{matrix4.sh,tables4.py}` (`matrix4.sh L9 <new-prefix> 3 layer 9 11 12 …`).

## Caveats

* Nothing at 1024 tokens was re-run in round 3 (host memory rules). The
  1024-token tables come from the previous session. Peak RSS with the
  recycler as the default is **not measured** at 1024 tokens. At 512 tokens it
  costs +0.1 GB on the layer and nothing on the MLP (best fit). The coordinator's
  large runs now use the recycler unless `TENSOR_RECYCLE=0` is set. Compare
  against the earlier single-shot numbers with `TENSOR_RECYCLE=0`.
* Part of the bench's recycler gain comes from reusing blocks freed by the
  weight commitment, which a deployed prover does once, not per proof. The
  forward-pass and in-prove reuse do apply per request. The steady-state
  column is the number for a long-lived prover.
* The host was shared with other agents in both sessions. All comparisons are
  alternated base/new pairs with the same arguments; single-run absolute
  values can be 30–50% high under contention (for example, MLP Metal "new, no
  recycler" 0.151–0.227 s).
* The Metal timings cover only small sizes (layer and MLP at 512 tokens) in
  round 3. Unified memory is not visible to `memguard`.
