# Tensor frontend: prover speed, round 2 (stream `speed`)

Branch `codex/tensor-r2-speed`, based on `codex/tensor-frontend` at `61ba1ce6c`.
Host: M4 Max (12 P + 4 E cores), AC power, 12 prover threads, `memguard`.
Other agents shared the host throughout (load average 4–8); every number below
comes from base and new binaries run back to back with the same arguments, and
noisy outliers were re-run. Raw JSON is in `~/Coding/ge-cache/tensor-speed/final/`.

**Status (2026-11-04, after the host crash).** The session before this one
crashed the host (36 GB, out of memory) at about 01:30. This round resumed
from `8970db7de`, ran only the allowed sizes (decoder layer `9 11 12`, MLP
`9 11 12`, one job at a time under `memguard --gb ≤ 8`) and added five
prover-scheduling commits that leave proofs unchanged (§What changed 7–11).
The recycling allocator is now the bench default and has a best-fit fallback.
The page faults of single-shot proving are moved off the critical path: the
GKR key inputs, the CPU GKR layers and the CPU batch E table are faulted in by
helper threads while earlier stages run. At layer 512, single shot, this
takes the CPU from 1.08 to 0.80 s and Metal from 0.69 to 0.60 s. The final
tables at the allowed sizes are in §Allowed sizes, final head. The 1024-token tables below
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

### Allowed sizes, final head (`f2e564a05`, round 3)

#### Per-commit ladder (quiet-host A/B pairs, single shot, layer `9 11 12`)

Each step was measured as alternated pairs against the step before, with the
same arguments, while the host was quiet. Ranges are 3 runs.

| step | commit | CPU prove (s) | Metal prove (s) |
|---|---|---:|---:|
| base | `61ba1ce6c` | 1.50–1.58 | 1.02–1.05 |
| previous session's head (no recycler) | `8970db7de` | 1.08–1.13 | 0.68–0.71 |
| + recycler on by default | `116859b9a` | 0.96–0.98 | 0.66–0.72 (noise) |
| + recycler best fit | `11daca15b` | 0.95–0.96 | – |
| + GKR key inputs faulted in during the witness commitment | `e37904482` | 0.88–0.92 (vs 0.96 with it off) | **0.59–0.61** (vs 0.67–0.69) |
| + CPU GKR layer blocks warmed during the commitment | `d97254a5f` | 0.82–0.83 (vs 0.89–0.98) | – (CPU only) |
| + CPU batch E table faulted in during the op sumchecks | `f2e564a05` | **0.79–0.83** (vs 0.81–0.92) | – (CPU only) |

Overall, layer 512 single shot: CPU 1.54 → 0.80 s (≈1.9×), Metal 1.04 →
0.60 s (≈1.7×). In steady state (best of 3) the last three commits are
neutral: CPU stays at 0.67 s, and Metal goes from 0.54 to 0.53 s. Their gain is
the first-touch page-fault cost of single-shot proving, which they move off the
critical path.

#### Final matrix (base vs head, all columns alternated)

Base `61ba1ce6c` vs the head. Layer: 5 rounds; MLP: 3 rounds; median per
stage. Raw JSON: `~/Coding/ge-cache/tensor-speed/r5/`; scripts
`scripts/matrix5.sh` / `matrix5b.sh` and `scripts/tables5.py`. "new, no
recycler" is `TENSOR_RECYCLE=0`, which also turns the GKR layer warm-up off;
the key-input and E prefaults stay on. "new (default)" is the bench as it is
now. Steady state is `TENSOR_RECYCLE=1 TENSOR_PROVE_REPS=3`, best of 3.
**This matrix ran while other agents were building (load average 5–8). The
CPU columns are about 15–20% slower than the quiet A/B pairs above, base and
head alike.** Use the ratios, and the ladder for absolute values.

| bench | path | base | new, no recycler | new (default) | base steady | new steady |
|---|---|---:|---:|---:|---:|---:|
| layer 512 tok (`layer 9 11 12 …`) | CPU | 1.769 | 1.161 (1.52×) | **0.957 (1.85×)** | 1.326 | **0.878 (1.51×)** |
| layer 512 tok | Metal | 1.136 | 0.697 (1.63×) | **0.677 (1.68×)** | 0.897 | **0.564 (1.59×)** |
| MLP 512 tok (`mlp 9 11 12 …`) | CPU | 0.325 | 0.231 (1.41×) | **0.189 (1.72×)** | 0.264 | **0.198 (1.33×)** |
| MLP 512 tok | Metal | 0.161 | 0.152 (1.06×) | **0.147 (1.10×)** | 0.119 | **0.116 (1.03×)** |

Digests on every run: layer `48cfb9d1fae7a8d5…` (`full_digest`), MLP
`a31527e0963a1f94…` (`proof_digest`; the MLP has no ext part). Proof sizes
are unchanged: 460,328 B (layer), 328,752 B (MLP). Bench lines:
`tensor-bench layer 9 11 12 4 12 54 2 20 2 1 0 9 1 2 54 [--metal]` and
`tensor-bench mlp 9 11 12 12 64 2 20 2 54 2 20 [--metal]` (layer: D = 2048,
F = 4096, 16 q / 4 kv heads; MLP: 2048 × 4096, fused SwiGLU).

#### Decoder layer 512 tokens, per stage (s)

CPU (5 runs per column, median):

| stage | base | new, no recycler | new (default) | base steady | new steady |
|---|---:|---:|---:|---:|---:|
| **prove** | **1.769** | **1.161** | **0.957** | **1.326** | **0.878** |
| prove (first rep) | 1.769 | 1.161 | 0.957 | 1.573 | 1.048 |
| multiplicities | 0.032 | 0.010 | 0.009 | 0.029 | 0.007 |
| ext_init | 0.241 | 0.047 | 0.043 | 0.211 | 0.014 |
| witness_commit | 0.238 | 0.222 | 0.255 | 0.178 | 0.171 |
| gkr | 0.586 | 0.497 | 0.370 | 0.361 | 0.377 |
| · input (CPU) | 0.089 | 0.016 | 0.015 | 0.011 | 0.012 |
| · layer build | 0.169 | 0.169 | 0.078 | 0.068 | 0.071 |
| · layer sumchecks | 0.331 | 0.317 | 0.270 | 0.268 | 0.289 |
| terminal | 0.065 | 0.005 | 0.004 | 0.061 | 0.004 |
| op_sumchecks | 0.136 | 0.065 | 0.060 | 0.113 | 0.059 |
| batch | 0.183 | 0.172 | 0.140 | 0.133 | 0.139 |
| witness_open | 0.066 | 0.067 | 0.061 | 0.060 | 0.066 |
| weight_open | 0.030 | 0.031 | 0.027 | 0.028 | 0.028 |
| forward (not in prove) | 0.268 | 0.172 | 0.175 | 0.262 | 0.190 |
| peak RSS (GB) | 6.28 | 6.17 | 6.42 | 7.11 | 7.19 |

prove range: base 1.529–1.879; new, no recycler 1.014–1.310; new (default) 0.784–1.060; base steady 1.050–1.338; new steady 0.707–0.927
digests: ['48cfb9d1fae7a8d5']

Metal (5 runs per column, median):

| stage | base | new, no recycler | new (default) | base steady | new steady |
|---|---:|---:|---:|---:|---:|
| **prove** | **1.136** | **0.697** | **0.677** | **0.897** | **0.564** |
| prove (first rep) | 1.136 | 0.697 | 0.677 | 1.070 | 0.647 |
| multiplicities | 0.036 | 0.009 | 0.009 | 0.031 | 0.007 |
| ext_init | 0.269 | 0.045 | 0.043 | 0.219 | 0.013 |
| witness_commit | 0.109 | 0.108 | 0.108 | 0.074 | 0.072 |
| gkr | 0.338 | 0.277 | 0.257 | 0.251 | 0.249 |
| · input (CPU) | 0.096 | 0.019 | 0.017 | 0.012 | 0.010 |
| terminal | 0.015 | 0.004 | 0.004 | 0.011 | 0.005 |
| op_sumchecks | 0.131 | 0.061 | 0.060 | 0.105 | 0.055 |
| batch | 0.100 | 0.069 | 0.071 | 0.100 | 0.073 |
| witness_open | 0.069 | 0.069 | 0.066 | 0.063 | 0.056 |
| weight_open | 0.031 | 0.033 | 0.031 | 0.026 | 0.026 |
| forward (not in prove) | 0.299 | 0.088 | 0.082 | 0.294 | 0.083 |
| peak RSS (GB) | 2.18 | 2.18 | 2.13 | 2.26 | 2.29 |

prove range: base 1.051–1.175; new, no recycler 0.679–0.737; new (default) 0.625–0.733; base steady 0.874–0.936; new steady 0.552–0.608
digests: ['48cfb9d1fae7a8d5']

#### MLP 512 tokens, per stage (s)

CPU (3 runs per column, median):

| stage | base | new, no recycler | new (default) | base steady | new steady |
|---|---:|---:|---:|---:|---:|
| **prove** | **0.325** | **0.231** | **0.189** | **0.264** | **0.198** |
| prove (first rep) | 0.325 | 0.231 | 0.189 | 0.291 | 0.225 |
| multiplicities | 0.004 | 0.004 | 0.004 | 0.004 | 0.004 |
| witness_commit | 0.043 | 0.046 | 0.037 | 0.034 | 0.040 |
| gkr | 0.094 | 0.092 | 0.068 | 0.064 | 0.073 |
| · input (CPU) | 0.012 | 0.006 | 0.005 | 0.004 | 0.006 |
| · layer build | 0.028 | 0.028 | 0.014 | 0.011 | 0.014 |
| · layer sumchecks | 0.053 | 0.056 | 0.048 | 0.048 | 0.054 |
| op_sumchecks | 0.006 | 0.006 | 0.005 | 0.005 | 0.006 |
| batch | 0.030 | 0.029 | 0.025 | 0.024 | 0.026 |
| witness_open | 0.026 | 0.023 | 0.025 | 0.022 | 0.021 |
| weight_open | 0.027 | 0.032 | 0.028 | 0.025 | 0.025 |
| forward (not in prove) | 0.075 | 0.086 | 0.074 | 0.079 | 0.083 |
| peak RSS (GB) | 2.57 | 2.58 | 2.59 | 2.81 | 2.67 |

prove range: base 0.305–0.349; new, no recycler 0.229–0.264; new (default) 0.188–0.217; base steady 0.263–0.264; new steady 0.189–0.201
digests: ['a31527e0963a1f94']

Metal (3 runs per column, median):

| stage | base | new, no recycler | new (default) | base steady | new steady |
|---|---:|---:|---:|---:|---:|
| **prove** | **0.161** | **0.152** | **0.147** | **0.119** | **0.116** |
| prove (first rep) | 0.161 | 0.152 | 0.147 | 0.148 | 0.141 |
| multiplicities | 0.004 | 0.004 | 0.004 | 0.004 | 0.004 |
| witness_commit | 0.022 | 0.023 | 0.023 | 0.013 | 0.011 |
| gkr | 0.073 | 0.061 | 0.057 | 0.049 | 0.048 |
| · input (CPU) | 0.017 | 0.005 | 0.005 | 0.004 | 0.004 |
| op_sumchecks | 0.005 | 0.004 | 0.005 | 0.004 | 0.004 |
| batch | 0.010 | 0.010 | 0.010 | 0.010 | 0.010 |
| witness_open | 0.020 | 0.021 | 0.019 | 0.017 | 0.017 |
| weight_open | 0.023 | 0.024 | 0.022 | 0.021 | 0.019 |
| forward (not in prove) | 0.021 | 0.022 | 0.021 | 0.019 | 0.021 |
| peak RSS (GB) | 1.01 | 1.00 | 0.97 | 1.03 | 1.01 |

prove range: base 0.160–0.216; new, no recycler 0.144–0.154; new (default) 0.141–0.180; base steady 0.112–0.132; new steady 0.113–0.130
digests: ['a31527e0963a1f94']

The MLP bench does not report a terminal stage. On the CPU, prove minus the
listed stages is ≈0.09 s on the base and ≈0.01 s on the head, because the
serial `f.mleEvalI32` terminal evaluations are now parallel (as at 1024
tokens). On Metal, the MLP was already device-bound in the base.

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

9. **GKR key inputs faulted in during the witness commitment**
   (`e37904482`, round 3). The 52 key-denominator columns (57 M leaves,
   0.9 GB at layer 512) are allocated before the commitment, and a helper
   thread touches one byte per 16 KiB page while the commitment runs. The
   values are still written after α and β are drawn (`keyValuesInto`,
   `xt.keyDenInto`). `Config.prefault_gkr_inputs` (default true),
   `TENSOR_PREFAULT=0`. GKR input stage 0.098 → 0.012 s. Prove: CPU 0.96 →
   0.88–0.92 s, Metal 0.67–0.69 → 0.59–0.61 s. Peak RSS unchanged.
10. **CPU GKR layer warm-up** (`d97254a5f`, round 3).
    `Config.warm_gkr_layers` (default false; ignored with an accelerator). A
    second helper allocates, touches and frees blocks of the sizes and order
    the CPU GKR build allocates (num and den, 2^(k−1) QM31 per level per
    instance). With a caching allocator the build then gets them back already
    faulted in. The bench turns it on whenever the recycler is on
    (`TENSOR_WARM_GKR=0` turns it off). GKR build 0.14–0.20 → 0.062 s, prove
    0.89–0.98 → 0.82–0.83 s. Peak RSS +0.03–0.05 GB single shot, +0.16 GB in
    steady state, +0.1 GB on the MLP.
11. **CPU batch E table faulted in during the op sumchecks** (`f2e564a05`,
    round 3). E (2^log_total QM31, 1 GiB at layer 512) is allocated right
    after the GKR, whose layers are gone by then, and its used part is touched
    while the terminal claims and op sumchecks run. Batch 0.146–0.159 →
    0.118–0.122 s. Same switch as 9; CPU path only; peak RSS unchanged.

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
`TENSOR_RECYCLE=0` turns it off. `Config.prefault_gkr_inputs` is true by
default and `Config.warm_gkr_layers` is false. The bench sets the warm-up
whenever it uses the recycler. Knobs: `TENSOR_PREFAULT=0`,
`TENSOR_WARM_GKR=0`. This is a bench-level choice: `prove` takes
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
* **Prefault and warm-up helpers (round 3).** These change when memory is
  allocated and first touched, not what is computed. Every key buffer is
  fully written by `keyValuesInto` / `xt.keyDenInto` after the challenges
  are drawn. The GKR build overwrites every layer entry, so the warm-up's
  zero bytes are never read. E is filled by `batch.fillRegion` as before
  (entries ≥ `lay.used` are never read). Each helper is joined before its
  buffers are used and on every error path, before they are freed. The
  helpers get their slices by value, and an allocation failure ends the
  warm-up early.
* **Segment index / eq_prefix.** The same terms of the same sum are computed;
  the only claims skipped are those whose range excludes x, and they
  contributed 0 before.

## Tests (54 CPU, 12 Metal)

The Metal lazy-factor, batch and eq-prefix tests run for `lazy_rounds` 1, 2,
3 and 5 (clamped to 3).


* decoder-layer goldens (round 3): both configurations are also proved with
  the key-input prefault off and with the GKR layer warm-up on, and must give
  the golden digests;
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

   Round 3: the fault cost is now hidden by the prefault (§What changed 9;
   input stage 0.012 s single shot), so a lazy input layer would save only
   the remaining compute and 16 B/leaf of memory. The estimate below was made
   before the prefault. The input stage is fault bound (0.09 s single shot vs
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
5. **Remaining single-shot gap at layer 512, round 3** (head, single vs
   steady, quiet host): CPU 0.82 vs 0.69 s, Metal 0.59 vs 0.55 s. What is left:
   ext_init 0.042 vs 0.011 s (fresh ext prover state at the start of `prove`;
   nothing earlier runs inside `prove` to overlap with, but a caller could
   overlap it with the forward pass), witness commitment 0.19–0.21 vs 0.16 s
   (codeword buffers allocated inside `pcs` / `pcs2`), and GKR build
   0.069 vs 0.053 s. In steady state the CPU is compute-bound: GKR layer
   sumchecks 0.215 s, commitment 0.16 s, batch 0.107 s.
6. **Metal core op sumchecks at 512 tokens** take ≈0.04 s against ≈0.012 s on
   the CPU (op_sumchecks minus ext_ops). A `sc_min_work` sweep (2^14, 2^16,
   2^18, 2^20) gave no clear winner (0.597–0.651 s prove, noise-level), so the
   threshold is unchanged and the knob was not kept.

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
round 3: `scripts/{matrix5.sh,matrix5b.sh,tables5.py}` (`matrix5.sh L9 <new-prefix> 3 layer 9 11 12 …`,
`START=4 matrix5b.sh L9 <new-prefix> 5 …` for extra rounds; `tables5.py L9 <new-prefix>`).
Knobs: `TENSOR_RECYCLE=0`, `TENSOR_PREFAULT=0`, `TENSOR_WARM_GKR=0`.

## Caveats

* Nothing at 1024 tokens was re-run in round 3 (host memory rules). The
  1024-token tables come from the previous session. Peak RSS with the
  recycler, the prefaults and the warm-up as defaults is **not measured** at
  1024 tokens. At 512 tokens the head's default costs +0.14 GB on the layer
  (6.28 → 6.42 GB) and nothing on the MLP; steady state +0.08–0.17 GB.
  Expect the 1024-token layer CPU peak (12.3 GB before) to rise by a few
  hundred MB. The coordinator's
  large runs now use the recycler unless `TENSOR_RECYCLE=0` is set. Compare
  against the earlier single-shot numbers with `TENSOR_RECYCLE=0`.
* The prefault and warm-up helpers are extra OS threads next to the prover
  pool (one each, short-lived). On a fully loaded host they compete with the
  pool. Zero-fill faults serialize in the macOS kernel anyway, which is why the
  overlap pays off. A deployed prover that reuses memory across proofs (steady
  state) gains nothing from them.
* The GKR layer warm-up depends on `gkr_prover_fast`'s build allocating in the
  same sizes. If that changes, the warm-up stops helping, but correctness is
  unaffected.
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
