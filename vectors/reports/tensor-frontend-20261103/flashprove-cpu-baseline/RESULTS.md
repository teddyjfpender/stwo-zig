# FlashProve `blocks/` CPU reference: same-machine numbers on Apple M4 Max

Source: anthropics/FlashProve at commit 9e2bdd8f (0.16.0-rc.26). Only `blocks/`, its plain C++17 CPU reference prover and verifier, was built. Nothing inside `fp/` was changed.
Machine: Apple M4 Max with 10 P-cores, 4 E-cores and 36 GB of RAM, on AC power. The laptop was shared and in active use. Every job ran under `memguard`, one at a time.
Build: `c++ -std=c++17 -O3 -mcpu=apple-m4 -DBLK_FIELD=2 -DBLK_HASH=1 -include macos_shim.h -I fp/blocks`, with Apple clang 17.0.0.
- `macos_shim.h` adds one function. `coins/coins.h` calls Linux `getrandom()`, so the shim maps it to `getentropy()`.
- The Makefile's default `-O2 -fno-ipa-modref` and g++ were not used.

Method: each figure is the median of at least 5 reps after 1 warm-up. The L=20 toy runs use 3 reps. Outputs are folded into a `volatile` sink so the compiler cannot drop the work.
- **M** = measured here.
- **D** = derived by arithmetic from measured or published numbers.
- **P** = published by FlashProve (docs or paper). Not reproduced here.

**Threading:** the CPU engine `EngineCpu` is **strictly sequential**. Its header says "plain, sequential C++", and it allows one thread per engine. The repo's CPU prover is therefore single-core.
- The "10 thr" and "14 thr" columns come from my harness, not from their engine. They run the same single-thread kernel independently on T threads at once, which gives an upper bound for embarrassingly parallel work.
- 10 threads is roughly "all P-cores". The 14-thread numbers are wall-clock-limited by the slowest thread, which lands on an E-core, so they come out *lower* than the 10-thread numbers.

Files (all in this folder):
- Code: `prim_bench.cpp`, `toy_scale.cpp`, `emul_check*.cpp`, `fmul_ilp.cpp`
- Logs: `prim_{1,10,14}t.log`, `toy_*.log`, `toy_L20_sample.txt` (profile), `cp_frame_request_fullsize.log`
- Machine-readable: `results.json`

---

## 1. Primitive throughputs (M)

### (a)–(c) Field arithmetic: their `operator*` and `operator+` in `field/field.h` and `field/gl64.h`

The kernels are scalar. The `u64` code does `u128` products, reduces them with the plonky2 `reduce128` method, and uses lazy reduction (`dot3`) for E×E. Arrays are 4096 elements long and fit in L1/L2.

| op | loop shape | 1 thread | 10 thr (aggregate) | 14 thr |
|---|---|---|---|---|
| F×F mul | `z[i]=x[i]*y[i]` (arrays) | **1.17e9 /s** (0.86 ns) | 1.04e10 /s | 8.7e9 /s |
| F×F mul | 8 independent register chains (`fmul_ilp`) | **1.66e9 /s** (0.60 ns) | – | – |
| F×F mul | dependent latency chain | 3.4e8 /s (2.9 ns) | 3.1e9 /s | 3.2e9 /s |
| F mul-add | `acc_j += x*y`, 4 register accumulators | **1.30e9 /s** (0.77 ns) | 1.22e10 /s | 9.8e9 /s |
| F add | arrays | 6.3e9 /s (0.16 ns) | 5.8e10 /s | 4.4e10 /s |
| E×E mul | `z[i]=x[i]*y[i]` (arrays, load-mul-store) | 2.26e8 /s (4.4 ns) | 2.0e9 /s | 1.7e9 /s |
| E×E mul-add | `acc_j += x*y`, 4 register accumulators | **5.5e8 /s** (1.80 ns) | 5.1e9 /s | 4.0e9 /s |
| E×E mul | dependent latency chain | 1.7e8 /s (6.0 ns) | 1.6e9 /s | 1.3e9 /s |
| E×F mul | arrays | 5.2e8 /s (1.9 ns) | 4.9e9 /s | 3.9e9 /s |
| E×F mul-add | 4 register accumulators | **1.32e9 /s** (0.76 ns) | 1.2e10 /s | 9.1e9 /s |

Notes:
- Loop shape matters more than I expected.
  - With clang 17, E×E in a load-mul-store array loop runs at 4.4 ns, close to its 6.0 ns latency. That stays true with vectorization disabled and `__restrict` added (`emul_check2.log`).
  - The same product inside a reduction runs at 1.8–1.9 ns.
  - The engine's own `fold_round` loop (below) gets about 1.2 ns per E×E.
- Take the register-accumulator rows as the throughput figures: about 1.3–1.7e9 F mul/s and about 5.5e8 E×E mul/s per P-core.
- E×F mul-add reaches 1.32e9/s. That is about 4e9 base-field products/s, because each E×F is three F products, so the F×F loops are not limited by the multiplier.
- One E×E costs 9 `mul_wide` and 3 reductions. E×F costs 3 F muls.
- Compiler: clang, not the g++ 13.3 they tuned for. Their comments say mask-vs-branch choices and inlining were timed on g++.

### (d) BLAKE2b in their tree code (`hash/hash.h`, `tree/opening.h`, `tree/tree.h`)

Leaf format: a label (tag word and index), the column's 8-byte symbols, zero padding if needed, then a **40-byte salt** (the default). Inner vertices are one compression each: `vertex()`, a label plus two 32-byte digests in one 128-byte block.

| item | 1 thread | 10 thr | 14 thr |
|---|---|---|---|
| leaf, 3 symbols (1 compression) | 9.9e6 leaves/s; 238 MB/s of column payload, 793 MB/s of hashed bytes | 9.3e7 /s | 7.7e7 /s |
| leaf, 12 symbols (2 compressions) | 5.1e6 /s; 490 MB/s payload | 4.7e7 /s | 3.9e7 /s |
| leaf, 96 symbols (7 compressions) | 1.35e6 /s; **1,040 MB/s** payload | 1.25e7 /s; 9.6 GB/s | 9.0e6 /s |
| leaf, 2048 symbols (129 compressions; the width of the weight table's column) | 7.1e4 /s; **1,162 MB/s** payload | 6.8e5 /s; **11.1 GB/s** | 6.2e5 /s |
| `vertex()` (1 compression) | 1.03e7 /s (97 ns) | 9.6e7 /s | 8.3e7 /s |
| **Merkle tree, 2^20 leaves, width 3 + salt** (leaves, then `Tree` build) | **0.214 s** (0.110 leaves + 0.107 vertices) | 0.234 s per tree per thread (4.5e7 leaves/s aggregate) | – |
| **Merkle tree, 2^20 leaves, width 96 + salt** (805 MB of columns) | **0.896 s** (0.812 + 0.101) | not run (0.8 GB per thread) | – |

The BLAKE2b compression costs about 95–110 ns, or about 1.17 GB/s for one stream on a P-core. This is their portable `Blake2bF`, with no SIMD and no multi-lane code.

### (e) Reed–Solomon encoding (`code/code.h`, `Encoder::encode`)

The encoder writes the tail, then the message, in coefficient form, copies that block up to n, and then runs `log_dim` radix-2 butterfly layers. The layers are a coset NTT on Goldilocks, with twiddles from a cached table.
- r > 0 pushes dim = ell + r above 2^log2(ell), which adds a full NTT layer. For example, the full-size config's `long` code (ell = 2^22, r = 218, n = 2^23) runs **23** layers on 2^23 points, so it costs a full-length NTT.
- Rates the repo uses:
  - full-size segment code: ~1/2 (log_n = 23, ell = 2^22, r = 219)
  - toy runs: 1/8
  - weight table: 0.1041 (n = 2^32)

| ell (message) | n | r | 1 thread: msg elts/s (codeword symbols/s) | 10 thr aggregate | 14 thr |
|---|---|---|---|---|---|
| 2^16 | 2^17 | 0 | 6.8e7 (1.35e8) | 3.6e8 | 4.9e8 |
| 2^16 | 2^17 | 218 | 6.2e7 (1.24e8) | 3.3e8 | 4.6e8 |
| 2^16 | 2^19 | 86 | 1.57e7 (1.26e8) | 9.5e7 | 1.1e8 |
| 2^18 | 2^19 | 0 | 5.9e7 (1.17e8) | 3.4e8 | 4.3e8 |
| 2^18 | 2^19 | 218 | 5.5e7 (1.11e8) | 3.5e8 | 4.1e8 |
| 2^18 | 2^21 | 86 | 1.35e7 (1.08e8) | 9.9e7 | 1.1e8 |
| 2^20 | 2^21 | 0 | 5.2e7 (1.03e8) | 3.5e8 | 4.2e8 |
| 2^20 | 2^21 | 218 | 4.9e7 (9.9e7) | 3.5e8 | 4.2e8 |
| 2^20 | 2^23 | 86 | 1.17e7 (9.4e7) | 8.8e7 | 9.9e7 |
| 2^22 | 2^23 | 0 | 4.6e7 (9.2e7) | – | – |
| **2^22** | **2^23** | **218** | **4.3e7 (8.7e7); 0.097 s per row** | – | – |
| 2^22 | 2^25 | 86 | 1.1e7 (8.9e7); 0.379 s per row | – | – |

- `Encoder<E>` with ell = 2^18, n = 2^21, r = 86 runs at 4.0e6 E-elements/s. That is about 3× the F cost, as expected, and `EngineCpu` encodes E rows coordinate by coordinate as F anyway.
- One thread produces about 0.9–1.35e8 codeword symbols/s. Running many rows in parallel saturates near **7e8 codeword symbols/s** on 10 P-cores, which looks memory-bandwidth-bound. Per thread at 10 threads, the cost is about 1.5–2× the single-thread figure.

### (f) Fold and sumcheck kernels

`EngineCpu::fold_round` and `EngineCpu::halve` (the `fold_bind` kernel) are private, so their loops are **copied verbatim** into `prim_bench.cpp`. `SumcheckCpu` is the repo's public class, called directly with the toy run's summand: eq(ζ,·)·(a·b − c), over 3 maps in E.

| kernel | size | 1 thread | 10 thr aggregate |
|---|---|---|---|
| `fold_round`: round message q(X) of degree 2, over all (lo, hi) row pairs, 4 E×E per pair | 2^18 / 2^20 / 2^22 E entries in m (and c) | **2.2–2.3 ns per entry of m** (4.3–4.6e8 entries/s) | 2.3–2.5e9 /s |
| `halve` (bind): `lo + g*(hi-lo)`, 1 E×E per output | 2^18–2^22 entries | **2.8–3.0 ns per input entry** (net of a copy) | ~1.2e9 /s with the copy included |
| `SumcheckCpu::round()`, first round | k = 14 / 16 / 18 | **205 / 225 / 245 ns per hypercube point** | – |
| `SumcheckCpu::bind()`, 3 maps | k = 14–18 | 2.7–2.9 ns per element | – |

- `SumcheckCpu` is a naive reference. For every point b, `round()` recomputes the eq weight as a product over the k − j − 1 remaining variables, which makes it O(k·2^k) per round. It also evaluates the summand through a `std::function` with heap vectors.
- In the CPU path the masked sumcheck of `cp_prove` uses its own implementation, which is not in `blocks/` (see `blocks/README.md`).

---

## 2. Whole toy runs: prover vs. verifier (M)

**Statement (`blocks/toy/product.h`).** The prover knows a, b, c ∈ F^(2^L) with a[i]·b[i] = c[i] for all i, and the proof is meant to hide them. The steps:
1. **SEND.** One oracle message carries the main rows a, b, c (k = 2: three rows in a table of 4) and one mask row over E. All of it is RS-encoded and committed in one salted Merkle tree, together with its out-of-domain sample and the fresh mask of the first fold.
2. **ZERO.** The verifier draws ζ ∈ E^L, and the claim becomes Σ_i eq(ζ,i)·(a_i·b_i − c_i) = 0.
3. **PSC.** A sumcheck with a hiding polynomial runs on that sum. It leaves 3 linear claims on the oracle: (hiding poly, c), a at the point, and b at the point.
4. **Zero-knowledge proximity test (IOPP).** The test runs on the group and batches those claims with the OOD answers. Each stage folds rows (FOLD, a masked sumcheck over the row variables), then a code switch (CS) re-encodes the folded row into 2^k shorter rows under a new code, which the verifier checks at random positions. A last stage (BASE) sends the final message masked and in full.

Setting: 128-bit target in every round (Johnson-radius bounds, as their accounting prints) and 40-byte salts. Proof of work on position rounds is 0 unless stated otherwise. All proofs were **ACCEPTED** by `toy_verify_file()`, which re-derives the plan from the public text alone.

Staging:
- **"repo-default"** is the pattern of the repo's own toy runs: `toy_size(L, log_n=L+3, mask=L−1, {1,1,L+2,L}, {0,0,L+2,L+2})`. The first code has rate 1/8 and about 86 positions. There is only one fold, so the last stage sends about 2^(L−1) E elements in full, and proof size grows **linearly** in n.
- **"deep"** is my choice: `{4,3,L,L−4}, {4,3,L−3,L−6}, {0,0,L−5,L−5}`. It adds two k = 4 code-switch stages, which keeps the proof size flat. The repo's planner refuses this pattern at L = 12 and 14, where the message and randomness do not fit the code.

| L (vector length 2^L) | staging | PoW bits | prover (median) | verifier (median) | proof bytes | first code: n, rate, positions |
|---|---|---|---|---|---|---|
| 12 (their `toy_run` binary, unmodified) | default | 0 | 0.052 s | 0.012 s | 176,328 | 2^15, 1/8, 87 |
| 12 | default | 0 | 0.047 s | 0.012 s | 175–177 K | 2^15, 1/8, 87 |
| 14 | default | 0 | 0.195 s | 0.014 s | 337–339 K | 2^17, 1/8, 86 |
| 16 | default | 0 | 0.802 s | 0.035 s | 943–946 K | 2^19, 1/8, 86 |
| 16 | default | 20 | 0.960 s (0.217 s of it is PoW) | 0.031 s | 925 K | 2^19, 1/8, 73 |
| 16 | deep | 0 | 0.494 s | 0.022 s | 269–271 K | 2^19, 1/8, 86 |
| 18 | default | 0 | 3.10 s | 0.123 s | 3.32 MB | 2^21, 1/8, 86 |
| 18 | deep | 0 | 2.05 s | 0.012 s | 251 K | 2^21, 1/8, 86 |
| 20 | default | 0 | 12.87 s | 0.495 s | 12.77 MB | 2^23, 1/8, 86 |
| **20** | **deep** | 0 | **8.37 s** | **0.014 s** | **341 K** | 2^23, 1/8, 86 (later stages: 65, 52, 87) |
| 20 | deep | 20 | 8.63 s (0.52 s of it is PoW) | 0.0125 s | 308 K | 2^23, 1/8, 73 (later: 55, 44, 73) |

- The prover scales by about 4× per +2 in L, so it is linear in n. At L = 20, about 8 µs of single-thread prover time per witness entry with deep staging, and 12 µs with default staging.
- Peak RSS at L = 20 (default staging) was 3.3 GB.

**Prover split by engine call** (a timing wrapper subclasses `EngineCpu`). At L = 20 with deep staging, of 8.37 s:
- `commit` (encode + leaves + tree + drawing tails and salts): 7.33 s
- `fold_begin`: 0.39 s
- `fold_round` and `fold_bind`: 0.14 s
- `evaluate`: 0.09 s
- the rest is host-side sumcheck and Fiat–Shamir work

**Profile (M; macOS `sample`).** One L = 20 run with default staging, 8,518 top-of-stack samples:

| share | where the time goes |
|---|---|
| **51%** | ChaCha20 in `StreamCoins`, drawing the salt (40 B per leaf) and random tails |
| **30%** | BLAKE2b leaves and vertices |
| 6.6% | RS `encode_rows` |
| 4.7% | `SumcheckCpu` |
| 3.6% | Tensor / `evaluate` |
| 1.2% | folds |

On the CPU reference, private randomness and hashing dominate the prover's time, not field arithmetic.

---

## 3. Default parameters (from the repo) and published H100 figures

### Default parameters

Source: `examples/full-size/config/policy.txt`, the default full-size parameter file. I planned it with their read-only planner, `blocks/frame/cp_frame -plan request` (output in `cp_frame_request_fullsize.log`).

General:
- **Target:** 128 bits per round, with proof of work counted. Without PoW the weakest round is 96.23 bits (P, figures.tsv).
- **Proof of work** applies only to position-drawing rounds: **20 bits** per request, **28 bits** shared per batch, **32 bits** offline/once. All other rounds have 0 bits. The most PoW in any round is 32 bits.
- **Salt:** 40 bytes per leaf. BLAKE2b, 32-byte digests.
- **Field and code:** Goldilocks with challenges in E (cubic). Plain RS on 2-adic cosets. Proximity tests go up to the Johnson radius minus a slack, citing ePrint 2025/2055, Thm 4.6, which they take as given.

**Weight table** (paper Table 2 and the `table` line):

| quantity | value |
|---|---|
| shape | 2^11 = **2048 rows**, so a column holds 2048 F |
| row message ℓ | **402,653,184** (402,653,181 plain plus 3 OOD pads) |
| random coefficients t | **44,040,191** |
| \|D\| | **2^32** |
| rate ρ = (ℓ + t)/\|D\| | **0.1041** |
| decoder radius δ | 0.6640 |
| matrix A | d = 3,076,096 matrix rows by 2^18 columns, about 8.06e11 table entries |

Opened columns (paper Table 2 and the cp_frame output):

| case | columns |
|---|---|
| ν_on | **64 per batch** |
| ν_off, ν_first, ν_copy | 62 each |
| one-time test | 62 |
| link | 62 + 62 |

Budgets: K ≤ 710,324 copies and N_j ≤ 688,127 batches per copy. They come from the masks' opening budget, ν_off + K·ν_first ≤ t.

**Opened-column bytes (D):** a column is 2048 × 8 B plus a 40 B salt, about 16.4 KB. 64 columns come to about 1.05 MB per batch, plus Merkle siblings.

**Opening formula** (`tree/opening.h`, `opening_bytes`): `|list|·(width·8 + salt) + (#siblings tree_walk needs)·32`. Siblings are deduplicated across the opened leaves of one tree. Proof size is the sum, over the planned messages, of field elements (8 B for F, 24 B for E), digests, nonces (8 B) and openings. `numbers/accounting.h` and `numbers/plan.h` plan the expected and maximum sizes.

**Per-request segment group "link":**
- First code: 2^23, ℓ = 2^22 + 219 random, 2^7 rows, **rate ~1/2**, proximity δ_seg = 0.290134, **219 positions**.
- Mask code: 2^17.
- Later IOPP stages open 55, 55, 55, 46 and 44 positions.

Other groups (folded table and links: code 2^24, rate 1/4, 97–101 positions; Ω and own: 2^22, 49–55 positions) are listed in `cp_frame_request_fullsize.log`.

**Planned file sizes (M, by the planner):**

| file | average | maximum |
|---|---|---|
| proof | **19.20 MB** | 19.68 MB |
| key | 3.29 MB | – |
| entry (leaf) | 2.94 MB | – |

Published (P): the mean proof is 18.78 MB, the key file 3.29 MB, and the client downloads 6.24 MB.

### Published H100 performance (P)

Sources: `docs/figures.tsv` and paper §7.2, Table 3. Setup: one H100 80 GB, 24 CPUs, up to 278 GB of host memory, Llama-4-Maverick-size integer model (400.7B weights), windows of 1,024 tokens.

| quantity | value |
|---|---|
| time per request, batches of 24 (a batch's time / 24) | **9.206 s** (n = 3, s.d. 0.077) |
| rate, batches of 24 | **111.23 tokens/s** |
| batch latency, 24 requests | 220.7–225.9 s |
| one request alone | 58.8 s/request (17.41 tokens/s) |
| batches of 8 | 13.41 s/request |
| batches of 64 | 123 tokens/s, but runs failed with CUDA errors |
| commitment, once (first table and one copy) | **2,323.77 s** |
| verifier, C++, 1 thread | 21.14 s |
| verifier, C++, 24 threads | 17.07 s |
| verifier, Lean executable | 1,414 s |

- **Per-stage breakdown of the 9.2 s:** **not published.** I searched `docs/figures.tsv`, `paper.txt` (the text of paper.pdf), `docs/*.md` and `prover/docs/*.md`, and found no split of weights opening/folding vs. look-ups vs. sumcheck vs. hashing, and no throughput figure for the weight passes.
- What is published about structure (`docs/architecture.md`): a batch proves its requests `-in-step` at a time per pass over the weights. Opening the batch's columns of the leaf table then takes **two more passes over the weights**: first a fold of the table's rows at a point drawn after every request's first chain, then the opening.
- **Derived estimate (D), only as a scale check:** suppose the 2,323.77 s commitment RS-encodes and hashes the full 2048 × 2^32 table twice ("the first table and one copy"). That is about 2 × 8.8e12 codeword symbols, so roughly 7.6e9 symbols/s and roughly 60 GB/s of BLAKE2b on one H100 plus host. Compare about 7e8 symbols/s and 11 GB/s here across 10 M4 P-cores. This assumption is not verified against their code.

---

## Caveats
- These numbers come from their *reference* CPU code. They do not reflect their CUDA prover, and the CPU path of `cp_prove` uses other sub-proof implementations.
- Their code was tuned for g++ 13 on x86. Here it ran on clang 17 on arm64.
- The host was shared and interactive. The spread between reps was within about 3% for the toy runs.
- The 14-thread figures are below the 10-thread ones because the median wall time is set by the threads on E-cores.
