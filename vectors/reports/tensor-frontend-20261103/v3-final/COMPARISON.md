# Tensor frontend vs FlashProve: measured comparison

Proof sizes are wire-encoded bytes (design/tensor-frontend/wire.md, the files `tensor-verify` reads); '*' marks rows that only report the struct-field sum.

## Primitives, one core, same machine (Apple M4 Max)

| primitive | stwo-tensor (M31/QM31, Blake2s) | FlashProve (Goldilocks/cubic, BLAKE2b) |
|---|---|---|
| base mul (arrays) | 5.12e+09/s (SIMD 1.09e+10/s) | 1.17e9/s |
| extension mul (arrays) | 2.39e+08/s | 2.26e8/s (5.5e8/s in register accumulation) |
| extension x base mul-add | 1.70e+09/s | 1.32e9/s |
| column leaf hash (2048 symbols) | 424 MB/s | 1,160 MB/s |
| RS encode 2^20 rate 1/2 (codeword symbols/s) | 4.61e+08 | 1.35e8 (2^16) / 8.7e7 (2^22) |
| sumcheck deg 2, all rounds, per entry | 6.9 ns | ~5 ns first round (fold_round 2.2 + halve 2.8) |

## Same relation (a (.) b = c over 2^L), same machine, NON-hiding (ours) vs hiding (FlashProve)

FlashProve: its sequential CPU reference (blocks/toy/product.h, not the CUDA cp_prove), deep staging, hiding on, 0 PoW, 1 core.
Ours here is NON-hiding; the like-for-like hiding comparison is the next section. 'bits' = our soundness calculator's
all-rounds-added bound with / without PoW (FlashProve's own all-rounds figure: 119.38 / 92.42).

| L | config | bits (w/ / w/o PoW) | ours prove | ours verify | ours proof | FlashProve prove | FlashProve verify | FlashProve proof | prove ratio |
|---|---|---|---|---|---|---|---|---|---|
| 16 | proven128 (160q, rate 1/4, 20 PoW) | 104.3 / 104.0 | 0.017 s | 0.9 ms | 149 KB | 0.49 s | 22 ms | 269 KB | 29.4x |
| 18 | proven128 (160q, rate 1/4, 20 PoW) | 102.3 / 102.2 | 0.036 s | 1.1 ms | 197 KB | 2.05 s | 12 ms | 251 KB | 56.2x |
| 20 | proven128 (160q, rate 1/4, 20 PoW) | 100.3 / 100.3 | 0.139 s | 1.4 ms | 249 KB | 8.37 s | 14 ms | 341 KB | 60.2x |
| 22 | proven128 (160q, rate 1/4, 20 PoW) | 98.3 / 98.3 | 0.535 s | 1.8 ms | 331 KB | - | - | - | - |
| 16 | conj128 (54q, rate 1/4, 20 PoW) | 54.8 / 34.8 | 0.017 s | 0.5 ms | 76 KB | 0.49 s | 22 ms | 269 KB | 29.6x |
| 18 | conj128 (54q, rate 1/4, 20 PoW) | 54.9 / 34.9 | 0.036 s | 0.5 ms | 94 KB | 2.05 s | 12 ms | 251 KB | 57.5x |
| 20 | conj128 (54q, rate 1/4, 20 PoW) | 55.0 / 35.0 | 0.122 s | 0.6 ms | 118 KB | 8.37 s | 14 ms | 341 KB | 68.5x |
| 22 | conj128 (54q, rate 1/4, 20 PoW) | 55.0 / 35.0 | 0.513 s | 0.8 ms | 142 KB | - | - | - | - |
| 16 | johnson (122q, rate 1/4, 20 PoW) | 113.7 / 98.2 | 0.020 s | 0.9 ms | 165 KB | 0.49 s | 22 ms | 269 KB | 24.1x |
| 18 | johnson (122q, rate 1/4, 20 PoW) | 113.6 / 96.8 | 0.047 s | 1.1 ms | 206 KB | 2.05 s | 12 ms | 251 KB | 43.5x |
| 20 | johnson (122q, rate 1/4, 20 PoW) | 113.5 / 96.8 | 0.148 s | 1.3 ms | 249 KB | 8.37 s | 14 ms | 341 KB | 56.7x |
| 22 | johnson (122q, rate 1/4, 20 PoW) | 113.4 / 96.1 | 0.600 s | 1.7 ms | 316 KB | - | - | - | - |

## HEADLINE: hiding vs hiding, same relation and machine (FlashProve sequential CPU reference, 20-bit PoW where available)

Both sides zero-knowledge. Our hiding-mode bits are the query term only (unique decoding) until the calculator covers hiding openings.

| L | ours prove | ours verify | ours proof | FlashProve prove | FlashProve verify | FlashProve proof | prove ratio |
|---|---|---|---|---|---|---|---|
| 16 | 0.027 s | 0.8 ms | 137 KB* | 0.49 s | 22 ms | 269 KB | 18.2x |
| 18 | 0.079 s | 1.1 ms | 215 KB* | 2.05 s | 12 ms | 251 KB | 26.0x |
| 20 | 0.305 s | 1.9 ms | 369 KB* | 8.63 s | 12 ms | 308 KB | 28.3x |
| 22 | 1.229 s | 3.1 ms | 674 KB* | - | - | - | - |

## Zero-knowledge MLP layer (hiding weights + witness, public input/output), D=4096, F=8192, 12 threads

| tokens | prove (+fwd) | verify | proof | weight commit (once) | peak RSS |
|---|---|---|---|---|---|
| 256 | 0.79 s (+0.26) | 70 ms | 2.82 MB* | 1.88 s | 8.6 GB |
| 512 | 1.45 s (+0.52) | 128 ms | 3.12 MB* | 1.95 s | 10.0 GB |
| 1024 | 2.73 s (+0.99) | 245 ms | 3.55 MB* | 1.93 s | 13.0 GB |

## SwiGLU MLP layer (D=4096, F=8192, 100.7M int8 weights), 12 threads

| config | tokens | prove (+ integer forward) | verify | proof | proved MAC/s (fwd+prove) | prove us/token | committed bits/token | stage split (commit/GKR/op/batch/open) |
|---|---|---|---|---|---|---|---|---|
| conj128 | 256 | 0.26 s (+0.25) | 33.9 ms | 392 KB | 5.03e+10 | 1027 | 1064960 | 0.03/0.06/0.02/0.02/0.10 |
| conj128 | 512 | 0.41 s (+0.49) | 64.7 ms | 412 KB | 5.72e+10 | 795 | 1056768 | 0.07/0.09/0.03/0.04/0.11 |
| conj128 | 1024 | 0.67 s (+1.00) | 126.1 ms | 434 KB | 6.16e+10 | 656 | 1056768 | 0.13/0.17/0.05/0.08/0.13 |
| conj128 | 2048 | 1.19 s (+2.05) | 248.5 ms | 463 KB | 6.36e+10 | 583 | 1052672 | 0.25/0.32/0.09/0.16/0.14 |
| johnson | 256 | 0.34 s (+0.25) | 36.5 ms | 806 KB | 4.38e+10 | 1310 | 1064960 | 0.03/0.05/0.02/0.02/0.18 |
| johnson | 512 | 0.48 s (+0.50) | 67.3 ms | 851 KB | 5.25e+10 | 935 | 1056768 | 0.06/0.09/0.03/0.04/0.19 |
| johnson | 1024 | 0.77 s (+1.03) | 129.2 ms | 897 KB | 5.71e+10 | 754 | 1056768 | 0.13/0.17/0.05/0.08/0.22 |
| johnson | 2048 | 1.32 s (+2.07) | 252.0 ms | 963 KB | 6.07e+10 | 646 | 1052672 | 0.25/0.33/0.09/0.17/0.24 |
| proven128 | 256 | 0.28 s (+0.29) | 37.1 ms | 894 KB | 4.53e+10 | 1077 | 1064960 | 0.03/0.05/0.02/0.02/0.11 |
| proven128 | 512 | 0.41 s (+0.50) | 68.0 ms | 938 KB | 5.66e+10 | 801 | 1056768 | 0.06/0.09/0.03/0.04/0.13 |
| proven128 | 1024 | 0.68 s (+0.98) | 129.7 ms | 990 KB | 6.22e+10 | 663 | 1056768 | 0.12/0.17/0.05/0.08/0.14 |
| proven128 | 2048 | 1.23 s (+1.98) | 252.5 ms | 1.04 MB | 6.42e+10 | 600 | 1056768 | 0.26/0.33/0.09/0.16/0.16 |

## Llama-style decoder layer (GQA attention + RoPE + softmax + RMSNorm + SwiGLU), 12 threads

| config | tokens | D | F | heads (q/kv) | weights | prove (+fwd) | verify | proof | prove ms/token |
|---|---|---|---|---|---|---|---|---|---|
| conj128 | 1024 | 2048 | 4096 | 16/4 | 37.7M | 1.70 s (+0.35) | 84.4 ms | 525 KB | 1.66 |
| conj128 | 512 | 2048 | 4096 | 16/4 | 37.7M | 0.70 s (+0.15) | 40.4 ms | 474 KB | 1.37 |
| johnson | 1024 | 2048 | 4096 | 16/4 | 37.7M | 1.89 s (+0.35) | 87.5 ms | 1.03 MB | 1.85 |
| johnson | 512 | 2048 | 4096 | 16/4 | 37.7M | 0.76 s (+0.15) | 42.9 ms | 912 KB | 1.49 |
| proven128 | 1024 | 2048 | 4096 | 16/4 | 37.7M | 1.74 s (+0.35) | 87.6 ms | 1.09 MB | 1.70 |
| proven128 | 512 | 2048 | 4096 | 16/4 | 37.7M | 0.79 s (+0.15) | 43.5 ms | 988 KB | 1.54 |

