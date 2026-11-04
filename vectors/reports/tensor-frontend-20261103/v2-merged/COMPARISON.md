# Tensor frontend vs FlashProve: measured comparison

## Primitives, one core, same machine (Apple M4 Max)

| primitive | stwo-tensor (M31/QM31, Blake2s) | FlashProve (Goldilocks/cubic, BLAKE2b) |
|---|---|---|
| base mul (arrays) | 3.75e+09/s (SIMD 1.02e+10/s) | 1.17e9/s |
| extension mul (arrays) | 1.93e+08/s | 2.26e8/s (5.5e8/s in register accumulation) |
| extension x base mul-add | 1.63e+09/s | 1.32e9/s |
| column leaf hash (2048 symbols) | 396 MB/s | 1,160 MB/s |
| RS encode 2^20 rate 1/2 (codeword symbols/s) | 2.97e+08 | 1.35e8 (2^16) / 8.7e7 (2^22) |
| sumcheck deg 2, all rounds, per entry | 10.6 ns | ~5 ns first round (fold_round 2.2 + halve 2.8) |

## Same statement, same machine: a (.) b = c over 2^L (FlashProve blocks/toy/product.h)

FlashProve: deep staging (their best proof size), hiding on, 1 core. Ours: non-hiding unless noted.

| L | config | ours prove | ours verify | ours proof | FlashProve prove | FlashProve verify | FlashProve proof | prove speedup |
|---|---|---|---|---|---|---|---|---|
| 16 | proven128 (160q, rate 1/4, 20 PoW) | 0.032 s | 1.0 ms | 151 KB | 0.49 s | 22 ms | 269 KB | 15.4x |
| 18 | proven128 (160q, rate 1/4, 20 PoW) | 0.052 s | 1.2 ms | 195 KB | 2.05 s | 12 ms | 251 KB | 39.1x |
| 20 | proven128 (160q, rate 1/4, 20 PoW) | 0.166 s | 1.5 ms | 250 KB | 8.37 s | 14 ms | 341 KB | 50.3x |
| 22 | proven128 (160q, rate 1/4, 20 PoW) | 0.693 s | 1.9 ms | 328 KB | - | - | - | - |
| 16 | conj128 (54q, rate 1/4, 20 PoW) | 0.016 s | 0.5 ms | 77 KB | 0.49 s | 22 ms | 269 KB | 29.8x |
| 18 | conj128 (54q, rate 1/4, 20 PoW) | 0.055 s | 0.6 ms | 93 KB | 2.05 s | 12 ms | 251 KB | 37.2x |
| 20 | conj128 (54q, rate 1/4, 20 PoW) | 0.159 s | 0.7 ms | 118 KB | 8.37 s | 14 ms | 341 KB | 52.8x |
| 22 | conj128 (54q, rate 1/4, 20 PoW) | 0.613 s | 0.7 ms | 141 KB | - | - | - | - |

## SwiGLU MLP layer (D=4096, F=8192, 100.7M int8 weights), 12 threads

| config | tokens | prove (+ integer forward) | verify | proof | proved MAC/s | prove us/token | committed bits/token | stage split (commit/GKR/op/batch/open) |
|---|---|---|---|---|---|---|---|---|
| conj128 | 256 | 0.38 s (+0.14) | 3.1 ms | 361 KB | 6.80e+10 | 1481 | 1064960 | 0.04/0.10/0.02/0.03/0.10 |
| conj128 | 512 | 0.61 s (+0.30) | 3.1 ms | 379 KB | 8.40e+10 | 1199 | 1056768 | 0.07/0.16/0.02/0.06/0.10 |
| conj128 | 1024 | 1.22 s (+0.59) | 3.2 ms | 405 KB | 8.44e+10 | 1192 | 1056768 | 0.16/0.34/0.02/0.17/0.11 |
| conj128 | 2048 | 2.26 s (+1.17) | 4.4 ms | 434 KB | 9.13e+10 | 1102 | 1052672 | 0.31/0.62/0.02/0.30/0.16 |
| proven128 | 256 | 0.55 s (+0.18) | 5.7 ms | 814 KB | 4.71e+10 | 2136 | 1064960 | 0.06/0.21/0.03/0.04/0.10 |
| proven128 | 512 | 0.80 s (+0.38) | 5.9 ms | 865 KB | 6.45e+10 | 1559 | 1056768 | 0.10/0.26/0.02/0.07/0.09 |
| proven128 | 1024 | 1.39 s (+0.69) | 6.3 ms | 915 KB | 7.40e+10 | 1360 | 1056768 | 0.22/0.45/0.02/0.15/0.11 |
| proven128 | 2048 | 2.06 s (+0.98) | 6.7 ms | 970 KB | 1.00e+11 | 1004 | 1056768 | 0.28/0.53/0.02/0.28/0.13 |

## Llama-style decoder layer (GQA attention + RoPE + softmax + RMSNorm + SwiGLU), 12 threads

| config | tokens | D | F | heads (q/kv) | weights | prove (+fwd) | verify | proof | prove ms/token |
|---|---|---|---|---|---|---|---|---|---|
| conj128 | 1024 | 2048 | 4096 | 16/4 | 35.7M | 4.77 s (+0.57) | 36.6 ms | 523 KB | 4.66 |
| conj128 | 512 | 2048 | 4096 | 16/4 | 35.7M | 1.55 s (+0.19) | 14.2 ms | 469 KB | 3.03 |
| proven128 | 1024 | 2048 | 4096 | 16/4 | 35.7M | 5.55 s (+0.57) | 39.8 ms | 1.08 MB | 5.42 |
| proven128 | 512 | 2048 | 4096 | 16/4 | 35.7M | 1.70 s (+0.21) | 18.0 ms | 970 KB | 3.33 |

