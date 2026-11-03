# Tensor frontend vs FlashProve: measured comparison

## Primitives, one core, same machine (Apple M4 Max)

| primitive | stwo-tensor (M31/QM31, Blake2s) | FlashProve (Goldilocks/cubic, BLAKE2b) |
|---|---|---|
| base mul (arrays) | 5.17e+09/s (SIMD 1.07e+10/s) | 1.17e9/s |
| extension mul (arrays) | 1.74e+08/s | 2.26e8/s (5.5e8/s in register accumulation) |
| extension x base mul-add | 1.70e+09/s | 1.32e9/s |
| column leaf hash (2048 symbols) | 393 MB/s | 1,160 MB/s |
| RS encode 2^20 rate 1/2 (codeword symbols/s) | 4.21e+08 | 1.35e8 (2^16) / 8.7e7 (2^22) |
| sumcheck deg 2, all rounds, per entry | 11.1 ns | ~5 ns first round (fold_round 2.2 + halve 2.8) |

## Same statement, same machine: a (.) b = c over 2^L (FlashProve blocks/toy/product.h)

FlashProve: deep staging (their best proof size), hiding on, 1 core. Ours: non-hiding unless noted.

| L | config | ours prove | ours verify | ours proof | FlashProve prove | FlashProve verify | FlashProve proof | prove speedup |
|---|---|---|---|---|---|---|---|---|
| 16 | proven128 (130q, rate 1/8, 20 PoW) | 0.036 s | 1.0 ms | 189 KB | 0.49 s | 22 ms | 269 KB | 13.6x |
| 18 | proven128 (130q, rate 1/8, 20 PoW) | 0.125 s | 1.7 ms | 326 KB | 2.05 s | 12 ms | 251 KB | 16.4x |
| 20 | proven128 (130q, rate 1/8, 20 PoW) | 0.500 s | 2.7 ms | 596 KB | 8.37 s | 14 ms | 341 KB | 16.7x |
| 22 | proven128 (130q, rate 1/8, 20 PoW) | 1.898 s | 5.2 ms | 1.13 MB | - | - | - | - |
| 16 | conj128 (54q, rate 1/4, 20 PoW) | 0.022 s | 0.5 ms | 97 KB | 0.49 s | 22 ms | 269 KB | 22.0x |
| 18 | conj128 (54q, rate 1/4, 20 PoW) | 0.082 s | 0.9 ms | 173 KB | 2.05 s | 12 ms | 251 KB | 24.9x |
| 20 | conj128 (54q, rate 1/4, 20 PoW) | 0.336 s | 1.6 ms | 323 KB | 8.37 s | 14 ms | 341 KB | 24.9x |
| 22 | conj128 (54q, rate 1/4, 20 PoW) | 1.331 s | 2.9 ms | 622 KB | - | - | - | - |

## SwiGLU MLP layer (D=4096, F=8192, 100.7M int8 weights), 12 threads

| tokens | prove | verify | proof | proved MAC/s | prove us/token | committed bits/token | stage split (commit/GKR/op/batch/open) |
|---|---|---|---|---|---|---|---|
| 1024 | 2.62 s | 26 ms | 7.64 MB | 3.93e+10 | 2561 | 1311232 | 0.42/0.63/0.08/0.78/0.05 |
| 256 | 0.63 s | 23 ms | 7.04 MB | 4.12e+10 | 2446 | 1311744 | 0.10/0.20/0.03/0.11/0.02 |
| 512 | 1.15 s | 25 ms | 7.31 MB | 4.47e+10 | 2250 | 1311744 | 0.21/0.33/0.05/0.24/0.02 |

