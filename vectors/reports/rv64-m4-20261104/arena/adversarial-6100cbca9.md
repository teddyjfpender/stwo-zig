# Adversarial re-verification of codex/rv64-m4-arena @ 6100cbca9 [M]

These results come from an independent rebuild: a fresh detached checkout of `6100cbca9`, with only the CUDA image rebuilt
(lib `0d49e793…`; the driver is `b28544a1` and the receiver is `7b823d49`, both unchanged). It ran on 2x5090 under the
GPU lock on 2026-11-04 between 13:43 and 13:59. Every run is a single observation on a shared host. The 1-minute load at
start is given per row.

**Parity.** For each run I computed the sha256 of every `proof/*.bin`, `bundle.json`, `recursion-om31/tree.json` and
`recursion-om31/*.proof`, and compared them name-by-name with the M3 integrate receipts
(`rv64-m3-20261104/integrate/scale/<block>.json`). The counts are 37 files for 26235156 and 55 for 24628607, with no
missing or extra files. **All 9 runs are byte-identical.** (The harness field `parity_vs_accepted_v7` is false here, and
it is also false in the M3 baseline receipts themselves, so it is not the comparator.)

| block | run | arena | load1 | request s | capture | setup | native | recursion | parity vs M3 | receiver |
|---|---|---|---:|---:|---:|---:|---:|---:|---|---|
| 26235156 | v-on1 | on | 51.1 | 34.46 | 2.53 | 8.82 | 4.94 | 17.94 | identical | accepted (43.7 s) |
| 26235156 | v-off1 | off | 61.6 | 37.51 | 2.69 | 8.66 | 5.54 | 20.40 | identical | - |
| 26235156 | v-on2 | on | 14.4 | 34.19 | 2.58 | 8.67 | 5.41 | 17.40 | identical | - |
| 24628607 | v-on1 | on | 29.9 | 49.72 | 3.44 | 13.01 | 7.77 | 25.32 | identical | accepted (64.9 s) |
| 24628607 | v-off1 | off | 17.3 | 50.76 | 3.39 | 12.65 | 7.21 | 27.23 | identical | - |
| 24628607 | v-on2 | on | 17.8 | 51.23 | 3.44 | 12.83 | 8.17 | 26.60 | identical | - |
| 26235156 | v-poison-a5 | on, poison 0xA5 | 20.4 | 35.18 | 2.54 | 8.85 | 5.29 | 18.31 | identical | - |
| 26235156 | v-poison-ff | on, poison 0xFF | 34.5 | 34.50 | 2.59 | 8.57 | 5.41 | 17.78 | identical | - |
| 24628607 | v-poison-a5 | on, poison 0xA5 | 22.0 | 52.63 | 3.28 | 12.96 | 7.66 | 28.47 | identical | - |

**Speed.** The stream claims no speedup, and this run agrees. On 24628607 the arena runs took 49.7 and 51.2 s against
50.8 s with the arena off, so there is no measurable delta. On 26235156 they took 34.5 and 34.2 s against 37.5 s off, but
the off run started at load 61.6, so I do not claim that difference either. The counters reproduce exactly: with the
arena on there are 0 pool mallocs, 0 trims and 0 OOM recoveries. With it off, 24628607 has 14,619 pool mallocs (the same
number the stream reported) and 26235156 has 9,329. In every arena run allocations equal releases per device,
`fence_records=0`, and map+unmap is 0.3-0.8 s per device.

**Poison** (`STWO_RV64_DEVICE_ARENA_POISON=<byte>`, test only, added in this commit). Every arena allocation is filled
synchronously before it is returned, and every freed range is filled before it can be reused: 3.1-4.9 TB of fills per
run, 10-16k allocations and the same number of frees. The proofs stay byte-identical to M3 on both blocks with 0xA5, and
on 26235156 with 0xFF too. So no arena-managed buffer is read before it is written or after it is freed in a way that
reaches a proof. This does not cover the pool path used under graph capture or `cudaMallocAsync` in `rv64/trace.cu`,
which bypass the arena.
