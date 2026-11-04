# M6 hint-tape receipts (stream hint-tape, branch codex/rv64-m6-hint-tape)

All runs: resident daemon (`scripts/rv64_m4_resident.py daemon 26235156 24628607`), 2x RTX 5090, M5 default producer
config (`DEFAULT_PRODUCER_ENV`), library = M5 integrate image `0caf0144` unless noted, `--store fresh`. Trial 0 =
first request of each block in a fresh service (cold fold classes), trial 1 = warm. Single observations; **the pod was
not quiet** (1-min load 10-30, the protocol bar is 8): every timing is [M] but not quiet-host quotable. Byte identity:
`parity_vs_m3.byte_identical` (every native, bundle and recursive proof hash equal to the M3 integrate scale receipts,
which are the M5 default bytes) on every request of every run below.

| file | driver | what |
|---|---|---|
| `daemon-base-m5.json` (+`-prep`) | M5 integrate `37f94901` | baseline in the same harness |
| `daemon-tape-check-849b20c98.json` | `37f0c823` | `STWO_RV64_FOLD_SEED_TAPE=check`: 26/26 folds `check_ok` (replay recorder) |
| `daemon-tape-on-849b20c98.json` | `37f0c823` | tape on, builder-replay recorder (record 69 ms median: above the gate) |
| `daemon-tape2-check-8cd7cd02b.json` | `ce462796` | check mode, direct emitter: 26/26 folds `check_ok` |
| `daemon-tape2-on-8cd7cd02b.json` | `ce462796` | **tape on (default), direct emitter**; fresh receiver (M5 `0babaf7e`) accepted both trial-0 proofs |

Warm (trial 1) comparison, base -> tape2-on [M]:

| block | request | recursion | DAG wall | fold host prep median | fold tail (after last leaf) | tail host prep sum |
|---|---:|---:|---:|---:|---:|---:|
| 24628607 | 28.10 -> 26.30 s | 18.87 -> 17.01 s | 18.61 -> 16.75 s | 0.403 -> 0.025 s | 4.81 -> 3.32 s | 1.51 -> 0.10 s |
| 26235156 | 18.78 -> 17.24 s | 11.94 -> 10.82 s | 11.73 -> 10.63 s | 0.385 -> 0.019 s | 2.98 -> 2.30 s | 1.18 -> 0.06 s |

Tape prep per fold (warm, 40 folds): median 23 ms = record 8.5 ms + plan/seed pack 12.9 ms + authority prep 0.4 ms.
Device assignment (GPU DAG) per fold unchanged: 16 ms stream; leaves 136 ms (the next item: chain runs).
Cold classes (trial 0) do not use the tape (first fold of a class builds the template) and are unchanged.

`*-prep.json` = `scripts/rv64_m6_hint_tape_prep.py RUN` (per-node pipeline.json census + FOLD_SEED_TAPE log census).

## HT2: device DAG grouping (chain runs) [M]

`assignment-ab-narrow-vs-chain.json` (GPU_OUTER_ASSIGNMENT_TIMING medians over 52 leaf / 56 fold nodes per run):

| variant (run) | leaf DAG stream | leaf launches | fold DAG stream | fold launches | leaf assignment total |
|---|---:|---:|---:|---:|---:|
| M5 narrow runs (tape2-on) | 136.1 ms | 6,303 | 16.0 ms | 2,108 | 170.6 ms |
| chain v1 (chain1-on) | 133.3 ms | 596 | 14.5 ms | 689 | 180.4 ms |
| chain v2 + record pipeline + L2 prefetch (chain2-on) | 133.2 ms | 596 | 14.6 ms | 689 | 168.2 ms |
| chain v3 + 16-byte value access + vector wide levels (chain4-on) | **113.0 ms** | 596 | **11.7 ms** | 689 | **153.6 ms** |

Every run: all proofs byte-identical to the M5 default, fresh M5 receiver accepted. `level-census.json`: a 24628607
leaf plan has ~146 k levels = 101 k Blake-G levels (mean width 26) + 30 k mul levels (width ~150) + 14 k other + 10
inverse, plus 579 levels wider than 2048 (6.2 M tasks); no width-1 levels. Kill rule (fill > 1.5x today's assignment
device time): not triggered at any step (0.83x leaf, 0.73x fold for v3). ncu is not usable in the pod container
(`ERR_NVGPUCTRPERM`), so each latency hypothesis was tested by a variant: record loads and old-input DRAM latency are
not the bound (v2 unchanged); memory transactions per warp instruction are (v3 -15/-20%).
