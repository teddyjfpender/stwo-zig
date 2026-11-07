# RV64 M9 prep: streaming commit (fused LDE → leaf hash)

Status: prototype + standalone evidence, 2026-11-07. Branch `codex/rv64-m9-stream-commit` (cut from
`codex/rv64-m7-integrate`). Flag `STWO_RV64_M9_STREAM_COMMIT` (default off; nothing in the prover calls
the new entry points). Lever #3 of `rv64-m9-plan.md` rev 3 §4.1: "FFT + Merkle 53% of GPU-s [M]; ×0.70 on
it [E]" (`plan_model.py` `'stream': (0.80, 0.70, 0.60)`).

Labels: **[M]** measured (CUDA events, RTX 5090, standalone, pod `rv64-resident-2x5090`), **[D]** derived
from measured values or exact geometry, **[E]** estimate.

## 0. Verdict

**The ×0.70 [E] factor is wrong for the fused design at the heights that matter.** The fused kernel is byte-identical (22/22 parity cases at logs 15–24, 0 mismatching words over every leaf/level-k node, root, opened value and path word; the negative control fails) [M]. But at log 22–24, where the recursion trees and native segments live, it is a **net loss of ×1.03–1.61 [M]**:

- At those heights, W2 needs a 2^(log−11)-row tile. That forces either a cross-CTA exchange (cluster DSMEM) or a taller, narrow-lane W1. Each costs more than the W2 write plus the leaf re-read it removes.
- Where no exchange is needed (log ≤ 21) it wins, but only by ×0.92–0.95 on LDE + leaves [M].

Two by-products of the same prototype are real and byte-identical:

1. **Block-aligned, larger chunks** are a planner-only change with today's kernels. The eager prefix banks, not the LDE, dominate the leaf pass: 24 words/row when a call ends mid-block, 8 when it ends on a 16-column boundary.
   - Log-24 × 304-column tree commit [M]: chunk 8 (2^27 words) 108.8 ms; chunk 16 unaligned 92.9; chunk 16 aligned 83.8; chunk 32 aligned **75.4 ms**.
   - That is −31% against 2^27, and −19% against the fullstack 2^28 setting when unaligned.
   - Streamed-commit scratch [D]: 3.50 GiB (chunk 2^27 + 2 × 24-word banks) → 1.50 GiB (aligned, same chunk), or 3.00 GiB with the 32-column chunk.
2. **Partial (leafless) trees**: the CTA hashes its 1,024 leaves up to k = 10 levels on chip.
   - Merkle layers on a log-24 tree drop from 1.03 to 0.05 ms [M].
   - The persistent tree drops from 1 GiB to 1 MiB [D].
   - Queried values and the bottom-10 siblings are emitted by the same pass, byte-identical to `open_values` + `open_paths` [M].

**Recommended model change** (`plan_model.py` `'stream'`): replace (0.80, 0.70, 0.60) with **(0.92, 0.86, 0.75) [E]**, re-labelled "aligned stream chunks + partial trees (+ fused N2B tail at log ≤ 21)":

- Central 0.86 = −0.6 of 4.41 GPU-s on 24628607 [E]: aligned 32-column chunks −0.41 (leaf 36.9 → 19.5 ms/304 columns, applied to an assumed 70% streamed share of `mixed_leaf` 1.25 GPU-s); partial trees −0.15 (`child_layer` 0.18); fused log ≤ 21 −0.03.
- The optimistic 0.75 assumes the cluster exchange is made nearly free (§3): then the fused kernel runs at its measured single-CTA rate at log 24 as well.
- This weakens the 60% case of `rv64-m9-plan.md` §4.3: streaming commit at ×0.60 was one of the three single-notch routes to 60%, and it is now out of reach.

## 1. What was built

| file | content |
|---|---|
| `src/backends/cuda/native/commitment/stream_commit.cuh` | fused kernel `stream_commit_kernel<Low>`: last `Low` N2B stages on chip + eager Blake2s absorption, optional on-chip subtree (k ≤ 10 levels), queried values and bottom-k path siblings |
| `src/backends/cuda/native/commitment/stream_commit.cu` | `stwo_m9_lde_first_pass_split_on` (W1 only, production strided kernels at heights 5..11, plus a relaxed copy for heights 12..14), `stwo_m9_stream_commit_on`, `stwo_m9_stream_commit_upper_paths_on`, `stwo_m9_stream_commit_enabled` (flag), occupancy probe |
| `src/backends/cuda/native/commitment/bench/stream_commit_bench.cu` | parity (every leaf/node, root, opened value and path word vs the production pair) + interleaved CUDA-event A/B; negative control `SC_NEGATIVE=1` |

Production commit of one chunk is three HBM passes: W1 `n2b_wide_strided*` (coefficients → intermediate),
W2 `n2b_wide_contiguous` (intermediate → LDE), L `mixed_leaf_kernel<true,true>` (LDE + eager SoA prefix
bank → prefix bank / leaves). The prototype keeps W1 and replaces W2 + L by one kernel that never writes
the LDE.

### Kernel design (and the two designs that failed first)

A W2 tile is 2^13 consecutive rows at log 24, but a leaf state is one row across all columns, so one CTA
would have to hold 8192 Blake2s states. The kernel uses one thread per row (1024 rows/CTA) and, for
`Low > 10`, a thread-block cluster of 2^(Low−10) CTAs: the `Low−10` cross-CTA stages run on a column slice
in registers and are exchanged through distributed shared memory (split `barrier.cluster` arrive/wait).

- **v1 (thread = row for FFT and hash, warp shuffles for 10 stages)** — byte-identical first try, but
  1.5–2.6× *slower* than W2 + L [M] (`bench1`): shuffle butterflies cost ~17 instr/element/stage vs ~6.5
  register-blocked, and one CTA/SM serialises every load behind barriers.
- **v2 (+ cp.async staging ring, smem twiddle cache, 2–4 columns per barrier)** — still 1.3–1.6× slower [M].
- **v3 (current)**: groups of 16 columns = one Blake2s block. Phase A: each column's 1024 rows are a
  register-blocked FFT on 64 threads × 16 values (bits 9..6, smem transpose, bits 5..2, two shuffle stages
  for bits 1..0); finished values go to a [16][1024] smem buffer. Phase B: thread = row absorbs 16 words
  (one compress). Groups end on block boundaries (the first group tops up the seed's pending words, re-read
  from the seed), so only h0..h7 are live across the FFT phase.

Bit identity: twiddles and stage indexing are exactly `n2b_wide_stages` (stage s pairs bit log_n−s, circle
stage last), and absorption is exactly the eager convention of `mixed_leaf_kernel<true,true>` (a full
block followed by more words is compressed early — the same compression with the same counter).

## 2. Measurements [M] (receipts `vectors/reports/rv64-m9-prep/stream-commit/`)

RTX 5090 (GPU 0, idle, `gpu.lock`, foreign compute apps = 0 checked before every hold). CUDA events, median of 3–5 interleaved reps. Random M31 coefficients (blowup 2, every 5th column zero-extended from log−3) and twiddles; both arms run identical arithmetic. REF = `stwo_lde_n2b_columns_on` + `stwo_blake2s_mixed_seeded_eager_compact_on` per chunk + `stwo_blake2s_layer_on`, i.e. the streamed path of `pcs_enqueue.cu`/`outer_trace_commit.zig`. `final1.log`:

| shape (log × cols, chunk) | REF total ms (LDE / leaf / layers) | FUSED total ms (W1 / fused / layers) | ratio |
|---|---|---|---:|
| 24 × 304, chunk 8 (2^27) | 108.8 (55.2 / 52.4 / 1.04) | 132.1 (50.7 / 80.1 / 1.03), Low 11 | 1.21 |
| 24 × 304, chunk 16, 7 lower-height cols first (unaligned) | 92.9 (54.3 / 36.9 / 1.02) | 118.0 | 1.27 |
| 24 × 304, chunk 16 aligned | 83.8 (54.6 / 28.1 / 1.03) | 106.5 (49.2 / 56.2 / 1.03), Low 11 | 1.27 |
| same, Low 13 (cluster 8, production W1) | 83.3 | 134.0 (26.7 / 106.1 / 1.03) | 1.61 |
| same, Low 10 (W1 height 14, 1-word lanes) | 83.4 | 117.0 (80.8 / 34.9 / 1.02) | 1.40 |
| same, k = 10 + 108 queries | 84.0 | 106.7 (layers 0.05) | 1.27 |
| 24 × 304, chunk 32 aligned | **75.4** (54.8 / 19.5 / 1.03) | 100.5 | 1.33 |
| 24 × 16 / 45 / 114, chunk 16 | 5.20 / 13.16 / 32.26 | 6.51 / 16.75 / 41.95 | 1.25 / 1.27 / 1.30 |
| 23 × 16, chunk 16, Low 10 | 2.504 | 2.638 | 1.05 |
| 22 × 32, Low 10 | 1.961 | 2.022 | 1.03 |
| 21 × 32 | 1.016 (0.620 / 0.242 / 0.147) | 0.960 (0.369 / 0.436 / 0.147) | **0.94** |
| 20 × 32 | 0.534 | 0.498 | **0.93** |
| 19 / 18 / 16 × 32 | 0.272 / 0.173 / 0.095 | 0.299 / 0.179 / 0.107 | 1.10 / 1.03 / 1.12 |
| 18 / 16 × 32, k = 10 + 108 queries | 0.168 / 0.097 | 0.150 / 0.080 | 0.89 / 0.83 |

Where the time goes [D]:
- **Single-CTA fused kernel** (Low 10): 34.9 ms for 304 × 2^24 rows, against W2 + leaf = 28.1 + 19.5 = 47.6 ms at the best aligned reference. That is **×0.73 of the pair it replaces**, but it needs W1 at height 14, which costs 80.8 against 26.7 ms.
- **Cluster variants** with the production W1: the exchange costs 1.6× (C = 2) to 3× (C = 8) the single-CTA rate. Occupancy is not the cause: 170 / 164 / 152 of 170 SMs co-resident for clusters of 2 / 4 / 8 [M, `split1.log`]. The cost is the DSMEM scatter plus two cluster barriers per 16-column group, and 128 B of register spill.
- **v1 history** (`v1-shuffle-bench.log`): thread = row with 10 shuffle stages ran 1.5–2.6× slower than REF. The cause was instruction count (~17 instr/element/stage), not memory traffic.

## 3. What would make the fused kernel pay at log 22–24 (not done)

- **A cheaper cross-CTA exchange.** The required budget is the single-CTA rate (6.8 ps/element). Options:
  - TMA multicast of the W1 output slice into every cluster rank, instead of register cross stages plus a DSMEM scatter;
  - one cluster barrier per two groups, with double-buffered exchange slots (smem is the limit: 74 KB of 99 KB used).
- **If the exchange becomes free:** log 24 would cost about W1 26.7 + 34.9 + 0.05 = 61.7 ms against 75.4 ms for aligned chunk 32. That is ×0.82 on the tree commit and the source of the optimistic 0.75.
- **The leaf pass here is already as cheap as the aligned bank traffic allows.** The fused kernel's remaining cost is the FFT tail and Blake2s compute, about 150 instructions per element.

## 4. Call sites in the GPU-native PCS path (read-only, `codex/rv64-m8-gpu` @ b289b021f)

| call site | today | replaced by |
|---|---|---|
| `src/backends/cuda/native/rv64/jobs/pcs_enqueue.cu` ~800–870 (rolling rebuild: `extend_columns` → `stwo_rv64_trace_open_values_on` → `stwo_blake2s_mixed_seeded_eager(_compact)_on` → layers → `open_paths`) | chunked LDE + eager banks + full tree in the dead bank | (a) block-aligned plan (`trace_stream_plan`); (b) final call with k = 10 nodes + values + bottom paths (`stwo_m9_stream_commit_on`) + `upper_paths`; (c) the fused tail only for chunks at log ≤ 21 |
| `src/integrations/riscv_cuda/rv64/jobs/outer_trace_commit.zig` `enqueueStreamed` (recursion trace commit, root only) | same chunk/bank schedule | (a) aligned plan; (b) k = 10 partial tree (only the root survives anyway) |
| `jobs/pcs_enqueue.cu` 572–620 (non-rolling `extend_source` + `stwo_rv64_trace_tree_on`) and `jobs/native_commit.zig` `enqueueInto` / `native_composition.zig` (materialised full LDE + `stwo_rv64_trace_tree_on`) | full LDE (e.g. 304 × 2^24 × 4 B = 19 GiB per tree [D]) + 1 GiB tree | the streamed schedule with an aligned plan: −(LDE − chunk − 1 GiB banks) per tree, roots unchanged. The fused kernel matters only where heights ≤ 21 dominate |
| `extend_combined` (DEEP) / `fri_tree_on` | not a trace commit | untouched |

## 5. Integration after GPU-native lands

1. **Aligned stream plan** (no new kernel, byte-identical roots).
   - In `trace_stream_plan.{zig,h}`, cut calls only where the absorbed word count ≡ 0 (mod 16), and size banks at 8 + (absorbed & 15) words per row (planes already supported by `stwo_blake2s_mixed_seeded_eager_compact_on`).
   - Raise the chunk to 32 full-height columns where the node budget allows: 3.0 GiB against 3.5 GiB today [D].
   - Flag `STWO_RV64_M9_STREAM_COMMIT=1` selects the aligned plan; the gate is node dump parity on roots.
2. **Partial trees in the final call.**
   - Route the last call of each streamed tree through `stwo_m9_stream_commit_on` with `subtree_levels = 10`, `query_rows` = the lifted queries, `values` = `t.values` (same `[column][query]` layout as `open_values`) and `paths` = `t.paths`.
   - Upper levels come from `stwo_blake2s_layer_on` on the 2^(log−10) nodes, then `stwo_m9_stream_commit_upper_paths_on`.
   - Lower-height groups keep the existing native-height prefix chain; the fused call takes their eager prefix as a lifted seed (tested in parity).
   - Gate: byte-identical proofs on 24628607 and 26235156 (rv64_gate) with fresh receivers.
3. **Fused N2B tail** only for full-height chunks at log ≤ 21 (`stwo_m9_stream_commit_low_bits(log) == 10` and production W1). Keep W2 + leaf above that until the §3 exchange lands and is measured below 1.0.
4. Re-measure the kernel census (bench15 on the landed default) and replace the `'stream'` triple in `plan_model.py` with measured values.

Not covered: request-level timing (forbidden in this stream); real twiddles (random words exercise identical arithmetic); `Plain` (unprefixed) leaves, which this path does not use.
