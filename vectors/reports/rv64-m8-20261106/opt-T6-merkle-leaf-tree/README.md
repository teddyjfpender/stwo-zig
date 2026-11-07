# T6 Merkle leaf + tree (M8 optimisation round 2)

Branch `codex/rv64-m8-opt-T6-merkle-leaf-tree`, cut from `c72b51646`. Claimed files: `src/backends/cuda/native/commitment/{progressive.cu,merkle.cu,blake2s_protocol.cuh}`, plus one new header, `merkle_fused.cuh`. The harness `merkle_fused_bench.cu` lives in this directory, outside `native/`, so the CuMetal closure ledger is untouched.
Only `merkle.cu` changed in the end; `progressive.cu` and `blake2s_protocol.cuh` are untouched (see "Leaf kernel" below).
Flag: `STWO_RV64_M8_MERKLE_FUSED` (unset or `0` = established kernels, `1` = T6 kernels, any other value fails closed with `cudaErrorInvalidValue`).

All numbers come from an RTX 5090 (GPU 1 of the pod), CUDA 12.8, production nvcc flags (`-O3 -std=c++17 -lineinfo sm_120`), with CUDA events around the extern "C" entry points. Arms are interleaved per rep; we report the median, with [min, max]. Sources and build line are in `merkle_fused_bench.cu`.
The orphan pid 3302210 held 30 GB idle on each GPU during all runs. It ran no kernels, but it is why the benchmark shapes stay at or below about 1.9 GB.

## 1. Fused tree layers: new entry point, bit-identical, 0.48-0.81x [M]

There is a new entry point beside the old ones; no existing signature changes:

```
int stwo_blake2s_merkle_layers_on      (Hash *tree, uint32_t leaves, uint64_t tree_capacity_nodes, void *stream);
int stwo_blake2s_merkle_layers_plain_on(...same...);
```

It builds every layer above the leaves of a contiguous tree. Layer 0 is `tree[0..leaves)`, each next layer follows the previous one, and the root lands at `tree[2*leaves-2]`. This is exactly the layout and the result of the loop that all callers run today: `pcs_enqueue.cu:856`, `pcs_pipeline.cuh:772`, `trace.cu:220`, `fri.cu:94` and `trace_commit.zig`. With the flag off, the entry point runs that same `child_layer_kernel` loop. With the flag on:
- `subtree_levels_kernel<L>` (L = 3, or 2 for one pass): each thread owns 2^L consecutive nodes and writes the L layers above them from registers. Every compression slot is used, and the input layer is read once instead of once per layer.
- Layers of ≤ 2048 nodes are built by one 1024-thread CTA (`fused_tail_kernel`).
- A 2^24-leaf tree needs 6 launches instead of 24.

**Parity [M]** (`kernel-parity.jsonl`): 55/55 cases pass. Leaves 2^1..2^22 for both protocols are byte-identical to the callers' `stwo_blake2s_layer_on` loop for mode 0 and mode 1; the whole buffer is compared, including 2 guard hashes past the root. 11 contract cases also pass: non-power-of-two input, fewer than 2 leaves, short capacity, null tree or stream, and an invalid flag all return `cudaErrorInvalidValue`.

**SASS [M]** (`sass-diff.txt`): all 8 kernels of the frozen `m7-integrate/cuda/native/commitment-merkle.cu.o` are SASS-identical in the T6 object. The only additions are the new kernels (6 after the review, `review/`) and the 3 new host entry points (`merkle_layers_on`, `merkle_layers_plain_on`, `m8_merkle_fused_override`). The default path therefore runs exactly the frozen device code.

**A/B [M]** (`kernel-bench.jsonl`, 9 reps, ms):

| leaves | callers' loop | fused | ratio |
|---|---|---|---|
| 2^10 | 0.0279 [0.0268, 0.0319] | 0.0137 [0.0128, 0.0159] | 0.491 |
| 2^14 | 0.0441 [0.0432, 0.0478] | 0.0301 [0.0289, 0.0346] | 0.683 |
| 2^18 | 0.0672 [0.0659, 0.0701] | 0.0395 [0.0389, 0.0407] | 0.588 |
| 2^20 | 0.1040 [0.1016, 0.1072] | 0.0723 [0.0715, 0.0724] | 0.695 |
| 2^22 | 0.2774 [0.2744, 0.2806] | 0.2255 [0.2230, 0.2272] | 0.813 |
| 2^23 | 0.5292 [0.5254, 0.5369] | 0.4281 [0.4272, 0.4323] | 0.809 |
| 2^24 | 1.0467 [1.0427, 1.0532] | 0.8307 [0.8268, 0.8370] | 0.794 |

At 2^24 the fused path (0.83 ms) is near its floor. The compression floor is about 0.65 ms [D]: 2^24 compressions at about 26 G/s (see section 2). The byte floor is about 0.60 ms [D].

Tuning A/Bs are in `tune-1-tail-nodes.txt` (tail of 1024, 2048, 4096 or 8192 nodes) and `tune-2-subtree-block.txt` (64, 128 or 256 threads). The chosen values and their numbers are in the comment above the constants in `merkle.cu`.

**Request level [D/E].** `child_layer_kernel` takes 0.181 GPU-s over 7,849 launches per warm 24628607 request (census2). Adoption would save about −0.03 to −0.06 GPU-s and about 5,800 launches [E]. This applies **only after callers switch** their loop to the new entry point. That switch is a 1-line change in files T6 does not own (see "Adoption" below). Until then the default and GPU-native paths are unchanged.

## 2. Leaf kernel: already at its roofline, so the narrow-width rewrite is rejected [M]

The census reading "0.55–0.80 TB/s at 8–16 columns" counted **input bytes only**. If you include the 32 B hash write per row, and on the production chain the seed and prefix state, the established `mixed_leaf_kernel` is at the hardware ceiling (`kernel-bench.jsonl`, leaf/eager roofline rows):
- **Eager chain steps** (the production shape, 2^27-word chunks): 1.41–1.60 TB/s of all bytes moved. At 8 columns with pending 8 → 0 it reaches 1.578 TB/s; at 32 columns, 1.601 TB/s. HBM peak is about 1.79 TB/s. **This is memory-bound.**
- **Wide leaves:** 21–26 G compressions/s. The SASS of one compression is 320 IADD3 + 320 LOP3 + 320 SHF, which is the minimum of 12 integer operations per G × 80. On this part (170 SMs at 64 INT32/clk) that caps at about 26 G/s [D]. **This is INT-pipe-bound.**
- **Rejected variant:** batched loads, issuing up to 16 − pending independent loads per step and then one uniform placement switch, plus array-state compression. It was bit-identical: 1050/1050 parity cases (`rejected-batched-leaf-parity.jsonl`) over widths 1–200, padded strides, lifted segments, and classic, plain, eager and compact chains. But it was **1.05–1.92x slower** at every shape (`rejected-batched-leaf-bench.jsonl`). It was removed, and `progressive.cu` is unchanged.

## 3. The real leaf lever: stream chunk width (an env knob, proof-invariant) [M kernel, D request]

Per row, an eager chain step moves the seed state (8 + pending words) in and the prefix state (8 + pending') out, plus the columns of the call. With the default 2^27-word chunk, a 2^24-row height gets **8 columns per call**, so state round trips are about 75% of the bytes. `chain_chunk` rows in `kernel-bench.jsonl` show one 64-column eager chain at 2^21 rows. The per-row traffic is the same as 2^24 rows with chunk/8. Leaves are byte-identical for every split:

| columns per call | ms per column | vs 8 |
|---|---|---|
| 4 | 0.0439 | 2.05x |
| **8 (today at 2^24 rows)** | **0.0214** | 1 |
| 16 (2^28-word chunk) | 0.0122 | **0.57x** |
| 32 (2^29) | 0.0077 | 0.36x |
| 64 | 0.0059 | 0.28x |

Compact eager (`STWO_RV64_COMPACT_EAGER_STATE=1`) is the same speed to within 0.3%. Its benefit is bank memory, not time.

**Projection [D]** for a warm 24628607 request (census2 mixed_leaf grids). The 2^24-row launches take 0.696 GPU-s at 8 columns per call; scaled by 0.57x that is about −0.30. The 2^23-row launches take 0.440 GPU-s at 16 columns per call; scaled by 0.63x (32 columns) that is about −0.16. Total: **≈ −0.46 GPU-s** for `STWO_RV64_PCS_STREAM_CHUNK_WORDS=268435456` plus `STWO_RV64_TRACE_STREAM_CHUNK_WORDS=268435456`. Caveat: this assumes those grids are chain steps at their tallest height.
- **Cost:** +512 MiB on the PCS stream scratch. The TC chunk is already shrunk by its admission logic when leases are live (`trace_commit.zig`).
- **Proofs:** both knobs are documented as proof-invariant (`vectors/reports/rv64-m3-20261104/mem/README.md`). The canonical runner re-checks payload SHA-256 across arms anyway.
- **Paths:** both the default path (`pcs_pipeline.cuh`) and the GPU-native path (`jobs/pcs_enqueue.cu`) read `pcsStreamBudget()`.

The request-level 3+3 (`ab-chunk-preset.json`) is queued on the pod. Its arms are identical except for the two chunk knobs. As in T5, the runner gives the process-budget guard to the fullstack arm only, which biases the result against the knob.

## Adoption (for the GPU-native integrator / legacy owners; T6 does not edit these files)

Replace the layer loop after the final leaf call with:
```
CHECK(stwo_blake2s_merkle_layers_on(reinterpret_cast<b::Hash*>(hashes), p.leaves, uint64_t(2) * p.leaves - 1, stream_raw));
```
The call sites are `jobs/pcs_enqueue.cu:855-860`, `pcs_pipeline.cuh:771-776`, `trace.cu:219-225`, `fri.cu:93-101`, and `trace_commit.zig` (its `Layer` loop). The result is byte-identical with the flag on or off.

## Status
- Kernel work, parity and microbenchmarks are complete [M].
- **Not landed.** Landing needs `rv64_gate.sh` PASS on a T6 image, which means relinking the frozen line with `commitment-merkle.cu.o` replaced. Two things block it:
  1. the orphan pid 3302210 holds 30 GB per GPU, so `GpuPcsInitializationFailed` happens before any proof (the same blocker as T2–T5);
  2. the pod disk has 2.2 GB free and a T6 image is 1.9 GB.
- `pipe1.sh` (pod, tmux `t6-pipe1`) waits for both GPUs below 2 GB and ≥ 5 GB of free disk. It then builds the image, gates 26235156 and 24628607 (default path), and runs the chunk 3+3. Status is in `/workspace/m3/runs/m8-opt-T6-merkle-leaf-tree/pipe1.status`.
