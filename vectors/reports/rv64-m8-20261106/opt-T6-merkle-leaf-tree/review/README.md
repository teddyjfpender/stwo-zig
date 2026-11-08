# T6 review (3217c7608, 33432900e)

Pod `rv64-resident-2x5090`, GPU 1, CUDA 12.8, production flags (`-O3 -std=c++17 -lineinfo -arch=sm_120`). Timing comes from the receipt's `merkle_fused_bench.cu`: CUDA events, a warm-up, the same leaves for both arms, loop and fused interleaved per rep, 9 reps, median ms. Variants are separate binaries, run in alternating rounds (r1: 2 rounds, r2–r4: 3 rounds). The raw lines are in `bench-r{1..4}.txt`. Scratch: `/workspace/m3/runs/m8-T6-review/`.

## Findings and dispositions

| # | Finding | Verified | Fix |
|---|---|---|---|
| 1 | The subtree and tail kernels used their own Blake2s node hash (`fused_compress`/`fused_children`/`node_init`/`node_bytes` over `progressive_compress`), a second copy of `hash_children_for`. | [M r2] With `hash_children_for` there are the same 64 registers and no spills, and the time is equal within noise (2^10 / 2^20 / 2^24: 0.0134 / 0.0725 / 0.8282 vs 0.0136 / 0.0723 / 0.8295). | Use `hash_children_for` and delete the copy. |
| 2 | `subtree_levels_kernel<_, 1>` (2 kernels) can never run. With a power-of-two `kFusedTailNodes`, every pass is 3 levels, plus at most one 2-level pass. | By derivation: `nodes > T` and `nodes` a power of two give `nodes >> 2 >= T/2`. | Use `levels = 3` or `2`, plus `static_assert` that the tail is a power of two. There are now 6 new kernels, not 8. |
| 3 | `kFusedTailBlock = 1024` had no A/B, against the "every tuning constant" rule. | [M r2] 256 / 512 / 1024 are within noise at every size. | Keep 1024, add the A/B to the comment, and use the `STWO_T6_TAIL_BLOCK` hook next to the other two. |
| 4 | It was unclear why `fused_tail_kernel` duplicates the frozen `upper_tail_kernel`. | [M r1, r3] `upper_tail_kernel` is about 2 µs slower as the tail, at 256 and 1024 threads alike. The cause is direct global `Hash` indexing (scalar loads): the same kernel body with direct indexing is just as slow (2^10 0.0136 → 0.0157 ms). | Keep the kernel, and document the reason and the numbers at `load_hash` and at the constants. |
| 5 | The mode-0 path re-implemented the callers' loop by launching `child_layer_kernel` directly. | It is the same kernels, but duplicated code. | It now calls `stwo_blake2s_layer_on_impl<Prefixed>` per layer, so mode 0 is the callers' loop by construction. This is host-only. |
| 6 | The tuning `-D` hooks were split across `.cu` and `.cuh`. | — | Moved them together into `merkle_fused.cuh`. |

## Checked and not a defect

- **Races and ordering.** Subtree writes are disjoint per thread. The tail's `__syncthreads` loop is uniform across the block, and its global writes are visible within the block after the barrier. All launches are on the caller's stream.
- **Reads.** The tail never reads past the previous layer. There are no uninitialised reads: every read is the leaves or a layer written earlier on the same stream.
- **Alignment.** `Hash` is `alignas(32)`, and the frozen kernels already rely on it.
- **Smallest and largest sizes.** Leaves = 2 gives one tail thread. All offsets are 64-bit. The 2^31 index math is 32-bit safe. The capacity check rejects anything short of `2 * leaves - 1` nodes.
- **Errors.** `cudaPeekAtLastError` surfaces an earlier failed launch in the pass.
- **Measurement validity.** The receipt uses events, a warm-up and interleaved arms, which is valid. Note that at 2^10–2^14 the event span includes the gaps while the host enqueues the launches (24 vs 6 launches). That is real cost for the eager-enqueue callers, but it is not pure kernel time.

## Verification of the fix [M]

- **Parity:** `parity-final.jsonl` passes 55/55: leaves 2^1..2^22, both protocols, mode 0 and mode 1 against the callers' `stwo_blake2s_layer_on` loop, with guard hashes, plus the 11 contract cases.
- **SASS:** the 8 frozen kernels (`child_layer`, `fri_leaf`, `interior4`, `upper_tail` × 2 protocols) are identical in the original T6 object, the fixed object and the frozen `m7-integrate/cuda/native/commitment-merkle.cu.o`.
- **Time (r4, fused, orig → fixed):** 2^10 0.0137 → 0.0136, 2^14 0.0303 → 0.0304, 2^20 0.0723 → 0.0725, 2^22 0.2268 → 0.2272, 2^24 0.8302 → 0.8281. This is no change. The loop arm is unchanged (2^24 1.0464 / 1.0448).
