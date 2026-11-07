# m9-poseidon2-leaves receipts

Design, numbers and integration path: `design/riscv-proving-stack/rv64-m9-poseidon2-leaves.md`.

| file | content |
|---|---|
| `receipt.json` | source/binary/vector hashes, toolchain, GPU policy |
| `parity.log` | [M] GPU == Zig reference, 330/330 runs (165 cases x 2 variants) |
| `bench-single.jsonl` | [M] CUDA-event medians, Blake2s `mixed_leaf_kernel` vs P2 v1/v2, leaves and full tree |
| `chain-24628607-trees.jsonl` | [M] all 68 native trees of 24628607 (M6 geometry), prefix-bank chain, Blake eager vs P2 |
| `bench-gpu-state.txt` | GPU utilisation and memory at entry and exit of each locked hold |
| `model.json` | [D]/[E] `python3 -I scripts/rv64_m9/poseidon2_leaves_model.py` |

The golden vectors (17.7 MB) stay out of git. To regenerate them: `zig run -OReleaseFast src/core/m9_poseidon2_leaves_vectors.zig -- vectors.txt` (sha256 `7099daaa…0f9c`).
