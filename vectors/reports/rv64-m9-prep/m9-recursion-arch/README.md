# m9-recursion-arch receipts

Doc: `design/riscv-proving-stack/rv64-m9-recursion-arch.md`. Labels: M measured, D derived, E estimate.

| file | label | produced by | sha256 |
|---|---|---|---|
| `census.jsonl` | M | `zig build test-riscv64-m9-recursion-census -Doptimize=ReleaseSafe` (lines `M9_RECURSION_CENSUS ...`, prefix stripped). Host: Apple M-series, CPU only, memguard --gb 6; 16.3 s, 1.10 GB max RSS. Production rows equal the unmodified `V.verify` (6 cases, `production_match`). | 662de9b38c426e0fec4227492667e194fdab3bff21ff0827736bacec5baa70af |
| `model.json` | D on M | `python3 -I scripts/rv64_m9/recursion_arch_model.py --out ...` | bd4a03bfb1e9f67ca04e2d03ef2de067ebf90a3354c6c29b5f4baedeb293c015 |
| `plan_model.json` | E | `python3 -I scripts/rv64_m9/plan_model.py --gas-sample gas_sample.json --json ...` | 18a009b64d6958a94b5e1413d79fa68f47e23b1c2144c560e52fbae3174dc4eb |

The gas sample stays out of git: `gas_sample.json` sha256 52578c5a916ade03414e899517ae21b0d52c26e0e52b2135fc2e567f30f05544 (2,900 rows, the m9-plan input).

census.jsonl schema: one line per (child, variant). `phases` maps each phase to [eq, qm31_ops, triple_xor, m31_to_u32, blake_g_gate, unpadded cells] rows; `total` uses the same layout; `batch` = sibling circuits per proof (divide by it for per-child rows). The first line holds the gadget costs (G rows per Blake2s compression; Merkle node rows for Blake2s and Blake3).
