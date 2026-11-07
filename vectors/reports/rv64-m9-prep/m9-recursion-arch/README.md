# m9-recursion-arch receipts

Doc: `design/riscv-proving-stack/rv64-m9-recursion-arch.md`. Labels: M measured, D derived, E estimate.

| file | label | produced by | sha256 |
|---|---|---|---|
| `census.jsonl` | M | `zig build test-riscv64-m9-recursion-census -Doptimize=ReleaseSafe` (lines `M9_RECURSION_CENSUS ...`, prefix stripped). Host: Apple M-series, CPU only, memguard --gb 6; 19.4 s, 1.08 GB max RSS. Production rows equal the unmodified `V.verify` (6 cases, `production_match`). Review r1: batch rows open one FIXED tree per circuit; `*_sharedfixed` rows are references that reproduce the first draft. | 8be9f71fc6ade7748c9422d4e61e07307a040f669fc703e9d3745d2d41b3c67d |
| `model.json` | D on M | `python3 -I scripts/rv64_m9/recursion_arch_model.py --out ...` | 74e8fe74b712f52eca6462345e3c80dabe8a31911172b5e3347262558d6fdcec |
| `plan_model.json` | E | `python3 -I scripts/rv64_m9/plan_model.py --gas-sample gas_sample.json --json ...` | 4b167253dcc361bb1d9abad2d8e72c8a16ab51da7408d733b7fdc26d4be9aff4 |

The gas sample stays out of git: `gas_sample.json` sha256 52578c5a916ade03414e899517ae21b0d52c26e0e52b2135fc2e567f30f05544 (2,900 rows, the m9-plan input).

census.jsonl schema: one line per (child, variant). `phases` maps each phase to [eq, qm31_ops, triple_xor, m31_to_u32, blake_g_gate, unpadded cells] rows; `total` uses the same layout; `batch` = sibling circuits per proof (divide by it for per-child rows); `batch_shared_fixed` = one shared FIXED tree (reference only, not admissible). The first line holds the gadget costs (G rows per Blake2s compression; Merkle node rows for Blake2s and Blake3).
