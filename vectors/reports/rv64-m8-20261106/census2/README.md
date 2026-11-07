# census2: round-2 census and target selection

Branch `codex/rv64-m8-census2`, cut from `codex/rv64-m7-integrate @ c72b51646`, with `codex/rv64-m8-census1` merged in (its census tool and receipts).
Labels: [M] measured, [D] derived from measured values, [E] estimate.

## Status (read first)

- **The fresh nsys profiles are queued, not done.**
  - Orphan pid 3302210 (`m8-native-hybrid` combined-serve, PPID 1, cwd deleted) still holds 30.1 GB on each 5090.
    - It has held them since 19:27Z on 2026-11-06, 6 h 20 min at 01:49Z.
    - Every harness service fails PCS init, and five round-1 pipelines (T1–T5) are waiting on it.
    - census2 is not allowed to stop it.
  - tmux `census2-pipe` on the pod starts by itself once both GPUs are below 2 GB.
    - It profiles one cold+warm default-path service for each of 24628607, 26235156 and 26235159.
    - The assets are pinned to the integrate head: `runs/m8-bench15/assets-c72b51646.json`.
    - The harness takes `gpu.lock` itself. Trace: `cuda,nvtx,osrt` plus the graph-node trace.
  - After each block, the pipeline:
    - writes the `nsys stats` CSVs (`nvtx_gpu_proj_sum`, `cuda_gpu_kern_sum`, `cuda_api_sum`, `osrt_sum`, `cuda_gpu_mem_time_sum`, `cuda_gpu_mem_size_sum`);
    - writes the warm and cold analyses;
    - records the SHA-256 of the raw files, then deletes them.
  - Outputs: `/workspace/m3/runs/m8-census2/summary/`. Status: `/workspace/m3/runs/m8-census2/pipe.status`.
- **What this round adds now [M]:**
  - read-only deep queries on the retained M7-P1 default-path trace of a 24628607 warm request;
  - the same trace census1 used: `runs/m7-integrate/daemon-24628607-r2-p1-inter-contributions-profile-20261106-01-06-baseline`, sqlite sha256 `04573fd8…`;
  - the PCIe link state of the pod;
  - a code read of each candidate kernel.
- **Tooling.** `scripts/rv64_m8_census.py analyze` now attributes each large idle gap (`gap_cause`):
  - the last kernel before the gap and the first kernel after it;
  - the shortest host NVTX ranges that cover the whole gap, which is the host work the GPU waited on.
- Files:
  - `m7p1-24628607-warm-deep.json`: H2D by range, source kind and size; per-kernel duration buckets, grids and NVTX ranges;
  - `m7p1-24628607-warm-d2d.json`;
  - `h2d-api-and-pcie.txt`;
  - `deep_queries.py`.

## New findings (24628607 warm, M7-P1 default-path trace)

### F1: H2D is link-bound, and the link runs at x8 [M]
- **The link.** Both 5090s train PCIe Gen5 at **x8** (`pcie.link.width.current=8`, max 16).
- **The copies.** The warm request moves 28.39 GB H2D in 1.156 copy-s at 24.6 GB/s. That is close to the Gen5 x8 practical ceiling.
  - 100% of it is `cudaMemcpyAsync` with CUPTI srcKind = pageable, from 2 threads (one per device).
  - API CPU time is only 0.046 s in total, so these copies do not block the way pageable copies normally do.
  - The arena's pinned ring saw only 4.3 GB for the whole process (`GPU_STAGING_SUMMARY`). The bulk bypasses it.
  - **Pinning would not help: the link is the limit. Only moving fewer bytes helps.**
- **By NVTX range (GB):**

| range | GB |
|---|---:|
| `rv64/owner/callback` | 11.61 |
| `rv64/recursion/MAIN-assignment` | 7.49 |
| `rv64/composition` | 3.41 |
| `m7/pcs/metadata_allocations` | 1.86 |
| `TC/MAIN` | 1.59 |
| `TC/INTER` | 1.49 |
| `TC/FIXED` | 0.95 |

- 24.0 GB arrives in 32 MiB-class copies (log2 25).
- Residency (no re-upload in a warm request) belongs to the GPU-native streams (native witness, recursion seed fill, driver prefix upload). Handed to them; not a census2 target.

### F2: D2D is 167 GB per warm request, 0.214 copy-s at 782 GB/s [M]
- **By range (GB):**

| range | GB |
|---|---:|
| `TC/INTER` | 70.3 |
| `TC/MAIN` | 56.0 |
| `owner/callback` | 23.2 |
| `TC/FIXED` | 8.6 |
| `recursion/INTER-witness` | 8.4 |

- 102.8 GB of it is in 88 copies of ≥ 1 GiB.
- These are column/coset copies in trace commit.
- In-place coset switching would remove most of them [E −0.15 to −0.2 GPU-s]. The call sites are trace-commit code (native) and transform (T4), so this is handed to them.

### F3: kernel shapes behind the round-2 targets [M unless noted]

| kernel | GPU-s | launches | distribution | NVTX range |
|---|---:|---:|---|---|
| `blake2s::mixed_leaf_kernel` | 1.342 | 1,307 | p50 1.10 ms; 1.09 GPU-s in the 1–10 ms bucket; grids 65536 (0.70) and 32768 (0.44) | `pcs/openings` 0.79, `TC/INTER` 0.29, `TC/MAIN` 0.20 |
| `blake2s::child_layer_kernel` | 0.181 | 7,849 | 6,517 launches < 10 µs (launch-bound) | `openings` 0.09 |
| `rv64::batch_round` <<<1,1>>> | 0.153 | 2,250 | p50 70.8 µs, p90 94 µs: serial dependent loads over ≤ 128 oracles | `owner/callback` (native GKR) |
| `oracles_sum` / `oracles_fold` | 0.150 / 0.155 | 2,250 each | 1,953 sum launches < 100 µs; 1,836 fold launches < 10 µs | `owner/callback` |
| `rv64::global_inverse_contribute` | 0.388 | 392 | 17 launches ≥ 10 ms = 0.24 GPU-s; grid 425,984 = 2^22 rows × 13 pairs | `recursion/INTER-witness` 0.361 |
| `rv64::keccak_witness` | 0.343 | 6 | p50 53.6 ms, max 112.7 ms; grids 2428 / 1171 | `owner/callback` |
| `rv64::bridge::witness` | 0.118 | 103 | 4 launches ≥ 10 ms (0.102) at grid 512 = 2^16 rows | `owner/callback` |
| `circuit_base::generate<0>` | 0.297 | 304 | 51 launches 1–10 ms | `MAIN-assignment` 0.189, `INTER-witness` 0.108 |
| `circuit_outer::cumulative` | 0.078 | 209 | | `INTER-witness` |

**Byte models and code reads [D]:**
- **`keccak_witness`.**
  - Each lane writes its 64 bit-columns one 4-byte store at a time, to row `keccak_physical(logical)`, which is bit-reversed circle order.
  - So every store instruction touches 25 columns × 1 sector, and adjacent pairs land on far-apart physical rows.
  - About 2–4 GB written (1,923 columns × 2^19 rows × 4 B; 27–29 rows used per pair) takes 53.6 ms: **38–75 GB/s effective, against 1.79 TB/s peak.**
  - On top of that come about 10^4 global atomics per pair into the `chi` and `xor5` tables.
- **`bridge::witness`.**
  - About 73 `range8` atomics per row into **256 bins** (heavy contention) and 26 into `range16`, then 134 per-row column stores.
  - About 25 ms per 2^16 rows, which is about 380 ns per row.
- **`global_inverse_contribute`.**
  - One OM31 inversion per 32 rows, by lane 0, while 31 lanes idle.
  - 128 B per row-pair × 2^22 × 13 = 7.0 GB, which is about 4.7 ms at 1.5 TB/s. Measured: about 14 ms per launch (about 3×).
- **`batch_round`.**
  - One thread loops over up to 128 oracles. It makes 2 dependent global OM31 loads per oracle (at about 0.5 µs latency each), then the weighted multiplies.
  - Field addition is exact, so a parallel tree reduction is bit-identical.
- **`mixed_leaf`.**
  - census1 microbenchmark [M]: 1.43–1.50 TB/s at 64–128 columns, but 0.55–0.80 TB/s at 8–16 columns.
  - At 8 columns, each 32 B row needs one compression plus a 32 B hash write, so the kernel is compression- and latency-bound, not DRAM-bound.

## Targets (round 2): mutually disjoint, outside the GPU-native and T1–T5 files

None of these files has a claim in `M8-INTERFACES.md`. None has been touched on any `codex/rv64-m8-gpu*` or `opt-T*` branch since c72b51646 (`git diff --name-only`, checked at 01:58Z).

| # | target | files to own | evidence | expected [E] |
|---|---|---|---|---|
| T6 | Merkle leaf + tree: narrow-width leaf path, leaf + k-layer fused subtree, one tail kernel for the small upper layers | `NAT/commitment/{progressive.cu,merkle.cu}` (+ `blake2s_protocol.cuh` internals; ABI unchanged) | `mixed_leaf` 1.342 GPU-s (12.7%); 0.55–0.80 TB/s at 8–16 columns; `child_layer` 7,849 launches (6,517 < 10 µs) | −0.25 to −0.40 GPU-s; −0.10 to −0.20 s request (TC and openings are on the native path) |
| T7 | GKR batch sumcheck: parallel `batch_round` (128 threads, smem reduce, thread-0 transcript); fuse fold(r) with sum(r+1) for small rounds; widen the persistent tail | `NAT/rv64/{batch.cu,batch_oracles.cu,batch_transition.cuh}` (+ `fold_sum.cuh`, `round.cuh` if needed) | `batch_round` 0.153 GPU-s at 70.8 µs × 2,250 single-thread; sum/fold chains launch-bound; GKR family 0.846 | −0.20 to −0.30 GPU-s; −0.10 to −0.15 s on the native window |
| T8 | LogUp batch inverse: block-level batch inversion (one inversion per 512–1024 rows, computed in parallel), fuse `global_row_sum`, then `cumulative` / scan | `NAT/rv64/global.cu`, `NAT/rv64/binding.cu` (`stwo_rv64_prefix_scan_on` only), `circuit_outer::cumulative` in `NAT/rv64/circuit_interaction.cu` | 0.388 + 0.078 GPU-s; about 14 ms per launch vs 4.7 ms byte bound; 31/32 lanes idle in each inversion | −0.20 to −0.28 GPU-s; −0.10 s on recursion after native |
| T9 | Witness generation: coalesced witness stores (physical-row tiles in smem), privatised smem histograms and warp-aggregated atomics | `NAT/rv64/{keccak_witness.cu,bridge_witness.cu}`, `NAT/circuit/base_witness.cu` | `keccak_witness` 0.343 GPU-s at 38–75 GB/s; bridge 0.118 (256-bin contention); `generate` 0.297 | keccak 0.34 → ~0.08, bridge → ~0.02, generate −0.1: −0.45 GPU-s; −0.15 s native, −0.05 s recursion |
| T10 | Narrow-capture replay throughput (the CPU recorder), which T1 left as its remaining bound | `src/integrations/riscv_cpu/word16_execution/{cpu_source,prepared}.zig` (T1 keeps `direct`/`capture`/`collector`) | 26235159 narrow capture 22.0 s summed at inflight 4 vs 38.7 s at inflight 16, about 5–9 MIPS per worker vs a 170 MIPS fast pass [M T1]; capture 5.76 s with T1 | 2× recorder throughput: 26235159 capture 5.76 → ~4.0 s; 24628607 −0.3 s; 0 GPU-s |

Every target keeps its kernel signatures (or adds entry points beside the old ones) and must stay byte-identical to the frozen D2 golden. Each lands behind a default-off `STWO_RV64_M8_<WHAT>` flag.
