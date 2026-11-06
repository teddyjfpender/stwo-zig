# census1: where the default path spends GPU and request time (round 1)

Branch `codex/rv64-m8-census1`, cut from `codex/rv64-m7-integrate @ c72b51646`, with `codex/rv64-m8-bench15` merged in for its harness.
Labels: [M] measured, [D] derived from measured values, [E] estimate.

## Status and limits (read first)

- **Fresh Nsight profiles are blocked. None was taken.**
  - Pid 3302210 is an orphaned, finished native-hybrid gate service (`runs/m8-native-hybrid/daemon-26235156-r2-gate-gate-n-26235156-00-baseline`).
  - It has held 30.1 GB on each 5090 since 19:28Z, so every harness service fails at PCS init with 1.5 GB free.
  - The census1 attempt failed this way, and so did the m8-gpu gate-1 small-block-proof.
  - It is logged in `/workspace/m3/M8-INTERFACES.md`. census1 is not allowed to stop it.
  - The profile tool is ready: `scripts/rv64_m8_census.py run` (nsys `cuda,nvtx,osrt` + graph-node trace), then `analyze`.
- **No hardware counters on this pod.**
  - `ncu` returns ERR_NVGPUCTRPERM, and `nsys --gpu-metrics` reports "not supported".
  - So achieved bandwidth = a byte model / kernel time [D], and occupancy is theoretical, from regs/smem/block [D].
  - Microbenchmarks (CUDA events) [M] calibrate the two biggest families.
- **The kernel census uses the retained M7-P1 default-path trace of 24628607**, warm request, 12.60 s window.
  - Source: `runs/m7-integrate/daemon-24628607-r2-p1-inter-contributions-profile-20261106-01-06-baseline` (source `898a38bfe`, library `1adfc381`).
  - Default-path kernels changed little since then: outside `rv64/jobs`, `git diff 898a38bfe HEAD -- src/backends/cuda/native` is 12 files, mostly additive.
  - This is a stand-in for the fresh 26235156 / 24628607 / 26235159 profiles, not a substitute.
- **Capture [M]** comes from the CPU-only `rv64-capture-bench` (built here, b22bdfa6e), run with the production capture options taken from the bench15 default manifest. The pod was loaded (load1 10–26), so those walls are diagnostic.

Files:
- `m7p1-24628607-warm.json`: analyzer output (families, top kernels, devices, copies, CUDA API, NVTX GPU projection);
- `capture-cpu.json`;
- `microbench.json`, plus the microbenchmark sources `blake_leaf_bench.cu` and `fft_bench.cu`.

## (a) Kernel GPU-seconds by family: 24628607 warm, default path [M]

The warm request takes 12.60 s. Kernel time is 10.58 GPU-s over 71,915 launches.

| family | GPU-s | % | launches | notes |
|---|---:|---:|---:|---|
| circle FFT / LDE / interpolation | 3.175 | 30.0 | 23,055 | wide passes at 1.47–1.50 TB/s [D]; b2n ≥2^19 and n2b 2^20 take 3 passes [M bench] |
| Merkle / Blake2s | 1.523 | 14.4 | 9,156 | `mixed_leaf` 1.342; 1.43–1.50 TB/s standalone [M bench] |
| composition / constraints (AOT) | 1.237 | 11.7 | 1,272 | truth shards 0.668 (148 regs), composition 0.269 (171), joined/projection 0.29 (253–255 regs) |
| quotients / OODS / FRI | 1.123 | 10.6 | 1,860 | `deep_combine` 0.480 (168 regs, occupancy 0.25), `sample_first` 0.412 |
| recursion assignment | 1.024 | 9.7 | 9,291 | `chain_run` 0.993: one 512-thread CTA, 689 launches, 1.44 ms each |
| GKR / sumcheck | 0.846 | 8.0 | 16,861 | `batch_round` <<<1,1>>> and `oracles_*` grid-1 chains, 2,250 rounds |
| LogUp / lookup | 0.753 | 7.1 | 3,841 | `global_inverse_contribute` 0.388, scans 0.13 |
| witness generation | 0.721 | 6.8 | 319 | `keccak_witness` 0.343 (57 ms each), `generate` 0.298 |
| transcript / channel | 0.078 | 0.7 | 726 | `channel_mix` <<<1,1>>> |
| PoW / other | 0.099 | 0.9 | 5,534 | |
| memcpy H2D | 1.156 copy-s | | 11,640 | 28.4 GB per warm request at 24.6 GB/s (PCIe); D2D 167 GB at 782 GB/s; D2H 62 MB |

Top kernels: achieved bandwidth and occupancy vs the 5090 peak (1.79 TB/s, 170 SMs, 48 warps/SM).

| kernel | GPU-s | mean | regs / smem | theor. occ. [D] | achieved [D] |
|---|---:|---:|---|---:|---|
| `blake2s::mixed_leaf_kernel` | 1.342 | 1.03 ms | 56 / 0 | 0.67 | standalone 1.43 TB/s at 64 cols, 1.50 at 128 [M]; 0.55–0.80 TB/s at 8–16 cols |
| `transform::n2b_wide_contiguous<13>` | 1.122 | 0.62 ms | 106 / 33 KB | 0.33 | 1.50 TB/s (84%): 32 words per thread in + out [D] |
| `circuit_fill::chain_run` | 0.993 | 1.44 ms | 64 / 4 KB | 1 CTA | latency-bound: 120,241 levels per node, 75% of them ≤32 wide [M log] → ~430 ns per level [D] |
| `rv64_truth_domain_0_shard_*` | 0.668 | 3.2 ms (shard 47: 95 ms) | 148 / 0 | 0.33 | compute-bound AOT |
| `n2b_wide_strided_short` | 0.533 | 0.43 ms | 116 / 33 KB | 0.33 | ≥1.5 TB/s (coefficient tails are not read) [D] |
| `rv64::deep_combine` | 0.480 | 14.5 ms | 168 / 0 | 0.25 | compute-bound: one QM31 inversion per 8 groups per row |
| `n2b_wide_strided` | 0.477 | 0.85 ms | 120 / 66 KB | 0.33 | 1.47 TB/s [D] |
| `rv64::sample_first` | 0.412 | 0.45 ms | 48 / 4 KB | 0.83 | |
| `global_inverse_contribute` | 0.388 | 0.99 ms | 66 / 0 | 0.58 | |
| `keccak_witness` | 0.343 | 57 ms | 54 / 0 | 0.75 | 1.6 waves |
| `b2n_continue` + `n2b_continue` | 0.574 | 0.1–0.27 ms | 40–72 | 0.67–1.0 | the third pass of large b2n / n2b(2^20) |
| `blake2s::child_layer_kernel` | 0.181 | 23 µs | 40 / 0 | 1.0 | 1.57 TB/s [D]; 7,849 launches, one per layer |

**Readout.**
- The two largest families, FFT and Merkle (4.7 GPU-s, 44%), already run at 1.4–1.5 TB/s. A rewrite cannot make them much faster; only moving fewer bytes helps (fewer passes).
- The headroom is in four places:
  - latency-bound single-CTA chains: `chain_run`, the GKR round triplet, `deep_validate`, `channel_mix` (≈1.5 GPU-s);
  - register-starved compute kernels: DEEP, AOT composition at 148–255 regs (≈2.4 GPU-s);
  - the extra FFT pass;
  - and, for request time, the CPU capture.

NVTX GPU projection, warm, attributed to the innermost range on the launching thread [M]:

| range | GPU-s |
|---|---:|
| `rv64/composition` | 2.324 |
| `m7/pcs/openings` | 1.620 |
| `rv64/owner/callback` (native GKR / witness) | 1.547 |
| `rv64/recursion/MAIN-assignment` | 1.216 |
| `rv64/TC/INTER` | 0.940 |
| `m7/pcs/deep` | 0.805 |
| `rv64/TC/MAIN` | 0.752 |
| `rv64/recursion/INTER-witness` | 0.692 |
| `m7/pcs/samples` | 0.502 |
| `rv64/TC/FIXED` | 0.122 |

## (b) Request critical path: 24628607 warm [M, M7-P1 trace and stage markers]

| stage | s |
|---|---:|
| capture (CPU) | 2.057 |
| setup | 0.132 |
| native prove | 4.600 |
| recursion after native | 5.598 |
| native verify (side thread, overlapped) | 1.509 |
| request wall | 12.592 |

- **GPU busy (kernels and copies, union):**
  - dev0 5.77 s (45.8%), dev1 6.21 s (49.3%);
  - lead idle 2.57 / 2.46 s, which is the **capture: both GPUs idle for its whole length**;
  - tail idle 0.17 / 1.14 s;
  - idle gaps ≥1 ms: 176 / 156, totalling 3.63 / 2.38 s.
- **The largest gaps** are 904 ms and 596 ms (dev0) and 286 ms (dev1). Each opens right after `m7/pcs/final_readback_encode` → owner controller host work, or at the native stage barrier (`derive_binding` → next segment).
  - These are the host waits H8/H13/H20–H25 that the GPU-native streams own.
- **CUDA API:**
  - `cudaEventSynchronize`: 2,188 calls, 6.35 s;
  - `cudaStreamSynchronize`: 2,610 calls, 3.79 s;
  - 62,643 `cudaLaunchKernel` calls;
  - 19 graph launches.
- **OS runtime (osrt):** the M7 trace was taken without osrt. The fresh census1 run includes it.
- **Capture [M, CPU bench, production options, loaded pod]:**

| block | steps | capture s | fast pass s | first / last segment ready s | ledger s | MIPS |
|---|---:|---:|---:|---|---:|---:|
| 26235156 | 15.3 M | 1.63–1.65 | 0.43–0.46 | 0.76 / 1.26–1.28 | 0.25–0.26 | 9.3 |
| 24628607 | 26.9 M | 1.79–1.90 | 0.49–0.50 | 0.78 / 1.41–1.49 | 0.32–0.35 | 14–15 |
| 26235159 | 204.8 M | 8.31–8.38 | 1.18–1.24 (≈170 MIPS) | 1.31 / 5.36–5.41 | 2.38–2.48 | 24.5 |

- **Capture bound [D].** A fixed ~0.8 s comes before the first segment: image load 0.26 s + boot + the first replay.
  - Replay runs on 8 workers, so 49 segments take 6+ waves.
  - The serial ledger (≈50 ms/segment) takes 2.4 s on 26235159.
  - The default path's stage 1 waits for all of capture (H1).

## (c) End-to-end overheads [M: bench15 smoke 26235156, default arm]

| item | s |
|---|---:|
| service start (process, 2 CUDA contexts, 686 library loads, pool) | 4.47 |
| service stop | 1.73 |
| cold request | 23.33 |
| warm request | 10.28 |
| cold-only setup: FIXED authority | 5.90 |
| cold-only setup: native keys | 1.05 |
| cold-only setup: image / program | 0.30 |
| cold recursion extra (class plans, graphs, outer FIXED) | +5.15 |
| verification on the request path: native verify side thread (CPU) | 1.03–1.51 (overlapped) |
| D2H readback per warm request | 62 MB, 3.2 ms copy |
| fresh CPU receivers | 30 s each (off path) |

- **The canonical preset runs `--store none`, so every service is cold.** The ArtifactStore / setup cache exist but are off in the measured path.

## Targets (round 1, mutually disjoint, outside the GPU-native streams' files)

See the StructuredOutput / workflow return for the full plan. Summary:

| # | target | own (claim) | evidence | expected [E] |
|---|---|---|---|---|
| T1 | capture: parallel replay + two-phase ledger + in-order sealed segments | `word16_global_execution/ethereum/{direct,capture,capture_options,capture_prefetch}.zig`, `rv64_ethereum_segments.zig` (emulator core only if needed) | 26235159 8.3 s (ledger 2.4 s serial, 8 replay workers); 24628607 1.8–1.9 s; GPUs idle the whole capture | 26235159 8.3→~3.0 s; 24628607 1.85→~1.1 s; request −0.7 s / −5 s |
| T2 | recursion assignment chain: warp-level narrow runs + Blake G macro-tasks | `NAT/rv64/circuit_fill_chain.cu`, `circuit_assignment.{cu,h}`, `rv64/assignment_runs.zig` | `chain_run` 0.993 GPU-s, 1 CTA, 120,241 levels per node (90,357 ≤32 wide), ~52 ms per node | 52→~15 ms per node; −0.7 GPU-s, −0.3 s recursion critical path |
| T3 | DEEP / OODS quotient kernels | `NAT/rv64/{deep.cu,deep.h,samples.cu}` (ABI unchanged; `pcs_enqueue.cu` and `pcs_pipeline.cuh` call them) | quotients/OODS 1.12 GPU-s; `deep_combine` 168 regs, occupancy 0.25; `deep_validate` <<<1,1>>> 2.26 ms × 33 | −0.5 GPU-s |
| T4 | circle FFT pass count | `NAT/transform/{b2n_fused.cuh,b2n_retained.cu,n2b_smem.cuh,n2b_fused.cuh,n2b.cu}` | 3 passes for b2n ≥2^19 and n2b 2^20 (1.5× bytes) [M bench]; log 12 = 12 launches at 127 GB/s | −0.25 to −0.35 GPU-s |
| T5 | AOT truth / joined / projection constraint kernels: register pressure and spills | `rv64/{joined_codegen.zig,truth_domain_fixtures.zig}`, `rv64_joined_fixture_main.zig`, `rv64_projection_fixture_main.zig` + own catalogue dir (NOT `composition_codegen.zig`, which native reads) | truth shards 0.668 GPU-s at 148 regs (shard 47: 95 ms per launch, occupancy 0.33); joined 0.174 and projection 0.119 GPU-s at 253–255 regs | −0.3 to −0.45 GPU-s; needs catalogue regen + own image |
