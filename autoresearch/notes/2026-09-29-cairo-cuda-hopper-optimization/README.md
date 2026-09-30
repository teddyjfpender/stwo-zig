# H100/H200 CUDA optimization — 29 September 2026

The funded host is one NVIDIA H200 (SM90), CUDA 12.8.93, driver 570.124.06,
at $4.59/hour. The account began at $22.7457296347. A separate guard limited
this session to $6 and a 75-minute hard deadline. The pod was deleted after
retaining both rounds of evidence. The observed account balance was $19.9749226511
from an initial $22.7457296347, a $2.7708069836 session charge.

Security stays canonical: 70 queries, 26 query PoW bits, 24 interaction PoW
bits, blowup/fold step 1, last degree bound 0, no lifting, salt 0. Every accepted
trial passes Zig and the pinned official Rust verifier, with zero fallback,
zero AOT misses and one terminal proof D2H.

## Implemented and first-round qualified

- Exact reverse-dependency AIR root closures, including imperative overwrites,
  duplicate roots, original constraint weights and original runtime constant
  ordinals. Sequential noinline helpers bound compiler frames without new
  GPU buffers or launches. The first measured generic-EC kernel fell from
  432.924 ms to 130.078 ms; its native frame fell from 24,224 to 4,688 bytes.
- Fused relation generation/inversion in 256-row shared-memory tiles. Preserve
  the old groups of 32 non-small denominators and small-row individual inverse
  behavior; the full-domain denominator slab becomes a bounded ABI placeholder.
  Full-coordinate CUDA differential covers 16/256/512/1024/2048/4096 rows.
- Process-owned runtime, full-plan-keyed bounded arena cache and authenticated
  preprocessing snapshot retained across sequential requests. Fresh inputs,
  witness generation, proving, Zig verification and publication still run.
  Startup is charged to the first request; teardown is recorded separately.

[First-round paired receipts](comparison-v5.json) and [summary](summary-v5.json)
retain all four workloads and two clean cold timings per product/workload.
The initial baseline block is excluded from timing because relation smoke
qualification overlapped ingress. It remains verified evidence. Warm requests
are separate from cold processes; every repeated receipt hashes the exact
proof bytes accepted by Rust. This is adapted input through publication;
raw PIE execution/adaptation, queueing and external Rust verification are excluded.

NVML whole-device usage is sampled every 10 ms and is a peak lower bound.
Logical arena, host RSS, private-frame resources and process wall are separate.
Original full proof files, executables, compiled-source snapshot receipts and three Nsight Systems
captures are retained in ignored local output (`hopper-v5-evidence.tar.gz`).

## Qualified result and rejected experiment

| SN PIE | v45 proof | Retained proof | Retained warm proof | v45 sampled GPU peak | Retained sampled GPU peak | Retained warm adapted-input → publication |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 2.218 s | 1.889 s | 1.733 s | 114.800 GB | 100.971 GB | 3.219 s |
| 2 | 1.504 s | 1.323 s | 1.165 s | 71.649 GB | 61.846 GB | 2.307 s |
| 3 | 2.206 s | 1.878 s | 1.726 s | 113.626 GB | 99.796 GB | 3.209 s |
| 4 | 1.595 s | 1.492 s | 1.334 s | 91.513 GB | 80.267 GB | 2.804 s |

The v45 column is a separate three-trial historical run, whereas retained
cold numbers use two clean timings per product/workload from the first-round
paired comparison. Warm figures are the median of repeated requests 2 and 3
in one process, not fresh-process timings. The optimized cold
adapted-input → publication medians are 6.432, 5.439, 6.364 and 5.984 seconds.
All four remain above the subsecond proof target.

The profiler identified an unsliced windowed EC body at 192 ms and addressed
quotient accumulation at 251 ms. The second candidate lowered the AIR slicing
threshold to 4,096 instructions and used four independent QM31 sums in the
quotient kernel. It **passed all four canonical proofs** but lost 21–34 ms of
proof time on PIEs 1, 3 and 4; PIE 2 gained 48 ms. Sampled memory changes
were below 0.7 GB. Nsight Systems measured quotient at 251.024 → 268.541 ms
and the windowed EC AIR at 192.368 → 197.355 ms. Both changes were reverted;
the qualified first-round implementation is retained. The
[second-round receipts](comparison-v5b.json) and [summary](summary-v5b.json)
show all four results, including the verified rejected candidate. Its archive, including all four suite proofs and three profiles,
is retained as ignored local output (`hopper-v5b-evidence.tar.gz`).

The next large memory candidate is structurally safe lookup-word interning,
provided it handles composite writers and every authenticated pointer/ordinal
mapping. It has not yet been implemented or measured.

Nsight Compute application replay reports `ERR_NVGPUCTRPERM`: this provider
host does not expose GPU hardware counters. Kernel replay was unsuitable for
this large arena. Nsight Systems CUDA/API/memory traces succeeded. Profiling
runs never contribute to benchmark timing verdicts.

## Further memory finding

[Lookup compaction screen](lookup-compaction-screen.json) tracks imperative
register definitions and interns identical constants. Across the authenticated
64 witness programs, 11,025 logical lookup words map to 6,144 distinct values.
This is an unweighted structural screen, not measured device memory savings.
Wire changes must handle composite writers, authenticated pointer mappings,
per-row ownership and relation descriptors together. No compact lookup layout
has been admitted into the prover yet.

[Design research](../2026-09-29-cairo-cuda-design-research/README.md) documents
source/license matches. Profiling setup follows the official
[Nsight installation guide](https://docs.nvidia.com/nsight-systems/InstallationGuide/).
