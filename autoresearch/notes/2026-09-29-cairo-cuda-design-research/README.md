# CUDA PIE design research — 29 September 2026

The largest opportunities are a persistent request lifecycle, bounded interaction
materialization, compiled AIR dependency slices, and a coefficient/evaluation
schedule that trades carefully measured recomputation for residency. Launch
tuning alone cannot deliver the requested subsecond latency or single-5090 fit.
This dossier records research and host analysis, not a new GPU speedup.

The problem-match brief is [problem-match.md](problem-match.md). Reproduce the
receipt summaries and authenticated-template analysis with
`python3 autoresearch/notes/2026-09-29-cairo-cuda-design-research/analyze.py`.
The brief is also [registered in autoresearch notes](../20260929-153623-cuda-cairo-subsecond-design-bounded-materialization-and-air-.md).
Reference revisions, licenses, inspected files and their digests are in
[sources.json](sources.json). Reference repositories are read-only under ignored
`zig-out/cairo-cuda-research-20260929`; no external build scripts were executed.

## Measured baseline and the required boundary

The retained v45 H200 receipt has three cold-process trials per PIE, twelve
accepted proofs, native NVIDIA CUDA, zero CPU fallback and zero AOT misses.
[Receipt](../2026-09-29-cairo-cuda-local/nvidia-v45-repeated-suite.json),
[derived profile](profile-summary.json).

| Benchmark | Prove/terminal decode median | Adapted input through publication median | Maximum sampled device usage | Logical arena |
|---|---:|---:|---:|---:|
| SN PIE 1 | 2.218 s | 7.042 s | 114.800 GB | 107.197 GB |
| SN PIE 2 | 1.504 s | 5.708 s | 71.649 GB | 64.055 GB |
| SN PIE 3 | 2.206 s | 7.118 s | 113.626 GB | 106.027 GB |
| SN PIE 4 | 1.595 s | 6.420 s | 91.513 GB | 83.911 GB |

GB in these tables means decimal bytes/1e9. Device usage is whole-device NVML
sampling at 10 ms and therefore a lower bound on peak; it includes more than
our logical arena. Host peak RSS is 1.21–1.53 GB and is a separate measurement.
These results do not include raw PIE adaptation, queueing, or the subsequent
official Rust verification process. They are not complete warm PIE requests.

[Task 09](../../tasks/cuda/09-cairo-sn-pie-subsecond.md) starts the acceptance
clock when canonical PIE payload bytes are process-owned. Decode, validation,
statement binding, complete witness construction, H2D, proving, encoding,
independent verification and publication remain inside it. File/network delivery,
cold startup, plan misses and queueing need separate receipts. A prepared CPI
or decoded witness cannot replace the ordinary PIE boundary. The original PIE
execution itself is already represented by the PIE and is not rerun.

Preserve 70 queries, 26 query PoW bits, 24 interaction PoW bits, blowup 1,
fold step 1, final bound 0, no lifting, salt 0, all active Cairo components and
the pinned official verifier. Cairo uses its canonical **plain BLAKE2s** PCS;
the RISC-V BLAKE3 work is not a license to change this protocol.

## Where the measured time goes

Median CUDA-event intervals, milliseconds; these may include host submission
gaps and are not pure hardware-counter compute attribution:

| Stage | PIE 1 | PIE 2 | PIE 3 | PIE 4 |
|---|---:|---:|---:|---:|
| Ingress event interval | 3142.0 | 2917.5 | 3281.6 | 3226.6 |
| Witness generation | 290.5 | 231.6 | 288.2 | 242.2 |
| Trace commitment / interaction work | 548.3 | 317.2 | 545.1 | 426.3 |
| Constraint evaluation | 1040.0 | 630.1 | 1033.6 | 588.6 |
| OODS | 52.1 | 35.4 | 51.6 | 42.8 |
| Quotient | 260.9 | 260.3 | 260.7 | 261.0 |
| FRI commitment | 6.9 | 6.9 | 6.9 | 6.9 |
| Query PoW | 0.2 | 4.2 | 1.5 | 9.1 |
| Decommitment | 10.6 | 10.7 | 10.6 | 10.6 |

The ingress host ledger separately reports approximately 2.49–2.69 s static
setup, 0.56–0.87 s source admission, 0.34 s runtime setup, 0.12–0.20 s allocation,
0.12 s controllers and 0.10 s binding. Removing repeated immutable work is a
major full-request opportunity; subtracting these numbers from a cold run is
not a measured warm latency. Some categories overlap with queued device work.

PIE 1 submits 3501 kernels. OODS accounts for 1385 launches but only 52 ms;
quotient takes 261 ms with eleven launches. FRI already takes only about 7 ms.
Even eliminating the entire OODS stage leaves PIE 1 above two seconds. Graphs
are useful for the launch floor and host feed, but cannot remove the large AIR
and commitment work. [NVIDIA graph measurements](https://developer.nvidia.com/blog/constant-time-launch-for-straight-line-cuda-graphs-and-other-performance-enhancements/)
support repeat-launch overhead reduction, not an inference of a tenfold proof
speedup.

The older v42 diagnostic event profile identifies 391 ms in generic partial-EC
AIR, 189 ms in window-18 AIR, and 129 ms in the EC-op witness with 2048 logical
rows. It is diagnostic, not the v45 headline baseline. No retained Nsight
Systems or Compute trace establishes the current achieved bandwidth, stall
reason or overlap. Those are the first hardware measurements to collect.

## Memory: the actual peak and its next bottleneck

Existing device-free host-admission tests passed 2/2 for the four real inputs.
The existing planner's dump prints slots at least 2^26 words; it omits about
0.30 GB at the largest reported stage. Complete planner peaks are retained.
[Inventory and counterfactuals](memory-inventory.json).

| Large resource, PIE 1 | Size | Present lifetime | Required consumer |
|---|---:|---|---|
| Expanded lookup inputs | 24.182 GB | Witness → interaction commitment | Relation source expressions after main-root challenge |
| Witness scratch | 9.107 GB | Witness only | Deductions / temporary values |
| Relation denominators | 8.604 GB | Interaction commitment only | Batch inverse and fraction chain |
| Main coefficients | 11.026 GB | Witness → OODS | AIR extension, OODS |
| Main evaluations | 22.053 GB | Witness → opening | Leaf hashing, AIR/quotient where domain matches, openings |
| Interaction coefficients | 8.604 GB | Interaction commitment → OODS | AIR, OODS |
| Interaction evaluations | 17.207 GB | Interaction commitment → opening | Leaf hashing, AIR/quotient, openings |
| Preprocessed coefficients/evaluations/tree | 10.812 GB | Ingress → OODS/opening | Immutable canonical PCS data |
| AIR LDE tile | 3.825 GB | Constraint evaluation only | Constraint kernels |
| Two progressive hash state slabs | 0.805 GB | Interaction commitment only | Exact mixed-height hash chaining |
| OODS reduce A/B | 3.603 GB | OODS only | Circle point evaluation reduction |

Printed live-byte stage sums for PIE 1 are 79.371 GB during witness, 106.897 GB
during trace commitment, 78.091 GB during AIR, and 53.805 GB at late openings.
The complete trace-commit peak is 107.197 GB. Kernel private frames, CUDA context,
pool reservation and sampling uncertainty are additional to that plan.

Perfectly removing the lookup slot gives an **82.715 GB lower-bound** printed
trace-commit working set. Perfectly removing lookup and denominator slots shifts
the largest stage to **78.091 GB during AIR**. These are counterfactuals with
zero replacement storage, not implementation or GPU measurements. An existing
107 GB allocation does not become smaller just because a value dies sooner:
the compiler must repack the arena and qualify event-safe aliases.

Consequently an 80 GB device still needs further reductions and runtime margin;
a [32 GB RTX 5090](https://www.nvidia.com/en-us/geforce/graphics-cards/50-series/rtx-5090/)
needs several structural changes. Caching the 10.8 GB preprocessed data saves
setup time but **does not free device capacity**. A 24 GiB capacity profile
remains the broader task's streaming target, distinct from 5090 capacity.

## References worth transferring, and their limits

**Airbender is the closest arithmetic reference.** Its trace holder supports
full evaluation storage or a single coset that is recomputed as needed. Tree
caching also has explicit policies; the partial-cache path is unfinished in the
inspected revision. This supports our retained-coefficient / bounded-evaluation
design, with a measured recomputation cost. Its generic constraint kernel uses
bounded flattened metadata and separate accumulation classes rather than a
large general-purpose thread array. Our higher-degree Cairo EC constraints
still require a faithful DAG compiler. [Trace holder](https://github.com/matter-labs/zksync-airbender/blob/6ec4ea725d654c5e4fd3a122d571ca37804f9abd/gpu_prover/src/prover/trace_holder.rs),
[constraint kernel](https://github.com/matter-labs/zksync-airbender/blob/6ec4ea725d654c5e4fd3a122d571ca37804f9abd/gpu_prover/native/stage3.cu).

A material comparison limit: Airbender's inspected `blake2s.cu` selects seven
rounds. Our canonical Cairo plain BLAKE2s requires ten. Transfer access patterns
and tiling only; copying its rounds would change proof semantics. Its M31
representation also admits p as an alternate zero, unlike several canonical
ABI boundaries here. [Hash source](https://github.com/matter-labs/zksync-airbender/blob/6ec4ea725d654c5e4fd3a122d571ca37804f9abd/gpu_prover/native/blake2s.cu).

**Sppark offers useful transform and ownership mechanisms.** Its narrow-field
mixed-radix kernels combine coalesced loads, register butterflies, warp shuffles
and shared exchanges. Partial twiddle tables avoid a full-domain table. Its
GPU utility owns reusable streams, events and stream-ordered allocations.
M31 circle FFT twiddles and index order are different from multiplicative NTT;
adapt the decomposition and prove exact circle-domain parity rather than
substituting its transform. [Kernel](https://github.com/supranational/sppark/blob/9e5c7951d4ff4992f78af26f48d3c9230b8c4136/ntt/kernels/gs_mixed_radix_narrow.cu),
[parameters](https://github.com/supranational/sppark/blob/9e5c7951d4ff4992f78af26f48d3c9230b8c4136/ntt/parameters.cuh),
[GPU ownership](https://github.com/supranational/sppark/blob/9e5c7951d4ff4992f78af26f48d3c9230b8c4136/util/gpu_t.cuh).

**ICICLE-Stwo needs branch-level scrutiny.** Default `dev` did not contain a
CUDA backend. The inspected `feat/icicle-backend-mt` branch has circle-transform
batching APIs, but multiple unfinished backend methods and per-operation
allocations/synchronization/copies. It is a mechanism reference, not a complete
verified replacement backend. ICICLE's public M31 arithmetic is useful, but
the available source must be distinguished from packaged CUDA backends.
[Actual GPU branch](https://github.com/ingonyama-zk/icicle-stwo/blob/37b52a9c36d95a6acf66524a585cd495df131268/crates/prover/src/core/backend/icicle/mod.rs).

**Era-bellman-cuda** demonstrates stream-ordered pool allocation and explicit
copy/compute event edges; its NTT includes multi-device exchange points. It is
a different proof/field system, so adopt ownership mechanisms rather than
arithmetic or claimed proof speeds. [Allocator](https://github.com/matter-labs/era-bellman-cuda/blob/d1fa8670ee84ec3477c6cc1c85a3554cfa5e0206/src/allocator.cu),
[NTT orchestration](https://github.com/matter-labs/era-bellman-cuda/blob/d1fa8670ee84ec3477c6cc1c85a3554cfa5e0206/src/ntt.cu).

**VortexSTARK is an experimental comparison, not code to import.** Its warp
interpreter still declares large dynamically indexed per-lane arrays; dividing
a bank among lanes does not establish that the compiler keeps it in registers.
Its large point-evaluation path is incomplete, and root-only Merkle tiling needs
additional opening retention or reconstruction. The inspected license is BSL
1.1 with non-production use until the stated change date. No production source
was copied. [Interpreter](https://github.com/garrick247/VortexSTARK/blob/272714aacd337d516a1d14d64e7c8cf0e0f4909b/cuda/constraint_eval_warp.cu),
[license](https://github.com/garrick247/VortexSTARK/blob/272714aacd337d516a1d14d64e7c8cf0e0f4909b/LICENSE).

Pinned **Stwo itself** batches denominator inversion across domain rows. Our
quotient currently batches eight sample denominators within a single row.
The relevant next candidate is cooperative cross-row inversion, not an alleged
missing exponentiation addition chain: our M31 inverse already has that chain.
[Pinned quotient source](https://github.com/starkware-libs/stwo/blob/7b211edde786775016ef3eecb837a6240d8fe792/crates/stwo/src/prover/backend/simd/quotients.rs).
[NVIDIA's scan work](https://research.nvidia.com/publication/2016-03_single-pass-parallel-prefix-scan-decoupled-look-back)
is a candidate primitive for field-product scans; its demonstrated bandwidth
does not predict the throughput of QM31 multiplication.

[FlashAttention](https://arxiv.org/abs/2205.14135) supplies the IO-aware analogy:
recompute cheap intermediates inside bounded tiles instead of materializing
large arrays. The analogy does not transfer attention's math, speedup or tensor
core implementation into exact M31 arithmetic. [Circle STARKs](https://eprint.iacr.org/2024/278)
defines the transform/protocol constraints that our transfer must preserve.

## The first engineering batch

1. **Make the ordinary PIE request use a persistent generic runtime.** Retain
   authenticated AOT modules, immutable PP, twiddles, prepared topology and
   allocation policy; decode and validate each new PIE. Split immutable
   authentication from per-request identity binding. Do not cache proofs,
   witnesses, random challenges or statements. Add cold/warm/file/request/queue
   receipts, cache hit/miss counters and resource high-water attribution.

2. **Remove whole-corpus interaction temporaries.** Replace expanded lookup
   buffers with authenticated expression views on compact witness inputs or
   reconstructed base rows. Replay deductions only where expressions require
   them, and never emit multiplicity side effects twice. After the main-root
   challenge, fuse relation fraction generation, bounded batch inversion and
   fraction multiplication. Keep the exact cumulative column chain and final
   row correction/reduction. Reuse bounded denominators across cohorts instead
   of retaining all 8.6 GB. Existing relation inversions are already batched;
   the win sought here is eliminating global materialization and its passes.

3. **Compile large AIRs as dependency slices.** Version imperative register
   writes, keep each root's original random-coefficient index, and generate
   bounded root bundles with scalar locals and shared producer recomputation.
   Our authenticated analysis found that merely consuming completed roots
   sooner changes none of the largest banks. SSA without slicing also changes
   no peak for the largest EC template. Slicing does:

   | Generic partial-EC variant | Modeled peak bank/thread | Dependency instruction work |
   |---|---:|---:|
   | Current / unsliced SSA | 11,256 B | 18,128 |
   | 128-root bundles, 4 bundles | 5,684 B | 19,581 (+8.0%) |
   | 64-root bundles, 7 bundles | 4,620 B | 20,817 (+14.8%) |
   | 32-root bundles, 14 bundles | 2,828 B | 23,386 (+29.0%) |

   These are fixed-order dependency/liveness models, not compiled stack sizes,
   arithmetic-weighted work or timing. The largest existing native frame is
   24,224 B/thread, more than the declared bank. Even 2,828 B exceeds what can
   fit wholly in 255 scalar registers. Compare compiler frames and local-memory
   traffic; do not promise a fourfold proof speedup. Bound partial accumulator
   storage and ordered merge work. Contiguous roots preserve coefficient
   assignment; field addition allows exact regrouping if reductions stay valid.
   [All template models](air-liveness.json).

4. **Replace simultaneously retained representations with bounded cohorts.**
   Retain coefficients where needed; regenerate evaluation cohorts for AIR,
   quotient and query gathering. Use a separately accounted immutable PP tier
   for capacity-limited devices. Keep only authenticated upper Merkle levels
   and reconstruct lower query subtrees after query challenges where this wins.
   Recompute complete leaves exactly: BLAKE2s compression blocks inside one
   leaf cannot be independently hashed and concatenated. Measure extra FFT,
   hash and input-read work. The 22/17 GB evaluation banks matter much more than
   another small temporary optimization once interaction materialization falls.

This is one coherent generic architecture batch. Validate producer/consumer
parity locally before the full GPU suite; do not rebuild and rerun every PIE
after each small edit. Kernel family changes still need independent reference
tests, authenticated AOT regeneration and final complete-proof gates.

## Follow-on kernels and scheduling

Use targeted Nsight measurements to decide among these candidates:

- Quotient cross-row batch inversion and tiled numerator reduction. First
  separate combine, numerator and transform contributions to the 261 ms stage.
  Preserve the pinned first bit-reversed subdomain, lift formula and zero policy.
- EC-op witness: the 2048-row kernel serializes many generic partial-EC
  deductions and affine felt252 inversions. Compare cooperative limb arithmetic
  and projective intermediate chains with exact batched affine normalization.
  Every required intermediate witness point and exceptional case must match;
  replacing only the final EC result is insufficient.
- Height-batched OODS reduction: reuse circle bases within cohorts, reduce
  kernel/temporary counts, and compare with the 35–52 ms stage ceiling.
- Circle FFT/LDE and mixed-height hashing: compare fused register/warp stages,
  compact twiddles and coalesced hash input layouts under measured register
  pressure. The current code already fuses large transform stages and reuses
  exact-domain LDEs. Retain those wins rather than rediscovering them.
- Captured stable regions and bounded lanes: after the lifetime plan is sound,
  capture regions between transcript barriers. Concurrent kernels help only
  when they shorten the measured critical path without exhausting bandwidth or
  increasing the live set. Proof concurrency is a later throughput decision.

CUDA 13 shared-memory spilling is a secondary experiment after shrinking AIR
banks. The retained baseline uses CUDA 12.8. NVIDIA's example has a 176-byte
spill frame and about an 8% kernel gain; our 24 KB frame is a different scale.
Moving 24,224 B × 256 threads to shared memory would require 6.20 MB per block.
This is not an on-chip solution. A toolchain change requires fresh AOT identity
and qualification. [NVIDIA compiler feature](https://developer.nvidia.com/blog/how-to-improve-cuda-kernel-performance-with-shared-memory-register-spilling/).

## Proposed runtime dependency and ownership contract

```text
runtime: authenticated modules, immutable data, prepared plans, bounded pools
request:
  PIE bytes → decode/validate → compact witness inputs
                   │
       bounded independent main-column cohorts
                   ↓
        main root / transcript challenge barrier
                   ↓
      lazy lookup views → bounded interaction cohorts
                   ↓
      interaction root / composition challenge barrier
                   ↓
      evaluation cohorts → sliced AIR → composition root
                   ↓
       OODS barrier → quotient → sequential FRI rounds
                   ↓
          query challenge → regenerate/gather openings
                   ↓
      encode → one terminal D2H → independent verify → publish
```

The coordination stream owns transcript order and terminal assembly. Bounded
compute lanes own disjoint cohort scratch. A H2D lane may overlap validated
compact-input chunks with independent work. Event edges protect every producer,
last consumer and alias reuse. FRI rounds remain sequential; graph capture may
span only stable, device-resident regions with correct challenge dependencies.
If any host transcript step bisects a region, split capture there.

Runtime-owned PP and modules are immutable. Shape cache keys include complete
ProofProgram/CudaPlan digest, statement-independent geometry, protocol, source
authority, GPU SM, driver/toolkit compatibility, module digest and schedule
version. Per-request mutations and transcript bytes are fresh bindings. Graph
updates validate all pointers/extents; production update failure fails closed.

Request input staging lasts to its last replay consumer, not necessarily first
witness completion. Coefficients last to their final AIR/OODS/recompute
consumer. Cohort evaluations/hash scratch last to their event, then alias.
Merkle caps last to opening publication. Terminal host proof storage lasts to
verification/publication. Each live resource has exactly one runtime/session
owner; unwind retires queued work before aliasing/freeing, preserves unrelated
cached resources and never publishes a failed proof.

Accounted capacity is persistent data + shape cache + maximum live request
resources + module/private/pool reservation + bounded staging + safety margin.
For k concurrent sessions, shared immutable data appears once but request live
resources and private work must be accounted for each overlap. Admission uses
actual free capacity and checked byte arithmetic, not the fixture name.

Multi-GPU work is a later architecture experiment. Column partitions make FFTs
independent but mixed-height leaves hash canonically ordered data across column
families; communication or regeneration remains. Row/subtree partitions simplify
Merkle merging but large FFT stages cross those partitions. Independent proof
aggregation would change the protocol boundary. Neither streams nor extra GPUs
remove these dependencies automatically.

## Falsifiable budgets, qualification and economics

PIE 1's existing proof phase needs more than a 55% reduction to go below one
second, before adding the missing raw PIE request work. An aggressive **design
budget**, not a forecast, is 100 ms host admission/input work, 100 ms witness,
200 ms commitments/interactions, 250 ms AIR, 150 ms OODS/quotient and 100 ms
FRI/PoW/opening/encoding/independent verification/publication: 900 ms plus a
100 ms margin. If actual raw input handling or a canonical dependency cannot
fit, report the failure and revise the design rather than narrowing the timer.

Track per-stage reads/writes/rereads rather than arena size alone. Removing the
24.182 GB lookup materialization avoids at least a full write and later read
when no equivalent array is substituted. The 8.604 GB denominator path has a
generation write, in-place inverse read/write and consumer read; fusion may
remove these slab transfers, but replacement field work and smaller-tile passes
must be counted. These byte estimates are operation ledgers, not Nsight traffic.

Profile one complete PIE 1 timeline and dominant AIR, relation/hash, witness
and quotient kernels with registers, frames, local/DRAM/L2 bytes, stalls,
occupancy limits, grid geometry and actual overlap. Instrumented runs diagnose;
uninstrumented paired runs decide. Use ten warmups and seven paired rounds per
PIE for the task's headline gate, keep cold/miss/file/queue receipts, and report
p50 and observed tails, all four per-family times and memory maxima. Longer
sustained runs are required to estimate p95/p99 reliably. No class-average gain
may conceal a failing PIE. Requalify Native/RISC-V shared changes by structural
class, with targeted tests first, rather than repeatedly running whole suites.

Required parity includes all witness/lookup values and multiplicities, interaction
accumulators, roots/challenges, circle FFT and quotient domains, CPU/CUDA outputs,
repeat proof bytes where deterministic, Zig verification and pinned Rust final
verification. Exercise invalid inputs, statement/proof mutations, cache/graph
identity mismatches, allocation failure, queued-device errors, teardown leaks,
zero fallback/JIT misses and one terminal proof read. Compiler resource reduction
without a full verified-request and capacity win is not an accepted optimization.

The prior v46 result is the caution: 9–11% faster isolated proving but a frame
increase to 38,616 B and about 3.88 GB more sampled memory; rejected. v48 added
0.805 GB for less than 1% timing change; rejected. New candidates must improve
the relevant latency/capacity frontier and retain an explicit fallback schedule
outside production admission, not silently degrade verification semantics.

For price r dollars/hour, warm request time t seconds and productive utilization
u, approximate allocated-device cost is r×t/(3600×u), plus startup amortization,
CPU, storage and transport costs. At the user's historical $3/hour and 1.5 s,
the fully utilized arithmetic is $0.00125/proof; its timing scope lacks a receipt.
A cheaper GPU wins only when capacity, complete latency and sustained queue
behavior all pass. No current 5090 latency, live hourly quote, or claimed
subsecond result is inferred from H200 timings. This research used no GPU credit.
