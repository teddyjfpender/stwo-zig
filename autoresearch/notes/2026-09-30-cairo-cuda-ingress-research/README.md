# Cairo CUDA ingress: measured bottlenecks and optimization design

Research date: 2026-09-30. Scope: authenticated compact PIE input through
the start of proof execution, and its effect on adapted-input-to-proof-JSON
latency. This is a design and experiment plan, **not** a measured speedup.
The canonical security and independent Rust-verifier baseline is
[`suite-v18.json`](../2026-09-29-cairo-cuda-subsecond/suite-v18.json): 70 queries,
26 query PoW bits, 24 interaction PoW bits, four H200 PIEs, one cold process per
PIE. PIE execution/adaptation, queueing and external verification are outside
that timer. The fastest proof interval alone is not the end-to-end latency.

## Current ledger

| PIE | Ingress | Static | Source | Other ingress | Proof | Adapted input → publication |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 4.661 s | 2.573 s | 0.789 s | 1.299 s | 1.034 s | 5.737 s |
| 2 | 4.011 s | 2.494 s | 0.523 s | 0.994 s | 0.657 s | 4.706 s |
| 3 | 4.500 s | 2.577 s | 0.762 s | 1.161 s | 1.030 s | 5.570 s |
| 4 | 4.410 s | 2.548 s | 0.748 s | 1.114 s | 0.798 s | 5.248 s |

Static is 55–62% of ingress. Other ingress includes runtime initialization,
controller and twiddle construction, arena allocation/binding, writers, and
statement preparation. All four v18 trials report `prepared_arena_reused=false`
and `preprocessed_reused=false`. The per-PIE v18 GPU ingress ledger reports
about 3.0–3.4 GB H2D and 2.189 GB D2D. The earlier v8 Nsight Systems
[`profile-candidate-pie-1-stats.log`](../2026-09-29-cairo-cuda-subsecond/profile-candidate-pie-1-stats.log)
reports 275 ms of H2D GPU activity over 957 transfers and 297 ms total
`cudaMemcpyAsync` API time over 1,042 calls. **Inference:** 2.5 s static wall
time is not explained by transfer-engine occupancy alone; file I/O, hashing,
CPU canonicalization/validation, pageable transfer staging and host submission
gaps need separate attribution. The Nsight run predates v18 and does not
establish a v18 phase decomposition.

The fixed STWZPPC artifact is 2,172,407,516 bytes; its digest is identical for
the four trials. The loader in
[`preprocessed_cache.zig`](../../../src/integrations/cairo_cuda/executor/preprocessed_cache.zig)
streams and hashes the whole artifact, checks column identities and every M31
coefficient, transposes SIMD blocks on the CPU, then uploads each column into
the arena. This is correct source-to-upload binding, but repeated for each
fresh plan. [`initializeStatic`](../../../src/integrations/cairo_cuda/executor/ingress/controller_bundle.zig)
also materializes 2.189 GB of base evaluations via D2D and forward transforms.
That staging is subsequently overwritten, so simply retaining the current
arena does not retain the evaluations for the next proof.

The v8 independently verified same-request `--repeat` trials in
[`comparison-v8.json`](../2026-09-29-cairo-cuda-subsecond/comparison-v8.json)
reduced static host time to 44–58 ms on the third proof, from 2.6–2.7 s on
the first. This demonstrates a roughly 2.4–2.7 s amortization opportunity
for reuse; it is **not** a v18 cross-PIE or cross-block result. Current CLI
repeat proves one request again. `app.zig` retains one static receipt keyed by
the full arena key and clears it on an arena miss. The CUDA arena cache is
bounded, and large PIE arenas cannot coexist on the measured H200. More
fundamentally, `ProofProgram.program_digest` includes the statement digest,
`CudaPlan.cache_key` includes that program digest, and the arena key includes
the plan key. Therefore even equal-layout blocks with different statements
may miss the cache. See
[`app.zig`](../../../src/products/cairo_cuda/app.zig),
[`program.zig`](../../../src/integrations/cairo_cuda/program.zig),
[`proof_program.zig`](../../../src/backend/proof_program.zig), and
[`execution_plan.zig`](../../../src/backends/cuda/runtime/execution_plan.zig).

## Problem match and design choice

This is an *incremental, content-addressed immutable-data serving* problem
with a large one-time build and many small, different queries, coupled to a
*resource-lifetime/arena packing* problem. Required semantics: each proof must
use authenticated canonical source bytes, exact Cairo protocol and layout,
request-specific public statement/witness, identical proof bytes, and
independent verifier acceptance. The common artifact and protocol can be
preprocessed; the statement and witness cannot be reused by shape alone.

| Candidate | Relationship and fit | Limitation |
| --- | --- | --- |
| Runtime-owned immutable GPU cache, keyed by artifact/protocol/layout digest | Direct match; removes repeated 2.17 GB read/hash/transpose/upload across different PIEs and blocks | Must split fixed storage from shape-specific arena and track event-safe lifetime; about 2.2 GB permanent device residency if coefficients alone |
| Layout-keyed arena cache, with separate full-plan/graph identity | Direct match for equal-layout new statements; avoids allocation and layout reconstruction | Statement-dependent buffers and graph parameters still need exact rebinding; large arenas exceed multi-PIE capacity |
| Pinned, pipelined cold loader | Improves unavoidable first load; CPU read/hash and H2D can overlap | Cannot eliminate the first full authentication; pinned memory consumes host capacity and buffers must survive until CUDA event completion |
| GPUDirect Storage | Direct path for cold artifact I/O | Only promising after validation/transposition move to GPU and storage/topology support is confirmed; no benefit to already-resident hot requests |
| Compress the artifact | I/O reduction if compressible | Sixteen 4 MiB probes show most middle regions are effectively incompressible with zlib level 1; measure full corpus before designing a format |

The first architectural transfer is a **runtime-owned, separately allocated
immutable preprocessed snapshot**, keyed by the artifact's trusted SHA-256,
preprocessed variant and ordered column identity/logs, coefficient layout
version, protocol/field configuration and target device. Proof arenas borrow a
read-only lease. Never infer identity from a pathname, prior request or shape
alone. Keep a strict full-program identity for graph executables; a new,
layout-only arena key may be introduced only after proving buffer extents,
address stability and all mutable parameters are equivalent. The static
snapshot must be retired only after every borrowing stream's last-use event.
Repack the arena to remove the old embedded fixed slots, otherwise the cache
needlessly raises peak memory. Expose memory admission and eviction counters.

| Resource | Owner and intended lifetime | Mutable? | Key / retirement |
| --- | --- | --- | --- |
| Canonical preprocessed coefficients (~2.19 GB device) | CUDA runtime, across requests | No | Authenticated artifact + layout + device; evict after last borrower event |
| Optional base evaluations (~2.19 GB) | CUDA runtime, across requests | No | Same key plus transform version; keep only if measured benefit exceeds capacity cost |
| Full proof arena (variable; entire process sampled at 61–100 GB by PIE) | One proof or compatible layout cache | Yes | Validated layout key; no simultaneous incompatible lease |
| Graph executable / AOT module | CUDA runtime, across requests | Graph parameters vary | Full program/target identity and explicit parameter update; retire after graph launches finish |
| Compact input, statement, feed instances | One proof | Yes | Authenticated per-request input identity; release after last consumer |

There is also a trust gap to resolve before broadening the cache:
`StaticInputs.preprocessed_artifact_identity` is optional, and `app.zig` does
not currently populate it. The loader computes a self-consistent receipt, but
does not compare it to the known canonical artifact digest on this path.
The independent verifier should reject an incorrect table, yet a production
cross-request cache should pin the expected digest from a trusted manifest and
fail closed before proof execution. Do not treat a previously computed receipt
alone as authority for an arbitrary file path.

The cold loader should retain the current **hash of exactly the parsed raw
bytes**. Make an offline derived format only if it embeds the raw source digest
and a layout/version digest, and a trusted build or first-load validation binds
it to the canonical artifact. No proof may start until authentication and
column/range checks complete. Rewriting the loader to `mmap` without owning a
stable byte snapshot invites file-mutation races; retain this invariant.

## Ordered experiments and falsifiers

1. **Measure the actual cold critical path.** Add monotonic host spans and
   NVTX ranges for file open/read, SHA-256, identity/range check, CPU transpose,
   H2D submit/completion, D2D, transforms and controller/writer planning.
   Collect H2D bytes/calls, CPU utilization, storage cache state, host RSS,
   device high-water, and stream idle gaps. Use a v18-equivalent binary and
   distinguish a cold process, warm process/new statement, warm shape, and
   same-request repeat. Nsight Systems can correlate NVTX CPU ranges with CUDA
   API and GPU workload [NVIDIA guide](https://docs.nvidia.com/nsight-systems/UserGuide/).
2. **Split immutable residency from the proof arena.** Trial the sequence PIE
   1→2→3→4→1 in one worker, with different statements where geometry allows.
   A passing mechanism has one artifact authentication/upload per worker,
   subsequent `preprocessed_reused=true`, no stale lease, and unchanged proof
   digests/Rust-verifier acceptance. The observed 2.4–2.7 s same-key static
   saving is the opportunity scale; cross-shape effect must be measured. Report
   2.2 GB persistent device cost and arena-repacking effect separately.
3. **Remove unrelated request-time work.** Load authenticated fixed tables,
   witness programs, relation templates, AOT modules and topology once per
   worker; cache immutable parsed forms. `canonical_source.prepare` currently
   reopens the static files and re-authenticates three of them twice, but the
   compact `.cpi` is already captured, hashed and parsed once. Avoid a fake
   optimization that skips dynamic-input parsing/authentication. Separate
   `program_digest` (security/graph identity) from an independently verified
   layout key; measure compiler and controller subphases before caching them.
4. **Improve unavoidable cold load.** Current `uploadSlice` passes an ordinary
   allocator buffer to `cudaMemcpyAsync`. NVIDIA documents that pageable host
   buffers make this path synchronous and prevent transfer/compute overlap
   [asynchronous execution](https://docs.nvidia.com/cuda/cuda-programming-guide/02-basics/asynchronous-execution.html),
   [pinned memory](https://docs.nvidia.com/cuda/cuda-programming-guide/02-basics/understanding-memory.html).
   Test a bounded two- or three-slot pinned ring, large chunked reads, one SHA
   stream over raw data, SIMD transpose/range-check on a CPU worker or GPU
   kernel, and H2D on a transfer stream. Recycle a slot only after its copy
   event. Compare CPU transpose versus GPU transpose, and verify exact column
   order/field range. Prediction is lower wall time through overlap, **not**
   a 2.5 s pure-transfer saving; older trace attributes only 275 ms to H2D
   device activity.
5. **Remove repeat base-evaluation work if it pays.** A separate read-only
   evaluation cache could avoid the 2.189 GB D2D+forward-transform pass; it
   costs roughly another 2.2 GB or requires different alias/lifetime packing.
   Time this pass independently and retain only if end-to-end latency improves
   without compromising the 100 GB PIE high-water and future device targets.
6. **Overlap independent cold work.** With common preprocessed residency
   outside the plan, background worker startup can authenticate/load it while
   a CPU thread parses and plans an arriving PIE. Record cold-start cost
   honestly; prewarming changes the request boundary, not resource cost.
   Where feasible, pipeline upstream PIE adaptation into ingestion of already
   produced chunks, with final digest/length checks before proof admission.
7. **Explore lower-priority mechanisms only after trace evidence.** CUDA
   Graphs amortize repeated GPU launch submission, but cannot capture the CPU
   artifact parse/hash and help only if the graph parameters are safely
   rebound [NVIDIA CUDA Graphs](https://docs.nvidia.com/cuda/cuda-programming-guide/04-special-topics/cuda-graphs.html).
   GPUDirect Storage can remove a host bounce buffer, but requires supported
   storage and a GPU-side validation/reorder design
   [NVIDIA GDS overview](https://docs.nvidia.com/gpudirect-storage/overview-guide/).
   `cudaMallocAsync` pooling matters only if arena allocation is still a
   significant measured cost after layout reuse. Full compression is probably
   low-return given the sampled coefficients' entropy.

## Acceptance and latency model

For each candidate, first run a narrow loader/arena microbenchmark, then a
single complete PIE proof with official Rust verification, then all four PIEs
and the mixed-PIE sequence. Compare uninstrumented paired ABBA runs under the
same H200 conditions. Preserve 70/26/24 security, exact proof digest, AOT-only
path, no CPU fallback, no intermediate proof D2H, and one terminal readback.
Report cold-worker, warm-worker/new-statement and warm-shape distributions,
publication latency, ingress phases, peak GPU/host memory, and throughput.

An illustrative arithmetic bound: removing the entire v18 static span and
nothing else would leave adapted-input→publication at 3.164, 2.212, 2.993,
2.700 s respectively. Removing both static **and** source spans entirely
would leave 2.375, 1.689, 2.230, 1.951 s. Those are counterfactual bounds,
not forecasts; a persistent cache will still have copy/transform/bind costs,
and proof generation remains 0.657–1.034 s. Subsecond proof generation does
not imply subsecond publication, so the performance target must use the latter
when judging block-pipeline economics.
