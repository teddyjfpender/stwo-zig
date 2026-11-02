# Bounded packed service truth composition

The OM31 service truth route now shards packed constraint rows through the existing scoped pool after each coset FFT has completed. It neither starts a pool nor changes the FFT, field, masks, power order, degree, transcript or global relation closure. `row_work.forEachRange` uses a nonblocking scoped-pool lease and falls back to the caller when the pool is unavailable or a cooperative queue is active. Every helper joins before error inspection or scratch release.

Each task owns disjoint packed output rows and a distinct heap workspace. The caller alone reserves constraint powers and advances the fresh-column cursor after a successful joined coset. The same `emitForWithWorkspace` constraint body serves the old `emitFor` point/circuit wrapper and the domain route. No constraint implementation is duplicated.

This workspace is necessary for correctness on the existing 1 MiB worker stacks: the Keccak packed buffers occupy 1,217,920 bytes before other stack frames. Scratch is allocated on the proof allocator before column reservation. The maximum is 16 tasks × 1,217,920 bytes = 19,486,720 bytes, below an explicit 32 MiB cap per active component. The minimum grain is 64 packed blocks, or 1,024 logical rows. The plan validates its dimensions and allocation fails without publishing partial scratch ownership. This is additional transient per-component scratch, not an RSS measurement or a global memory-admission guarantee.

Qualification uses two real fixture CPU shards and three service truth proofs (Keccak, ADD and DOUBLE), with truth logs increased to at least 11 so row work exceeds the parallel grain. Both one-worker and four-worker schedules run under 1 MiB worker stacks. They produce exactly the same physical proof bytes, claim coordinates and stage-one manifest bytes; independently reconstructed keys and a fresh receiver establish final global closure. The digest is pinned against the pre-change serial implementation, not merely against another new-code run:

`eaa04370373513f54f8c7435f1453983681413dfd978f56026f363ed8fa9f386`

Focused tests additionally compare all six truth-family packed residual streams from the wrapper and explicit heap workspace, compare first/last packed lanes against native OM31 scalar emission, and inject all workspace-allocation failures. The fixture, command and raw logs are retained under `vectors/reports/rv64-truth-parallel-composition-20261101/`.

This qualifies deterministic parallel truth constraint evaluation on the fixture geometry. It does not establish a full-block speedup, GPU qualification, a changed security level, or removal of other composition/FFT costs. Measurements on a shared host must not be promoted as controlled speedups.
