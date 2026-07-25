# Session 03: CUDA Architecture Completion Audit

## Scope

This session resumes the original CUDA system-architecture goal after the
kernel-optimization loop reached a clean stopping point. The authority is:

- `conformance/2026-07-24-cuda-system-architecture-goal.md`;
- `autoresearch/tasks/cuda/00-cuda-measurement-contract.md` through
  `09-cairo-sn-pie-subsecond.md`;
- the user-supplied architecture specification captured by that goal.

Performance experimentation is not reopened. Work in this session must remove
an architecture, correctness, measurement, or activation blocker.

## Audit Result

The branch at `2f59c211` contained a substantial first implementation, but it
was not the complete target:

- four Native product routes emitted `ProofProgram`: wide Fibonacci, XOR,
  Plonk, and the seeded-wide Blake example;
- the production runtime was strict AOT, graph-enabled, exact-proof gated,
  zero-fallback, and single-terminal-D2H;
- the process object still owned one session, one physical stream, and one
  prepared shape;
- `CudaPlan` produced lane/dependency metadata that production execution did
  not consume;
- Poseidon and state machine were not product routes;
- RISC-V and Cairo did not emit CUDA programs;
- `core_cuda` remained correctly disabled;
- the stwo-perf runner could not parse the staged CUDA report schema;
- the structural benchmark did not require its 1.3x target, a cold boundary,
  or per-workload Rust-oracle receipts for headline eligibility;
- no locked-host A/A calibration existed;
- retained Nsight Compute evidence was absent.

Calling this state a pooled process service or an activation-ready generic
backend would have been an overclaim.

## Accepted Structural Slices

### Process Ownership

Commit `9167dc18` places a process-wide ownership lease around
`NativeRuntime`. A second independent owner is rejected until the first owner
closes or aborts. This establishes the one-owner invariant without pretending
that the still-missing bounded session pool exists.

### Complete Plan Identity And Multi-Shape Cache

Commit `5d165a1d` upgrades the plan cache identity to bind:

- GPU UUID and SM;
- CUDA driver, runtime, and toolkit versions;
- runtime build, host toolchain, and kernel-pack identities;
- scheduler and graph schema versions;
- graph mode and lane count.

The single prepared arena is replaced by a four-entry LRU. A live proof leases
its entry, so eviction cannot invalidate graph addresses or arena ownership.
Mixed-shape tests cover hit, miss, all-live rejection, LRU eviction, graph
replay, and non-LIFO persistent-allocation release.

No new execution stream was added. Lane concurrency remains blocked on real
dependency-event and saturation evidence.

### Autoresearch And Oracle Gate

Commit `4864ae95` adds fail-closed parsing of
`native_cuda_product_v6` to stwo-perf and adds artifact-bound pinned-Rust
receipts to the structural controller. Headline eligibility now requires:

- judge sampling;
- complete required structural coverage;
- at least 1.3x class-equal portfolio improvement;
- every warm row below its regression ceiling;
- every cold-process row below its separate regression ceiling;
- Rust-oracle acceptance for every workload.

`core_cuda` remains disabled. No calibration or oracle result is fabricated.

## Profiler Evidence

Commit `704df5d0` fixes `stwo-prof cuda compute`: Nsight Compute does not accept
the Nsight Systems-style `--` option terminator before the application.

Commit `c2a3c651` retains the pre-N2B `log20 x 100` Nsight Systems capture,
kernel summary, identities, and receipt under:

`conformance/evidence/cuda/system-architecture-sm89/profiling/`

The capture established that coefficient/evaluation transforms consumed the
majority of device kernel time. It was diagnostic evidence and did not supply
benchmark verdict timing.

Nsight Compute 2025.1.1 was exercised on the same RTX 4090 host. The host
returned `ERR_NVGPUCTRPERM`: hardware performance counters are disabled at the
container boundary. The receipt records this missing capability. No roofline,
bandwidth, occupancy, register, or spill result is claimed.

## Remaining Critical Path

1. Finish and GPU-gate Native state-machine and Poseidon product routes.
2. Replace surrogate class labels with real hash-heavy, lookup-heavy, and
   irregular structural rows.
3. Retain per-family CPU/CUDA/Rust parity receipts.
4. Run the backend-neutral persistent mixed-shape request service on the
   locked CUDA host and retain queue, cache-hit, memory, and oracle evidence.
5. Consume measured `CudaPlan` dependencies with real event/stream scheduling,
   or retain one stream with explicit saturation evidence.
6. Freeze locked-host CUDA A/A calibration and the predecessor anchor.
7. Activate `core_cuda` only through a reviewed evidence-bound manifest change.
8. Complete RISC-V and Cairo `ProofProgram` adapters under their own oracles.

The full goal remains active until those requirements are proven.
