# CUDA System Architecture Delivery Goal

Status: active
Authority: this document, `CONTRIBUTING.md`, and `autoresearch/MANIFEST.json`
Scope: generic stwo-zig proving on authenticated NVIDIA CUDA devices
Correctness oracle: pinned Rust Stwo is the final Native proof authority

## Goal

Deliver CUDA as a generic, process-resident proving backend rather than a
wide-Fibonacci product experiment. Native, RISC-V, and Cairo frontends must
eventually emit one backend-neutral proof program. CUDA compiles that program
into a device-specific plan and executes it through one process-owned runtime:

```text
Native / RISC-V / Cairo
          |
     ProofProgram
 AIR + trace + PCS + transcript DAG
          |
       CudaPlan
 schedule + arenas + lifetimes + modules
          |
      CudaRuntime
 device + streams + caches + bounded sessions
          |
 authenticated per-SM CUDA modules
```

The architecture is complete only when CUDA improvements are measurable across
structural classes, proof bytes remain exact, the Rust oracle accepts the
result, no CPU fallback occurs, and production requests perform no compilation.

## Non-goals

- Optimizing only wide Fibonacci or one log size.
- Calling a CPU prover from a CUDA-labelled product.
- Treating a kernel microbenchmark or profiler replay as a proof-speed verdict.
- Enabling streams or graphs without dependency and saturation evidence.
- Using NVRTC, PTX JIT, or driver fallback in a judged production run.
- Activating CUDA autoresearch before broad Native AIR coverage and calibration.
- Hiding startup, verification, teardown, allocation, or transfer costs.

## Present Baseline

The first architecture slice has landed on
`feature/cuda-system-architecture`:

- CUDA stage events and optional NVTX ranges cover every proof stage.
- `stwo-prof cuda` exposes capability, Nsight Systems, Nsight Compute, and
  product-report attribution commands.
- `CudaRuntime` owns the CUDA device, module cache, event resources, and
  repeated proof lifecycle for a process.
- `ProofProgram` describes the Native wide-Fibonacci statement without
  backend-specific execution calls.
- `CudaPlan` compiles program identity, arena requirements, schedule order,
  barriers, work estimates, and a device/toolchain/kernel-pack-bound cache key.
- A prepared shape is compiled once and retained across process repetitions.
- `scripts/native_cuda_benchmark.py` separates cold process, runtime
  initialization, shape preparation, first request, warmups, steady verified
  requests, independent verification, and teardown.

Diagnostic RTX 4090 evidence after retained plan compilation:

| shape | steady resident proof | row rate | committed-cell rate |
| --- | ---: | ---: | ---: |
| `log20 x 100` | about 73.7 ms | about 14.2 MHz | about 1.42 billion/s |
| `log18 x 37` | about 8.8 ms verified | about 33.2 MHz resident | about 1.23 billion/s |

At `log20 x 100`, device time and resident wall time are now nearly equal.
Trace commitment consumes about 83% of device time. The remaining primary
problem is therefore commitment/Merkle memory traffic and launch topology, not
host plan construction. These numbers are diagnostics, not a judged promotion.

## Required Components

### 1. ProofProgram

`ProofProgram` is immutable and backend-neutral. It must describe:

- public statement, protocol, AIR, and implementation identities;
- component and trace-column geometry;
- constraint programs and evaluation domains;
- commitment trees and openings that remain live;
- transcript absorptions, barriers, challenges, and challenge consumers;
- quotient chunks and FRI rounds;
- buffer sizes, alignment, mutability, and lifetime intervals;
- dependency-DAG nodes and estimated logical work.

Rules:

- Frontends emit semantics; they do not schedule CUDA kernels.
- Validation rejects dangling identities, invalid lifetimes, overflow, cycles,
  challenge use before derivation, and protocol-inconsistent shapes.
- The digest covers every field that can affect proof semantics or execution.
- Native CPU and Metal may consume the same representation incrementally, but
  CUDA delivery must not require them to migrate atomically.

### 2. CudaPlan

`CudaPlan` compiles one valid program for one production runtime identity:

- arena offsets, alignment, alias sets, and peak accounted bytes;
- persistent, shape-local, request-local, and terminal-host resources;
- topological execution schedule and transcript joins;
- kernel variants, grid/block geometry, and dynamic shared memory;
- coordination and lane-stream assignment;
- graph-capture regions and updateable request parameters;
- predicted bytes, global passes, launches, graph launches, and barriers.

Its cache key binds:

- complete `ProofProgram` digest;
- protocol and statement geometry;
- GPU UUID and SM capability;
- CUDA driver/runtime compatibility contract;
- CUDA toolkit and host toolchain identity;
- authenticated kernel-pack digest;
- scheduler version and graph schema version.

The plan cache is bounded. Eviction cannot invalidate a live proof. Cache hits,
misses, preparation time, and reuse count are report fields.

### 3. CudaRuntime

One runtime owns one visible GPU for the process:

- primary context and immutable device identity;
- authenticated module registry;
- memory and event pools;
- twiddle, domain, immutable table, and prepared-plan caches;
- one coordination stream plus measured lane streams;
- graph executable cache;
- per-SM kernel variants;
- bounded proof-session admission.

Rules:

- No frontend or AIR names appear in the runtime.
- No module load, context creation, toolkit discovery, or compilation occurs
  inside a warm proving request.
- Every allocation has one owner and one last-use event.
- Request failure unwinds live resources without destroying reusable runtime
  state or concealing a device error.
- Multi-proof concurrency is admitted only when one proof leaves measured GPU
  capacity and the total in-flight memory remains within policy.

### 4. Authenticated Code

Production uses AOT code:

- stable primitives ship in authenticated, per-SM cubin packs;
- released Native, RISC-V, and Cairo programs ship in authenticated packs;
- modules load once per process;
- missing exact production support fails closed;
- PTX compatibility is labelled, separate, and ineligible for judged results;
- NVRTC is a research/onboarding tool outside the proving request.

The product report binds module, runtime, source closure, toolkit, host
toolchain, device, and product identities. A dirty or compatibility build can
run diagnostics but cannot produce headline evidence.

## Execution Rules

The scheduler derives concurrency from the proof DAG and profiler evidence:

1. Use one coordination stream for transcript-visible ordering.
2. Run independent trace and commitment components on lane streams when their
   kernels do not already saturate the GPU.
3. Join only at true root, challenge, quotient, or output dependencies.
4. Partition quotient work and independent Merkle subtrees where evidence
   shows useful overlap.
5. Preserve sequential FRI-round dependencies while parallelizing within a
   round.
6. Perform no intermediate D2H operation and exactly one terminal proof read.
7. Replace stable launch sequences with CUDA graphs only after byte-exact
   direct execution is retained as a differential path.

The plan must state why each stream, event, wait, and graph boundary exists.
More streams and more graphs are not objectives. Lower verified request time
with exact work is the objective.

## Structural Benchmark Contract

CUDA is measured over these classes:

| class | minimum required coverage |
| --- | --- |
| latency | cold process, runtime miss, shape miss, shape hit, steady small proof |
| narrow/deep | high row count and few columns |
| wide | widths 32, 100, 37, 73, and 128 |
| hash-heavy | Native Blake and Poseidon |
| lookup-heavy | Native Plonk/LogUp and range-check structure |
| irregular | state machine and nonuniform multi-component trace |
| VM | RISC-V ALU, memory, branch, SHA, and Keccak portfolios |
| extreme | admitted log20-log22 memory-saturating proofs |
| sustained | randomized mixed-shape queue with bounded in-flight sessions |

Every row records:

- immutable source, binary, module, toolchain, protocol, statement, and device
  identity;
- cold process, runtime initialization, shape preparation, first request,
  steady resident proof, decode, independent verification, verified request,
  and teardown time;
- stage GPU critical path and final proof-device time;
- row MHz, committed-cell throughput, constraint work, and hash work;
- kernel and graph launches, launch gaps, overlap, and synchronization count;
- H2D, D2H, D2D, DRAM, and L2 bytes where available;
- occupancy, register pressure, spills, achieved bandwidth, and dominant
  kernel roofline evidence;
- host CPU, RSS, device allocation high-water mark, pool state, energy, power,
  and thermal state where available;
- canonical proof digest/size, Zig verification, Rust-oracle result, repetition
  determinism, and fallback counters.

Nsight Systems diagnoses gaps, synchronization, overlap, allocation, and module
loading first. Nsight Compute profiles only dominant kernels. Instrumented
captures never supply the uninstrumented verdict time.

## Statistical And Scoring Contract

- Candidate and predecessor use immutable optimized binaries on the same GPU.
- Warm verdicts use at least ten warmups and seven counterbalanced ABBA rounds.
- Ratios are paired at the round level.
- Each workload has a `candidate / predecessor <= 1.05` regression ceiling.
- Portfolio weight is equal per structural class, then geometric within class.
- Confidence intervals use deterministic round bootstrap.
- Cold-process and verified-request boundaries are separate verdict dimensions.
- Missing samples, timeouts, proof drift, device drift, fallback, or telemetry
  loss fail closed.
- A single extreme canary cannot dominate the portfolio.

## Correctness Gates

Every admitted program and optimization must pass:

1. exact repeatability across repeated CUDA proofs;
2. exact Native CPU/CUDA canonical proof bytes where the protocol permits;
3. independent Zig verification;
4. pinned Rust Stwo verification as the final Native correctness oracle;
5. transcript/challenge parity;
6. CPU/CUDA differential intermediate tests for changed algorithms;
7. controlled statement, commitment, transcript, and proof mutation rejection;
8. zero CPU fallback attempts and completions;
9. exactly one terminal D2H operation;
10. zero leaked live arena bytes after each proof and after teardown;
11. allocation-failure and device-error unwind tests;
12. exact AOT admission with zero JIT misses.

RISC-V additionally uses the pinned Stark-V oracle. Cairo additionally uses the
pinned Rust stwo-cairo implementation. Neither frontend may weaken the Native
PCS or transcript gates.

## Autoresearch Activation Gate

`core_cuda` starts disabled and promotion-ineligible. A reviewed governance
change may enable it only when one frozen evidence package proves:

- all six Native AIR families are generic `ProofProgram` emitters:
  wide Fibonacci, Blake, Poseidon, Plonk/LogUp, state machine, and XOR;
- every scored CPU/CUDA proof is byte-identical and Rust-oracle accepted;
- production reports show exact authenticated AOT and zero fallback;
- complete lifecycle and stage telemetry passes schema validation;
- the structural controller covers latency, narrow/deep, wide, hash-heavy,
  lookup-heavy, irregular, and extreme classes;
- A/A dispersion is frozen on the designated locked CUDA judge host;
- CUDA source paths are the only new editable surface;
- the benchmark binary, board adapter, runner parser, verdict schema, feed,
  ledger epoch, and activation receipt are tested together.

VM and sustained coverage may remain separately disabled only if the Native
board neither claims them nor scores them. They become mandatory before a
generic CUDA backend release.

## Performance Contract

Minimum accepted system result:

- at least 1.3x class-equal portfolio speedup;
- no workload regression beyond its CI-bound ceiling;
- no new CPU fallback, compilation, intermediate D2H, or unaccounted memory.

Primary objective:

- at least 2x class-equal portfolio speedup;
- at least 20 row-MHz and 2 billion committed cells/s for saturating geometry;
- `log22 x 100 <= 210 ms` as a canary, not as the portfolio score;
- lower or equal accounted peak memory;
- improved or neutral cold startup and sustained throughput.

## Ordered Delivery

The detailed tasks are in `autoresearch/tasks/cuda/`:

1. measurement contract;
2. persistent runtime;
3. generic proof program;
4. scheduler and graphs;
5. memory-pass reduction;
6. Native AIR coverage;
7. autoresearch activation;
8. RISC-V adapter;
9. Cairo adapter;
10. sub-second SN PIE proving.

Tasks 1-3 have an implemented first slice. They remain subject to broader AIR
and adversarial validation. Task 4 begins with the measured commitment/Merkle
hot path; it must not add concurrency speculatively.

The 2026-07-24 priority update moves tasks 9 and 10 directly after Native
architecture closure. RISC-V CUDA remains required for generic backend release,
but it does not block the next Cairo/SN PIE performance phase.

## Completion Checklist

- [x] Stage event and lifecycle report contract.
- [x] `stwo-prof cuda` diagnostic entry points.
- [x] Process-owned runtime and repeated proof session.
- [x] Backend-neutral first `ProofProgram`.
- [x] Cache-keyed first `CudaPlan`.
- [x] Retained per-shape plan and structural benchmark controller.
- [ ] Nsight Systems trace with launch-gap and overlap evidence.
- [ ] Nsight Compute evidence for dominant commitment kernels.
- [ ] Pass-reduced commitment/Merkle implementation.
- [ ] Evidence-derived lane scheduler and graph regions.
- [ ] Six Native AIR emitters and exact oracle parity.
- [ ] Frozen locked-host A/A and predecessor baseline.
- [ ] Reviewed `core_cuda` activation.
- [ ] RISC-V generic CUDA adapter.
- [ ] Cairo generic CUDA adapter.
- [ ] Four canonical SN PIEs below one second at the verified-request boundary.
- [ ] Sustained mixed-shape service evidence.

## Primary References

- [CUDA platform compatibility](https://docs.nvidia.com/cuda/cuda-programming-guide/01-introduction/cuda-platform.html)
- [CUDA Graphs](https://docs.nvidia.com/cuda/cuda-programming-guide/04-special-topics/cuda-graphs.html)
- [NVRTC](https://docs.nvidia.com/cuda/nvrtc/)
- [Nsight Systems](https://docs.nvidia.com/nsight-systems/UserGuide/)
- [Nsight Compute](https://docs.nvidia.com/nsight-compute/ProfilingGuide/)
