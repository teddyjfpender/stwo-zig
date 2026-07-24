# Native CUDA Backend Port Goal

## Objective

Deliver a first-class Native Stwo CUDA product in `stwo-zig` by importing the
proven CUDA/C++ implementation from
`teddyjfpender/stwo@1d1d10c31fdac45c9ecb7aee9d3e8935b5cf8035` and driving it
through Zig-owned proof orchestration.

The product is complete only when a CUDA-labelled proof is a GPU-resident proof,
not a CPU proof with isolated CUDA kernels.

## Scope

This goal covers Native Stwo first:

1. Preserve the complete upstream CUDA/C++ and generated AOT source authority.
2. Build it as an isolated CUDA product with an explicit toolkit, host compiler,
   target-SM set, source identity, and archive identity.
3. Expose an exact C ABI to Zig. No Rust runtime is part of the product.
4. Own one CUDA execution context, stream set, memory pool, and device arena for
   the complete proof request.
5. Keep trace data, commitments, quotient work, FRI state, Merkle state,
   transcript state, and proof-opening work resident until their protocol
   lifetimes end.
6. Return only the final proof and authenticated telemetry to the host.

The Cairo witness/AIR integration from
`teddyjfpender/stwo-cairo:generic-backend` is a later product layer. Its
generated sources remain preserved by the exact import, but it must not enlarge
or weaken the Native CUDA product contract.

## Non-Negotiable Architecture

- CUDA has a dedicated product and build closure. CPU and Metal products do not
  discover, configure, compile, or link CUDA.
- CUDA construction fails closed when `nvcc`, the CUDA driver/runtime, a
  supported device, generated AOT modules, or required symbols are absent.
- The proof session is explicit. There is no nullable context, process-default
  execution path, implicit stream, or detached eager compatibility mode in the
  production CLI.
- Device columns are not exposed as host slices.
- A CUDA-labelled run may not call the SIMD prover, download an intermediate
  column for host computation, use a CPU constraint evaluator, or silently
  retry a rejected kernel on the CPU.
- Unsupported protocol features are admission errors before proving starts.
- CUDA and Metal are different implementations. Shared protocol types are
  welcome; shared runtime policy or fallback machinery is not.

## Required Telemetry

Every proof report must bind these counters to the product identity:

- CUDA device UUID, SM, driver, runtime, toolkit, and compiled target set.
- Imported source-closure digest, archive digest, and AOT manifest digest.
- Context, stream, graph, pool, and arena identities.
- Kernel and graph launches by proof stage.
- H2D, D2H, and D2D bytes by proof stage.
- Allocations, frees, reserved bytes, live bytes, and peak live bytes.
- Synchronization calls and their stage boundaries.
- JIT/AOT hits, misses, and compile time.
- CPU fallback attempts and completed CPU fallbacks.

Both fallback counters must be exactly zero. Intermediate D2H traffic must match
an explicit allowlist; proof output and diagnostic counters do not authorize
host-side proving.

## Correctness Gates

1. Source closure: the imported CUDA tree matches `source_manifest.json`.
2. Build closure: every ordinary `.cu` unit compiles, device linking succeeds,
   every generated AOT source produces a cubin, and the linked symbol manifest
   exactly matches the Zig ABI.
3. Operation parity: field, circle transform, commitment, quotient, FRI,
   transcript, PoW, and decommitment differentials match Zig SIMD.
4. Proof parity: Native CPU and Native CUDA produce canonical byte-identical
   proofs for every supported workload and protocol profile.
5. Oracle parity: the pinned Rust Stwo verifier accepts every CUDA proof.
6. Residency: strict telemetry proves zero fallbacks and rejects unallowlisted
   intermediate host traffic.
7. Stability: repeated proofs in one process preserve proof bytes, bounded pool
   growth, and stable graph topology.
8. Isolation: CPU, Metal, and repository structure gates stay bit-for-bit
   unaffected when CUDA is not selected.

No skipped hardware test is release evidence. A non-CUDA host may validate
source, ABI, build-plan, product-isolation, and fail-closed behavior, but cannot
promote the backend.

On a CUDA host, `python3 scripts/cuda_device_smoke.py` compiles and runs the
product-owned differential suite against the exact archive produced by
`python3 scripts/cuda_build.py`. Both commands emit immutable receipts; a
receipt copied from another source closure is invalid.

## Performance Evidence

The first benchmark matrix must include Native wide Fibonacci at logs 14, 16,
18, 20, and 22 plus representative narrow, wide, and deep workloads. Report:

- cold process time;
- warm verified-request time;
- proof-only device time;
- MHz or committed-cell throughput, with the denominator stated;
- peak host RSS and device memory;
- transfer and synchronization totals;
- exact proof identity;
- CUDA and Zig CPU results on the same host.

Starknet PIE and Cairo benchmarks follow only after the Native product earns all
correctness and residency gates.

## Delivery Checkpoints

- [x] Pin and import the exact upstream CUDA/C++ source authority.
- [x] Land the deterministic CUDA source/build identity and source gate.
- [x] Define the typed, shape-checked Zig ABI for every resident proof stage.
- [x] Build the static CUDA archive and Native generated AOT pack directly.
- [x] Implement the Zig execution context, isolated pool, lifetime-aware arena,
      strict AOT loader, stage admission, and residency telemetry owners.
- [x] Replace every staged legacy ABI implementation with a small product-owned
      Native unit and pass its real-device differential.
- [x] Implement the resident Native proof transaction from ingress through the
      single final proof read.
- [x] Enable the isolated `stwo-native-cuda` product and CLI.
- [x] Pass local non-CUDA isolation, source-conformance, closure, and fail-closed
      contract gates.
- [x] Pass real-device ABI, operation, proof, oracle, and residency gates.
- [x] Pass the repeated-process proof/topology/pool-stability gate.
- [ ] Publish a persistent-session warm-request benchmark. Repeated one-shot
      transactions in one process are not a substitute.
- [ ] Publish the first judged CUDA benchmark evidence.

## Current Evidence

As of 2026-07-24, the Native CUDA MVP is a complete resident prover. Pinned
Rust/CUDA files remain immutable algorithm and oracle authority; the executable
archive contains zero imported authority objects and is owned under
`src/backends/cuda/native/`.

The clean SM 89 build contains 22 product-owned Native CUDA objects, one
product-owned host object, one Native AOT cubin, and 68 active ABI symbols with
zero staged symbols. All 12 real-device differentials pass on an RTX 4090.
They cover the execution context, platform identity, trace generation,
transforms, domain-prefixed Blake2s commitments, composition split, OODS,
quotient, FRI, PoW, transcript, and canonical decommitment assembly.

The end-to-end `log_n_rows=5`, `sequence_len=8` proof establishes:

- one strict-AOT CUDA transaction from ingress through proof assembly;
- one terminal D2H proof read and no intermediate D2H reads;
- zero CPU fallback attempts and zero completed CPU fallbacks;
- exact canonical equality with the Zig Native CPU proof;
- successful independent Zig verification;
- successful verification by pinned Rust Stwo
  `a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2`;
- three same-process CUDA transactions with byte-identical proofs, identical
  launch topology, and zero final pool usage;
- 8,390 canonical proof bytes with SHA-256
  `452fb396032380b7c031fc95f0b7c00d0a3c6e05622321f84f06cb3a801e3b2c`.

The hardware gate found and corrected three copied-contract defects before
activation: coefficient log sizes were consumed as coefficient counts, CUDA
commitments omitted Stwo's leaf/node domain prefixes, and decommitment read
leaf-to-root descriptors as root-to-leaf. The product build now also tracks
every `.cu`, `.cuh`, host, AOT, and builder-script input explicitly; isolated
cache tests prove source/header changes invalidate the archive while unchanged
builds reuse it.

Initial ReleaseFast performance is diagnostic cold-process evidence, not a
judged promotion. On one RTX 4090 with a 16-core AMD EPYC 7282 host, seven
independent width-100 processes produced these median resident times:

| log rows | trace rows | CUDA resident | trace-row MHz | committed Mcells/s |
| ---: | ---: | ---: | ---: | ---: |
| 14 | 16,384 | 209.941 ms | 0.078 | 7.80 |
| 16 | 65,536 | 212.251 ms | 0.309 | 30.88 |
| 18 | 262,144 | 236.212 ms | 1.110 | 110.98 |
| 20 | 1,048,576 | 336.886 ms | 3.113 | 311.26 |
| 22 | 4,194,304 | 790.369 ms | 5.307 | 530.68 |

The same-host Zig SIMD screen reached a median 8.110 seconds of prove time at
log 22, so the large width-100 diagnostic is about 10.3x faster on CUDA.
Small cells remain dominated by roughly 210 ms of per-process setup. The
largest admitted saturation point, log 22 by 128 columns, completed in
905.045 ms and processed 536,870,912 committed cells at 593.20 million
cells/second.

These measurements do not establish CUDA-over-Metal superiority: the current
M5 Metal diagnostic is faster at the inherited width-100 log-22 shape, and the
hosts differ. The remaining performance boundary is explicit: the CUDA CLI is
still one proof transaction per process, reports zero graph launches, and
launches hundreds of kernels for large proofs. Persistent context/session
reuse, graph capture, and a same-host judged CPU/CUDA matrix are follow-up
requirements, not facts inferred from the cold screen.
