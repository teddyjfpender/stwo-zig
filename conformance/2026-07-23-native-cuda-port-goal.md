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
- [ ] Implement the resident Native proof transaction from ingress through the
      single final proof read.
- [ ] Enable the isolated `stwo-native-cuda` product and CLI.
- [x] Pass local non-CUDA isolation, source-conformance, closure, and fail-closed
      contract gates.
- [ ] Pass real-device ABI, operation, proof, oracle, residency, and stability
      gates.
- [ ] Publish the first judged CUDA benchmark evidence.

## Current Evidence

As of 2026-07-23, the product archive contains no imported CUDA translation
units. Pinned Rust/CUDA files are immutable algorithm and oracle authority only;
the executable closure is product-owned under `src/backends/cuda/native/`.

Real-device evidence currently covers:

- one proof-owned nonblocking stream and isolated async memory pool;
- generation-bound live-allocation validation for every device capability;
- resident wide-Fibonacci trace construction at a non-target width of 37;
- strict Native AOT constraint loading and launch with an exact expected
  accumulator;
- progressive Blake2s commitments across widths 1, 15, 16, 17, 31, 32, and
  33;
- ordinary Merkle layers, four-level fused reduction, and both supported FRI
  leaf layouts;
- complete-range alias rejection for Merkle reductions;
- an eight-operation resident Blake2s Fiat-Shamir transcript including secure,
  raw, query, boundary-state, seeded-state, and nonzero PoW vectors;
- retained B2N, in-place N2B, full LDE, and pre-circle LDE over padded
  contiguous slabs at logs 3, 8, 9, 10, and 13, including width 37;
- OODS point derivation, staged coefficient evaluation, reduction, scatter,
  barycentric weights, and multi-column evaluation with prepared unique index
  maps and explicit capacity bounds;
- every element of the 1024-value OODS batch-inverse tree, after its copied
  final-pair indexing defect was found and corrected by the hardware gate.

The exact clean rebuild contains zero imported authority objects, 21
product-owned Native CUDA objects, one product-owned host object, and one
Native AOT cubin. Eleven independent real-device differentials pass on SM 89.
The active product manifest binds 66 ABI symbols and has no staged symbols.

The progressive Blake2s hot path has zero per-thread stack and zero compiler
spills on SM 89. It uses 56 registers for absorb and 48 for finalize. This
resource result is evidence for the copied scalar-state design; it is not a
proof-performance claim.

The backend is not yet a prover. The resident stage implementations and
single-read proof-bundle ABI are present, but the full executor still requires
the composition split, canonical transcript schedule and proof decoder before
it can establish canonical proof parity, Rust-oracle acceptance,
repeated-session stability, product activation, and judged benchmarks.
