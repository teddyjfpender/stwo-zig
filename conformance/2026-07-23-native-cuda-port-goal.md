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
- [ ] Replace the legacy Zig FFI with the exact imported ABI.
- [ ] Build the static CUDA archive and copied generated AOT pack directly.
- [ ] Implement the Zig execution context, pool, arena, and telemetry owners.
- [ ] Implement the resident Native proof session and stage admission.
- [ ] Enable the isolated `stwo-native-cuda` product and CLI.
- [ ] Pass local non-CUDA isolation and fail-closed gates.
- [ ] Pass real-device ABI, operation, proof, oracle, residency, and stability
      gates.
- [ ] Publish the first judged CUDA benchmark evidence.
