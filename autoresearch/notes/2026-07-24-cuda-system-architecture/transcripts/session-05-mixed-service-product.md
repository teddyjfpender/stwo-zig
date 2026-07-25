# Session 05: Native CUDA Mixed-Service Product

## Delivered Slice

The Native CUDA product now exposes:

```text
stwo-zig-native-cuda sustain \
  --backend cuda \
  --output-dir <proof-directory> \
  --report-out <service-report.json> \
  --cycles <1..4> \
  --execution-mode graphs
```

One process opens one CUDA runtime. Before runtime ownership transfers into the
backend-neutral request service, the product prepares the exact three-shape
working set:

1. wide Fibonacci, `log18 x 37`;
2. Poseidon, `log_n_instances=13`;
3. state machine, `log16`, initial state `(9, 3)`.

The product then submits the deterministic sequence
`wide, poseidon, state_machine` for the requested number of cycles. All requests
execute and publish in ticket order through the service's single physical lane.
No request creates a process, CUDA context, runtime, or independent service.

Each request owns its host prepared plan. The process runtime owns the
fixed-address execution cache and retains all three exact shape keys. The run
fails if any request begins with a cache miss, loses its retained shape,
publishes out of order, or produces a non-sequential runtime proof index.

## Proof And Report Boundary

Every published request:

- executes through the strict-AOT resident driver;
- permits zero CPU fallback attempts or completions;
- performs exactly one terminal proof read;
- decodes canonical proof bytes;
- passes independent Zig verification;
- writes an ordinary native proof-exchange artifact;
- retains the canonical and artifact SHA-256 values;
- requires repeated appearances of the same family/input to be byte exact;
- emits a pinned-Rust-oracle hook binding artifact path, digest, and upstream
  commit.

The `native_cuda_mixed_service_v1` report records runtime initialization, shape
preparation, queue wait, service, resident proof, device critical path,
decoding, verification, teardown, queue high-water marks, shape hits, memory
bounds, proof indices, device identity, launch/synchronization/fallback
counters, aggregate rows, committed cells, and sustained rates.

Cross-AIR MHz is not averaged. The report retains total time and separately
named aggregate trace-row and committed-cell rates.

## Promotion State

The structural workload registry recognizes the staged deterministic service,
but the sustained class remains disabled. Every report explicitly states:

```text
registry_enabled=false
headline_eligible=false
evidence_class=diagnostic_unjudged
```

The blockers are immutable hardware exact-proof evidence and pinned Rust-oracle
receipts for every artifact. Product-local Zig verification is necessary but
does not substitute for the external oracle. The architecture goal's sustained
evidence checkpoint therefore remains open until a locked CUDA host executes
and retains the receipt package.

## Local Gates

The implementation was checked with:

```text
zig test src/products/native_cuda/cli.zig -OReleaseSafe
# 12/12 passed

python3 -m unittest scripts.tests.test_native_cuda_benchmark
# 22/22 passed

python3 -m unittest \
  scripts.tests.test_native_cuda_benchmark \
  scripts.tests.test_cuda_build \
  scripts.tests.test_cuda_product_closure
# 44/44 passed

zig build test-cuda-build-plan
# 37/37 passed

zig build test-cuda-runtime-contract
# passed

zig build test-cuda-adapter -Doptimize=ReleaseSafe
# Rust adapter 3/3 passed

zig build test-stwo-prover -Doptimize=ReleaseSafe
# 181-source prover closure passed

zig build test -Doptimize=ReleaseFast
# 388-source repository closure passed

zig build cuda-source-closure
# passed
```

This Mac cannot link or execute the Linux CUDA product. No hardware timing or
oracle receipt is fabricated from the host-independent gates.
