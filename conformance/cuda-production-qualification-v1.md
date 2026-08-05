# CUDA production qualification v1

**Status:** active contract; NVIDIA admission pending

This document separates repository correctness, Apple-Silicon development
evidence, and NVIDIA product qualification. Passing a lower tier cannot be
reported as passing a higher tier.

## Frontend catalog contract

`src/backends/cuda/aot/native/product_sets.json` is the canonical frontend-to-
AOT mapping. The builder accepts exactly the catalogued set for the named
frontend; it rejects arbitrary subsets, cross-frontend mixing, unavailable
frontends, duplicate cache keys, stale manifests, or source identity drift.

| Frontend | AOT sets | Current CUDA state |
| :--- | :--- | :--- |
| Native | `.` | Staged |
| Cairo | `.`, `cairo_eval` | Staged |
| RISC-V | none | Unavailable: no parity-gated adapter |
| SM83 | none | Unavailable: no product descriptor |

Each available frontend must own statement binding and authenticated trace and
constraint programs. The backend owns residency, PCS stages, scheduling,
telemetry, AOT loading, and teardown. A new frontend is admitted by extending
this catalog and supplying its integration and parity gates; it must not reuse
another frontend's archive implicitly.

## Tier 1: repository-local gates

These gates do not require CUDA hardware:

```sh
zig build cuda-source-closure cuda-cumetal-ledger cuda-build-plan \
  test-cuda-build-plan test-cuda-runtime-contract \
  -Doptimize=ReleaseFast -j2
```

They authenticate the 28-file active authority, product-source disposition,
ABI symbol pin, cache-generated Native AOT, complete 33-source CuMetal ledger,
frontend catalog, runtime ownership, and fail-closed loader contracts. They do
not establish device correctness.

## Tier 2: CuMetal development evidence

CuMetal is optional and macOS-only. The checked ledger is pinned to CuMetal
0.1.3 commit `e88dd103bddaff9a134913dec4bd8439817d160c`.

```sh
zig build cuda-cumetal-ledger
zig build cuda-cumetal-portability \
  -Dcuda-cumetalc=/absolute/path/to/cumetalc \
  -Dcuda-cumetal-root=/absolute/path/to/cuda-metal
zig build cuda-cumetal-audit \
  -Dcuda-cumetalc=/absolute/path/to/cumetalc \
  -Dcuda-cumetal-root=/absolute/path/to/cuda-metal \
  -Dcuda-air-inspect=/absolute/path/to/air_inspect \
  -Dcuda-air-validate=/absolute/path/to/air_validate
```

The authenticated compatibility patch raises the floor to all 33 maintained
translation units. The full audit ratchets every outcome and runs
`constraints/powers.cu` on the Apple GPU against an independent host QM31
oracle. A passing receipt requires the numerical marker and runtime provenance
containing both `device=apple_gpu` and `launch_success=true`; CPU fallback and
stubs are rejected.

Native additionally has an end-to-end local gate:

```sh
zig build run-native-cumetal-smoke \
  -Dcuda-cumetal-clang=/absolute/path/to/clang \
  -Dcuda-cumetalc=/absolute/path/to/cumetalc \
  -Dcuda-cumetal-root=/absolute/path/to/cuda-metal \
  -Dcuda-cumetal-library=/absolute/path/to/libcumetal.dylib \
  -Dcuda-air-inspect=/absolute/path/to/air_inspect \
  -Dcuda-air-validate=/absolute/path/to/air_validate
```

It builds the 33-unit runtime, six-source selected authority closure, one host
loader, and 15 strict Native AOT entries. Exact source-native Metal modules
provide PoW search and decommitment query normalization where CuMetal 0.1.3
cannot faithfully lower the PTX. The gate constructs the complete resident
wide-Fibonacci proof, asserts zero fallback, and independently verifies it in
Zig.

This tier provides early compiler-compatibility and numerical evidence. It is
not evidence about NVIDIA occupancy, memory ordering, graph behavior,
performance, or production readiness.

## Tier 3: NVIDIA admission

CUDA products remain staged until an explicitly provisioned Linux/NVIDIA lane
records all of the following for every supported SM and frontend:

1. exact NVCC, host compiler, CUDA toolkit, driver, GPU UUID, and SM identity;
2. successful archive and strict-AOT construction from cache-generated sources;
3. device smoke coverage for allocation, transfer, launch, AOT lookup, and
   teardown failures;
4. repeated deterministic proofs accepted by the independent verifier;
5. CPU/NVIDIA proof parity for each admitted frontend and representative AIR;
6. zero fallback, complete transfer/launch accounting, and expected residency;
7. graph/direct execution parity where both modes are exposed; and
8. benchmark receipts clearly labelled as NVIDIA results.

Native and Cairo require separate receipts because their catalogues and
statement bindings differ. RISC-V and SM83 cannot enter this tier until their
catalog status changes from unavailable and their independent parity gates
exist.

The current production verdict is therefore: repository architecture, AOT
generation, 33-source CuMetal compatibility, and one complete Native
wide-Fibonacci proof/verification path are locally qualified on Apple Silicon.
Cairo and RISC-V CuMetal execution remain explicit TODOs and fail closed.
NVIDIA product admission is pending fresh hardware evidence.
