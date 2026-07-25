# Session 11: SN2 constraint AOT product packaging

Date: 2026-07-25

## Scope

This increment converts the backend-neutral Cairo evaluation-program traversal
and unfused CUDA emitter into a deterministic offline product inventory for the
exact `vectors/cairo/sn_pie_2_composition.bin` bundle.

It does **not** establish CUDA constraint parity or an SN PIE proof. It packages
the kernels required for the next device differential without using runtime
compilation.

## Exact inventory

- Components: 58
- Constraint placements: 279
- Constraints: 1,325
- Exact program identities: 278
- Deduplicated emitted CUDA bodies: 271
- Distinct component-source identities: 58
- Body-source bytes: 6,549,162
- Manifest SHA-256:
  `06c0d3adb44e015bcd1e2ff62e5e54f82c13d8cee5f6dc3e2db5cd8ab782c916`
- Ordered source-closure SHA-256:
  `222206e3531ebdc766fa17f05d4dfb6f9dd8c87feb6f342db3f9d002a9e80afd`

Four emitted bodies are reused: two occur twice and two occur four times.
Deduplication is by exact emitted source SHA-256, not by component name or an
assumption that repeated semantic hashes have identical placement semantics.

## Authenticated identities

Each placement records:

- component index and label;
- component instance and part index;
- local and global random-coefficient base;
- random-coefficient count;
- trace, evaluation, and program domain log sizes;
- SHA-256 of the exact backend-neutral program encoding;
- SHA-256 of the component source contract.

The component source identity covers every trace span, preprocessed-column
index, denominator inverse, extended-parameter source, and relevant component
domain/count field. Program identity covers all header fields, constants,
base instructions, extension instructions, and constraint roots with explicit
little-endian encoding.

Each deduplicated body records:

- the compact semantic hash and deterministic kernel symbol;
- emitted CUDA source SHA-256;
- an ordered program-set SHA-256;
- an occurrence-catalog SHA-256;
- CUDA codegen version 1;
- a cache key derived from all three SHA-256 identities and the codegen
  version;
- ABI schema `cairo_eval_part_v1` (numeric schema 22);
- explicit `module_globals = none`.

The offline CUDA builder reads the hand-owned Native AOT set and the generated
`cairo_eval` set through
`src/backends/cuda/aot/native/product_sets.json`. With two requested SM
targets, the build plan contains 319 sources and 638 cubins: 48 existing
Native sources plus 271 Cairo evaluation bodies.

## Reproducibility and host gates

The Zig product test regenerates all 271 sources and the complete manifest
from the pinned composition bundle, then compares every byte with the
checked-in product. Python validation independently recomputes source,
catalog, program-set, kernel, label, and cache identities and rejects source,
placement, or exact-program drift.

Passed:

- `zig build test`
- `zig build source-conformance`
- `zig build test-cuda-build-plan`
- `zig build test-cuda-runtime-contract`
- `python3 -m unittest scripts.tests.test_cuda_cairo_eval_aot`
- `python3 -m unittest scripts.tests.test_cuda_aot_identity`
- `python3 -m unittest scripts.tests.test_cuda_build`
- `python3 scripts/cuda_product_closure.py`

## Evidence boundary and next gate

This session proves source generation, product coverage, identity binding,
offline build-plan inclusion, and deterministic reproduction. It does not
prove that all 271 sources compile with NVCC, that any generated body launches,
or that its arithmetic agrees with Zig SIMD.

The next mandatory gate is a real-device, strict-AOT differential:

1. Compile the declared set for the target SM without NVRTC or source JIT.
2. Resolve every placement through its authenticated cache key and kernel
   name.
3. Launch each part in canonical component/part order with the recorded source
   and random-coefficient bindings.
4. Compare the four-coordinate cumulative accumulator with Zig SIMD after
   every one of the 279 placements.
5. Require zero missing entries, zero runtime compiles, zero CPU fallbacks,
   and an authenticated AOT receipt.

Only that gate may claim per-part or cumulative constraint parity.
