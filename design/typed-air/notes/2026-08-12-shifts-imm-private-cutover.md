# SHIFTS_IMM private fixed-authority readiness

Date: 2026-08-12

Status: private admission complete; atomic production integration in progress

## Result

SLLI, SRLI, and SRAI have one authenticated, allocation-free executable
authority for five-bit shift semantics, arithmetic sign extension, x0 result
visibility, physical witness generation, all 67 direct roots, and all 16
ordered relation events. Register and immediate shifts consume the same fixed
65-root scalar kernel, preventing two optimized production transcriptions from
drifting. The pointer-free, source-location-independent binding is pinned by
SHA-256:

`444d3dfa289bac646a6330087980af2726f30dd78bba2b891b511b2fcd9b980a`

The authority retains the existing protocol geometry exactly:

- 51 main columns;
- 66 semantic roots plus one placement root;
- 16 relation events in batches of two;
- eight interaction columns;
- opcode identifiers 16 (SLLI), 17 (SRLI), and 18 (SRAI).

## Correctness admission

The private gate establishes:

- symbolic identity with the independent handwritten evaluator for every
  direct root, placement root, numerator, tuple field, relation domain, role,
  arity, access ordinal, ordering position, and batch size;
- rejection of forged semantic roots, range-refinement evidence, authority
  bindings, and malformed rows before any destination write;
- all three directions, all 32 amounts, zero and 31 boundaries, signed extrema,
  x0 reads and writes, and source/destination aliasing;
- exhaustive admission of all 98,304 legal SLLI/SRLI/SRAI register and amount
  encodings, plus all 8,192 relevant funct7/amount combinations so illegal
  upper immediate encodings fail closed;
- exact equality between the compact two-access compiler and the generic
  access-transaction oracle;
- rejection of forged, stale, and reused retirement plans before publication;
- exhaustive cold-construction allocation-failure cleanup, cold retirement
  failure atomicity, and an allocation-free pre-reserved warm path.

The proof-level typed-versus-legacy A/B test now requires live agreement from
the pinned Sail oracle; it cannot report a production receipt from a fallback
model. The ReleaseSafe proof receipt is 57,802 bytes with proof SHA-256
`899af87adeed04a0d27d61c478e22d863cc042a4e76f33eb6f450efd21618660`,
transcript digest
`c9fe8662566356756947e76fa4799287e39f5cd47ccd4d3968ae9c820cff5406`,
and one transcript draw.

The private root passes 220 tests in Debug, ReleaseSafe, and ReleaseFast.

## Performance admission

The performance receipt consumes every QM31 coordinate of every direct root and
lookup tuple. This caught a real instruction-cache regression hidden by the
older first-coordinate checksum: forced unrolling of the 65-root shared kernel
measured only 0.82-0.85x legacy throughput. Removing forced inlining and
unrolling from that large kernel restored stable parity while retaining the
fixed, allocation-free program.

Serial, paired, interleaved ReleaseFast medians measured:

- fixed direct evaluation: 0.9949-1.0006x legacy throughput;
- fixed ordered-lookup construction: 2.7542-2.7830x legacy throughput;
- fixed failure-atomic retirement: 1.2467x legacy throughput.

Every gate rejects throughput below 0.97x legacy. The runtime footprints are
64 bytes for the compact transaction, 80 bytes for the immutable plan, and 16
bytes for the single-use prepared token, with explicit one-word growth budgets
on the first two types.
The retained pointer-free authority is pinned to 280 bytes, including its
248-byte authenticated binding.

## Production boundary

The handwritten semantic evaluator now lives at the explicit
`shifts_imm_legacy_test_oracle.zig` path. A short compatibility shim preserves
the shared tree until LT_REG and both shift families cross the production
registries atomically; that shim must be deleted in the integration batch.
Production closure then requires aggregate Debug, ReleaseSafe, and ReleaseFast
AIR and runner suites, exact proof/transcript A/B, the full shared rigidity
corpus, formal extraction, and live Sail agreement.
