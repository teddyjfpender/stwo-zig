# SHIFTS_REG private fixed-authority readiness

Date: 2026-08-12

Status: private admission complete; atomic production integration in progress

## Result

SLL, SRL, and SRA now have one authenticated, allocation-free executable
authority for architectural low-five-bit shifting, arithmetic sign extension,
x0 visibility, physical witness generation, all 70 direct roots, and all 20
ordered relation events. The authority shares the exact fixed 65-root shift
core with SHIFTS_IMM so the two families cannot acquire divergent hot-path
transcriptions. Its pointer-free, source-location-independent binding is pinned
by SHA-256:

`c587bc538b1dd084a260a1b359caeb6e4ca26c4e2625000ffee2ca7ffeb43409`

The fixed evaluator retains the existing protocol geometry exactly:

- 60 main columns;
- 69 semantic roots plus one placement root;
- 20 relation events in batches of two;
- ten interaction columns;
- opcode identifiers 2 (SLL), 6 (SRL), and 7 (SRA).

## Correctness admission

The private gate establishes:

- exact symbolic identity with the independent legacy evaluator for every
  direct root, placement root, numerator, tuple field, relation domain, role,
  arity, access ordinal, ordering position, and batch size;
- zero new symbolic DAG nodes when the fixed authority is evaluated after the
  legacy program, proving construction identity rather than sampled equality;
- randomized QM31 equality over arbitrary secure-field rows;
- all three opcodes, all 32 effective shift amounts, high ignored shift bits,
  logical and arithmetic extrema, x0, and every source/destination alias form;
- exhaustive decoding of all 98,304 architectural SLL/SRL/SRA R-type register
  encodings;
- atomic rejection of malformed bindings and invalid trace rows;
- exact equality between the compact three-access compiler and the generic
  access-transaction oracle;
- rejection of forged, stale, and reused retirement plans before publication;
- exhaustive cold-construction allocation-failure cleanup, cold retirement
  failure atomicity, and an allocation-free pre-reserved warm path.

The private root passes 217 tests in both Debug and ReleaseSafe and 220 tests
in ReleaseFast. The
proof-level typed-versus-legacy A/B test now also requires live agreement from
the pinned Sail oracle; a fallback model cannot produce a production receipt.
The ReleaseSafe proof receipt is 58,094 bytes with proof SHA-256
`1888a7d8af0b3ffe477a8a50bf21c01901ddee4986bc75b94c4d6a91dc3ce2f8`,
transcript digest
`7c6d116c910308dc3534f33cf016d3d741462a070038e2e925015f1c06801fbb`,
and one transcript draw.

## Performance admission

The strengthened performance receipt consumes every QM31 coordinate of every
direct root and lookup tuple. It exposed a real instruction-cache regression
from force-inlining and unrolling the 65-root shared shift kernel; allowing the
optimizer to retain compact loops restored direct-path parity. Serial, paired,
interleaved ReleaseFast medians measured:

- fixed direct evaluation: 33,721,166 ns versus 33,672,084 ns, or 0.9985x;
- fixed ordered-lookup construction: 6,943,292 ns versus 14,121,625 ns, or
  2.0339x;
- fixed retirement: 148,792 ns versus 204,333 ns, or 1.3733x.

Both gates require at least 0.97x legacy throughput. The pointer-free runtime
footprints are pinned to 80 bytes for the compact transaction, 96 bytes for the
plan, and 16 bytes for the single-use prepared token.
The retained pointer-free authority is pinned to 308 bytes, including its
276-byte authenticated binding.

## Production boundary

The handwritten semantic evaluator now lives at the explicit
`shifts_reg_legacy_test_oracle.zig` path. A short compatibility shim preserves
the shared tree until LT_REG and both shift families cross the production
registries atomically; that shim must be deleted in the integration batch.
Production closure still requires aggregate Debug, ReleaseSafe, and ReleaseFast
AIR and runner suites, exact proof/transcript A/B, the full shared rigidity
corpus, formal extraction, and live Sail agreement.
