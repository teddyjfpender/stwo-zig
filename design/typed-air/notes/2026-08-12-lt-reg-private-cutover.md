# LT_REG private fixed-authority readiness

Date: 2026-08-12

Status: private admission complete; atomic production integration in progress

## Result

SLT and SLTU now have one authenticated, allocation-free executable authority
for architectural comparison, x0 visibility, physical witness generation, all
36 direct roots, and all 14 ordered relation events. The admitted binding is
pointer-free, source-location independent, and pinned by SHA-256:

`b7e2e713c2075ae6d3b9eb34f2c715f831269a4f109190a328078a8bd454f7d4`

The fixed evaluator exactly retains the existing protocol geometry:

- 44 main columns;
- 35 semantic roots plus one placement root;
- 14 relation events in batches of two;
- seven interaction columns;
- opcode identifiers 3 (SLT) and 4 (SLTU).

## Correctness admission

The private gate establishes:

- exact QM31 equality with the independent legacy evaluator for every direct
  root, placement, numerator, tuple field, relation domain, role, arity, access
  ordinal, ordering position, and batch size over randomized secure-field rows;
- signed and unsigned extrema, equality, first differences in every byte,
  x0 reads and writes, rs1/rs2 aliases, and rd/source aliases;
- exhaustive decoding of all 65,536 architectural SLT/SLTU R-type register
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
The ReleaseSafe proof receipt is 58,475 bytes with proof SHA-256
`41903dd780a9a1b9eefa6d1cad162fce84b30c020886ec2a4ef14bef825cd0cb`,
transcript digest
`cb8385b0af4c1b786801bf0c1e11e802582cdf0f03083bf48dd5200e850dea09`,
and one transcript draw.

## Performance admission

The strengthened performance receipt consumes every QM31 coordinate of every
direct root and lookup tuple. Paired, interleaved ReleaseFast medians on the
same workload measured:

- fixed direct evaluation: 18,147,541 ns versus 20,921,042 ns, or 1.1528x;
- fixed ordered-lookup construction: 8,363,000 ns versus 25,355,084 ns, or
  3.0318x;
- fixed retirement: 137,833 ns versus 205,709 ns, or 1.4925x.

Both gates require at least 0.97x legacy throughput. The fixed runtime
footprints are 80 bytes for the compact transaction, 96 bytes for the plan, and
16 bytes for the single-use prepared token. Compile-time budgets allow only one
natural word of headroom for the first two footprints.
The retained pointer-free authority is pinned to 232 bytes, including its
200-byte authenticated binding.

## Production boundary

The handwritten semantic evaluator now lives at the explicit
`lt_reg_legacy_test_oracle.zig` path. A short compatibility shim preserves the
shared tree until LT_REG and both shift families cross the production
registries atomically; that shim must be deleted in the integration batch.
Production closure still requires aggregate Debug, ReleaseSafe, and ReleaseFast
AIR and runner suites, exact proof/transcript A/B, the full shared rigidity
corpus, formal extraction, and live Sail agreement.
