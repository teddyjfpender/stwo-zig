# 2026-08-13 — exact PCS/DEEP row-24 proof

## Question

Can universal row 24 reproduce the native PCS/DEEP verifier exactly inside the
same typed outer proof as rows 20--23 and 25--34, without weakening the local
soundness boundary, and what does the added work cost?

## Context and exact revisions

This is mutable branch evidence from `feat/typed-air-precompiles`, not an
immutable release receipt. The predecessor outer proof covered 14 components,
rows 20--23 and 25--34. Row 24 existed as typed AIR and witness authority but
did not yet consume real verifier-captured PCS values in that proof.

## Implementation

`pcs_deep_circuit.zig` is now the proof-independent arithmetic authority for
the native PCS quotient law. It binds transcript-derived OODS geometry,
bit-reversed lifting-domain queries, stable sample batching, transcript-order
random powers, conjugate-line quotients, and equality with the values passed to
FRI. Every proof value is an explicit graph input.

`recursive_fri_outer.zig` independently rebuilds the PCS and FRI graphs from
the captured profile on both prover and verifier paths. Six lanes—PCS and FRI,
each in segment, left-child, and right-child modes—share typed rows 30--32.
Schedules concatenate within a proof mode and overlay physical rows between
modes. Constants and zero outputs remain explicit public wire anchors. Row 24
is inserted at manifest index 4, making rows 20--34 contiguous.

The accepted algebra reductions are exact:

- graph identities fold zero/one arithmetic and identical subtraction;
- the native per-sample `p(cq - ay - b)` sum is factored by sample-point batch
  as `c * sum(p(q-v)) + (point.y-domain.y) * sum(p(conj(v)-v))`;
- each batch caches the native denominator determinant and imaginary
  coefficients, leaving two products per query denominator.

The native differential test evaluates the optimized graph against the native
PCS quotient implementation. The input row and fixed-wire adapter continue to
derive their values only from a transactionally successful native verifier
capture.

## Commands or experiment

```text
zig build --build-file src/frontends/riscv/build.zig \
  test-recursion-air-edit -Doptimize=ReleaseSafe

STWO_RECURSION_ACTIVE_FRI_OUTER=1 \
STWO_RECURSION_OUTER_WORKERS=4 \
zig build test-riscv-recursion-poseidon-leaf -Doptimize=ReleaseSafe

STWO_RECURSION_FRI_FRONTIER_BLOWUP=2 \
STWO_RECURSION_ACTIVE_FRI_OUTER=1 \
STWO_RECURSION_OUTER_WORKERS=4 \
zig build test-riscv-recursion-poseidon-leaf -Doptimize=ReleaseSafe
```

## Observations

Both outer runs independently verify and reject all three public-boundary,
wire-closure, and proof-body mutations. The fixed adapter rejects 21/21
mutations failure-atomically on frozen V1.

| Measure | Frozen V1, 2x/193 | Frontier candidate, 4x/97 |
| --- | ---: | ---: |
| Honest proof union | 16/36 | 16/36 |
| Components | 15 | 15 |
| Columns, preprocessing/main/interaction | 307/758/252 | 307/758/252 |
| Constraints | 848 | 848 |
| Proof estimate | 64,476 B | 62,908 B |
| Prove | 57.974 s | 28.766 s |
| Assembly | 47.950 s | 23.928 s |
| STARK body | 10.013 s | 4.830 s |
| Independent verify | 18.860 s | 9.440 s |
| PCS graph nodes | 764,768 | 395,662 |
| PCS graph inputs/outputs | 179,344/6,370 | 92,272/3,202 |
| Active multiply/inverse/linear rows | 540,626/16,021/470,147 | 279,938/8,053/243,519 |
| Poseidon2 calls | 52,303 | 26,675 |

The first sound row-24 frozen-V1 checkpoint, before the accepted algebra
reductions, estimated 66,652 bytes and measured 70.196 s prove, 59.923 s
assembly, and 25.236 s verify. The accepted implementation improves those
same-scope figures by 3.3%, 17.4%, 20.0%, and 25.3%, respectively.

The older 4x/97 outer measured 12.608 s before row 24. The new 28.766 s result
is not a same-scope regression: it additionally proves the complete PCS/DEEP
graph. It is the honest cost baseline for optimizing that new authority.

## Soundness finding

An experiment removed duplicated local query-bit, query-position, active-row,
and FRI-route constraints and crossed a useful row-capacity threshold. It was
rejected and fully reverted. The present partial outer does not yet prove all
global lookup claims whose cancellation would justify delegating those local
facts. A local equation may be removed only after the replacement relation is
present, bound, and cancelled in the same proved statement.

This leaves a precise performance target: reduce the row-30 multiply capacity
without borrowing unproved global closure. Candidate mechanisms are an
authenticated degree-one constant-scaling lane and algebraic graph reductions,
each accepted only on exact differential, mutation, proof-identity, and
end-to-end measurements.

## What this does not establish

This is an arithmetic-subsystem proof. Rows 1--19's statement/transcript and
challenge ownership, row 35, full cross-domain relation closure, binding of
child proof bytes to the recursive leaf, and the canonical proved `2 -> 1`
node remain open. The 4x/97 result is a measured frontier candidate; frozen V1
remains 2x/193 until a versioned protocol decision promotes another profile.

## Decisions/tasks affected

- R-012 honest real-proof coverage advances from 15/36 to 16/36.
- Row 24 is no longer an open proof-integration task.
- The next proof span is rows 1--19, followed by row 35/global closure.
- Performance work may not use unclosed lookup relations as an implicit
  soundness premise.
