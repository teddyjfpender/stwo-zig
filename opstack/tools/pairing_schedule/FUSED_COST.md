# Fused whole-pairing source-cost model

This follows `README.md`; the complete scalar oracle is a correctness reference,
not the proposed final arithmetization. `fused_model.py` evaluates explicit
quadratic congruences, checks the original homogeneous point/line outputs and
ports the existing asymmetric integer-carry derivation. It creates no provider,
ISA tag, proof, production admission or guest-retirement claim.

The focused Zig test in `poseidon2_outer/pairing_source/cost_test.zig` independently
checks all five modeled envelopes against the original `curves.spec.deriveRelation`.
The ReleaseSafe focused test passes. This verifies the numerical carry model;
it does not turn these expressions into a complete AIR/SSA argument.

## Preserve the exact homogeneous line convention first

All arithmetic below is in canonical Fq2; `B` is the source-owned twist constant
and `half=(p+1)/2` is a source-owned canonical literal. The original homogeneous
doubling has this fused schedule (each assignment writes two Fq coordinates):

```
k=x*y; a=half*k; b=y*y; c=z*z; e=3*B*c
g=half*(b+3*e); h=2*y*z; j=x*x
X=a*(b-3*e); Y=g*g-3*e*e; Z=b*h; i=e-b
line=(-h,3*j,i)
```

There are **24 scalar congruences**, including explicit half intermediates and
canonical i. The line's sign and factor3 are source-owned coefficients in the
four later point-scaling equations; no free noncanonical field value is emitted
as a canonical SSA writer. The addition schedule is:

```
t=y-Qy*z; l=x-Qx*z; c=t*t; d=l*l
e=l*d; f=z*c; g=x*d; h=e+f-2*g
X=l*h; Y=t*(g-h)-e*y; Z=z*e; j=t*Qx-l*Qy
line=(l,-t,j)
```

Here h is an affine expression in already canonical writers; its uses expand
only to quadratic terms. There are **22 scalar congruences**. This keeps the
original point and line normalization exactly: the prototype compares all
256 doubles and 92 additions of a real four-pair request against the original
oracle formulas, including both final Frobenius corrections. It changes no
residue-witness interpretation. Every canonical output-coordinate mutation
fails its defining congruence.

An affine-line alternative is mathematically possible but is not this model.
For affine tangent slope lambda, `(-1,lambda,y-lambda*x)` differs from the
original homogeneous tangent by the nonzero Fq2 scale `2*y*z²`. For an addition
line its scale is `-z*(x-Qx)`. Products/squarings of these scales remain in Fq2,
a subfield of Fq6, so a separately proved factor can be absorbed into c.
However, the existing host residue witness cannot simply be reused unchanged;
the new line recurrence/scaling or new witness generation must be qualified.
No silent affine/homogeneous interchange is proposed.

## Subgroup check with constrained slope advice

The exact scalar `6*x*x` has 127 bits, 126 doublings and 69 additions after its
leading one: **195 point steps** per finite Q. An affine step uses eight scalar
congruences (four Fq2 equations): checked denominator inverse; slope equation;
new x equation; new y equation. Lambda, inverse and output coordinates are
canonical, typed writer ports. The inverse and slope coordinates form one
atomic checked operation, not independent unverified host hints. The point
reads and immutable scalar program bind which operands repeat in a doubling.
The final point must equal the source-fixed psi(Q) after the curve check.

A zero denominator makes this positive fastpath unavailable. It must cause
fallback/unsatisfiability, never a free slope or an incorrect true result.
The source-bound mode/point/infinity selectors and complete fallback behavior
still need an AIR. The prototype checks all 780 steps for the real four-pair
request and rejects changes to every inverse, slope and point coordinate.

## Direct sparse034 polynomial instead of 32 generic rows

The extension basis is exactly `i²=-1, v³=9+i, w²=v`. For an accumulator with
12 Fq coordinates, a canonical sparse034 factor has only six nonzero Fq
coordinates at indices 0,1,6,7,8,9. Expanding and reducing the basis gives 12
output congruences. Each output depends on exactly 12 scalar inputs after
source-owned operand remapping; maximum positive/negative product coefficient
masses are 40/23. No triple-byte products are required: four preceding scalar
congruences produce the two point-scaled Fq2 coefficients. This avoids the
unsafe assumption that an unbounded cubic limb convolution fits M31.

The independent generic tower multiplication matches all 72 sparse basis
products and 17 mixed/edge inputs. Every changed output is rejected. The exact
source carry derivation gives 34 quotient bytes, 64 carries, 19 carry bits and
strict M31 residual bounds 133,399,980 /133,395,862. With the same literal row
format as the new direct dense provider, the common shape is **691 MAIN**;
the conservative inherited BYTE/SSA plus global claim allowance is **40 INTER**.
It still requires a new actual source emitter/SSA/term binding and range ledger.

| Source role | Scalar equations | MAIN/row | INTER allowance | Active arithmetic cells |
|---|---:|---:|---:|---:|
| Homogeneous double | 24 | 498 | 40 | 12,912 |
| Homogeneous add | 22 | 626 | 40 | 14,652 |
| Affine subgroup step | 8 | 530 | 40 | 4,560 |
| Direct sparse034 outputs | 12 | 691 | 40 | 8,772 |

The source-derived half/constant inputs are counted as slots; they must be
constrained to the exact literals by the new immutable instruction ROM. All
rows include canonical result/distance/borrow and quotient/carry fields.
These widths are geometry calculations, not physically qualified layouts.
Forty interaction columns are a conditional allowance based on BYTE512/SSA16
terminal bindings plus global Wire; exact relation accounting may change it.

Adding four existing-style 418-cell scaling rows and the complete 20-Fq,
57-cell input frontier gives **11,584 active cells per line**, compared with
**14,772** for the current 32-row Miller-line provider. This is a conditional
source-shape saving, not a measured wall-time result. A whole-pairing local SSA
may remove repeated internal frontiers/global Wire columns, but this estimate
conservatively retains them. The direct dense square/multiply reference costs
are 9,456/14,748 active cells, including their original frontiers.

## Whole-request and bounded private-cache cost

On the retained 84-call/336-pair positive corpus, a single source-validated
87-entry G2 table would give:

| Work | Active modeled cells |
|---|---:|
| Exact homogeneous preparation (87 Q) | 101,212,668 |
| Subgroup steps (87 Q) | 77,360,400 |
| Seeded Miller squares/products, inverse/tail, direct lines | 421,668,576 |
| Subtotal | 600,241,644 |

This subtotal excludes public-input/hint frontiers, curve checks/psi endpoint,
branch/infinity selectors, fixed columns, all padding, closure and recursion.
The 87-point table is not a source-authorized cross-proof cache. If workers
share it, its full point/line tuple and multiplicity closure must be proved;
a metadata reference or hash equality is insufficient.

The more conservative bounded model instead groups **up to eight complete
requests per worker**, derives its exact private G2 table from those requests,
and repeats validation/preparation across workers. The retained requests need
**117 private G2 validations across 11 groups**, not 87. Every new group owns
its complete scalar/point/line source closure. The modeled roles use independent
power-of-two geometry; the current U15 scaling-row minimum log15 is retained.
The result is **1,203,030,016 padded arithmetic cells** before the listed
exclusions. The largest individual BYTE512+SSA16 checkpoint is **1,799,356,416
bytes** at the current 52-byte/fact source estimate. This is not a whole-worker
memory bound: all banks, MAIN, retained coefficients, provider tables, transcript,
GKR stages, output and allocator overhead still need the real planner.

That layout deliberately avoids assuming global point-cache reuse for free.
It also does not claim that removing field-call frontiers costs no internal
range/SSA facts. The receipt records exact per-role logs and counts; source
proof geometry and the 128-target union/mass/pole ledger must be independently
re-established before constructing a wide key. Per-request input identity,
count and result ownership remain bound to the existing complete RAM/CPU chain.

The next engineering gate is a closed sparse polynomial + fused point row
emitter with finite-difference degree tests, coherent canonical/quotient/carry
forgeries and original line equality, then a complete positive one-request
native proof. Only after those pass should source-suite, guest fastpath and
recursive worker integration be attempted. The hard 10× heavy-block target
remains open; these models establish a concrete bounded design to test.
