# Wide service arithmetic and classic global relations

This source work separates the original MAIN polynomials from lookup storage
and supplies explicit degree-eight global LogUp kernels. It does not select a
production profile or qualify a complete Ethereum proof or whole-protocol
128-bit security claim.

## MAIN seams

| Authority | Direct residuals | Maximum degree |
|---|---:|---:|
| Keccak Word16 bridge | 133 | 3 |
| Secp ADD bridge | 373 | 3 |
| Secp DOUBLE bridge | 373 | 3 |
| Secp product truth | 426 | 3 |
| Secp linear truth | 413 | 3 |
| Keccak truth, existing strict boundary gate | 5,453 | 3 |

Keccak and secp bridges expose `emitMainFor` using typed call-span publics.
Secp truth exposes `emitMainFor(F,kind,row,polynomial,span,sink)`. The original
secp bridge interleaves RAM inverse checks with direct lane transitions; small
shared transition/readability/tail helpers preserve that exact legacy order.
The old emitters still use their original four-coordinate interaction layouts.
Native counts retain the old native arithmetic; external call counts and
nonempty flags are circuit wires.

Keccak already exports `emitDirectFor`. Its legacy active-bit gate multiplies
`boundary * active * v * (1-v)` and is genuinely degree4. The existing pair2n
route's `active_bit_gate=false` instead uses `boundary * v * (1-v)` at degree3.
Padding already forces those state coordinates to zero. The new wide route
must explicitly choose this stronger boundary gate; the legacy route still
selects its original gate and is not silently changed.

## Explicit eight-coordinate global kernels

`main_only/global_classic.zig` provides three independently useful encodings:

- `singlesFor`: one strict inverse per fraction and one joint prefix. Affine
  denominators and quadratic weights remain degree3.
- `linearPairsFor`: one strict inverse per denominator pair and one joint
  prefix. Both denominators and weights must be affine under the authoritative
  role equations. Quadratic weights here would raise the degree to4.
- `clearedPairFor`: one strict pair inverse and one independently claimed
  cleared prefix. `delta*D0*D1-w0*D1-w1*D0=0` is degree3 with affine denominators
  and quadratic weights. The separate inverse rejects either pole, including
  zero-weight poles; clearing a denominator is not permission to cancel it.

Every current and previous secure value decodes exactly eight physical
coordinates. Shape mismatches return errors. These APIs do not draw challenges
or authenticate producer claims themselves: the caller must use the global
manifest-derived challenges, bind every physical claim to the transcript and
close the complete ledger. Tuple and weight projections remain the existing
RAM/KIO/Wire authorities.

| Case | Joint singles columns / samples / claims | Cleared pairs columns / samples / claims |
|---|---|---|
| KIO truth, 25 fractions | 208 / 216 / 1 | 208 / 312 / 13 |
| Secp truth, 3 Wire fractions | 32 / 40 / 1 | 32 / 48 / 2 |
| Bridge, 2 fractions | 24 / 32 / 1 | 16 / 24 / 1 |

Samples count physical coordinate-column openings, with each prefix opened at
current and previous rows. Equal column counts can hide a larger recursive
opening workload. Odd truth arities therefore favor joint singles on this
accounting; two-fraction bridges favor cleared pairs when weights are
quadratic. Linear RAM pairs can still share one joint prefix. No runtime speed
claim follows from this structural accounting.

## Qualification and remaining integration

Dense native OM31 values and actual OM31 circuit wires agree on all eight
coordinates for all six MAIN authorities. Fourth finite differences vanish.
Global degree tests use the original LS RAM tuples, Keccak IO tuples/activity,
secp truth Wire tuples/coefficients, and secp bridge Wire tuples/quadratic output
weight; each stated degree3 bound is exercised by a nonzero third difference.
Actual circuit checks accept valid inverse/prefix witnesses and reject
zero-weight poles, high-coordinate inverse/prefix corruption and an altered
public claim. Cost tests count columns, predecessor openings and independent
claims together. Existing native-Q crypto and bridge proof suites are retained.

Still required: compose MAIN, local-GKR binding and wide global constraints
under one MAIN commitment per role; generate and commit genuine wide interaction
witnesses; carry every physical claim through stage-two/global manifest closure;
admit the complete receiver geometry independently; qualify separate truth
GKR rosters; and complete the wide block/recursion security budget. Standalone
MAIN arithmetic or an individually valid global fragment is not execution
acceptance.
