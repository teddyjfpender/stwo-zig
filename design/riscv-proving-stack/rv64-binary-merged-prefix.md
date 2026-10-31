# BINARY combined-prefix encoding v2

This changes the physical BINARY lookup encoding, not the FUNCTION13 operation
IDs or byte-AND truth set. `word16_v1/binary_encoding.zig` owns the explicit
encoding identity. Concrete closed execution, raw/indexed CPU, diagnostic and
weighted BINARY transcript owners bind that identity before roots/challenges.
The distributed facts-only role schema also changes. Retained v1 proof hashes
remain historical controls; new proofs require fresh verification and pins.

| Per BINARY domain row | Prior encoding | Encoding v2 |
|---|---:|---:|
| Fixed/main M31 columns | 2/42 | 2/42 |
| Interaction M31 columns | 28 | 24 |
| Secure strict inverses | 5 | 5 |
| Secure cyclic prefixes | 2 | 1 |
| Constraints | 52 | 50 |
| Sampled M31 values | 80 | 72 |
| Native quotient domain | 2n | 2n |

Eight unconditional AND requests use four inverse-of-product columns. The
FUNCTION request has one single inverse. Every denominator is affine, so the
strict paired inverse equations have degree three. The combined contribution
is the sum of all eight positive AND inverses minus multiplicity times the
FUNCTION inverse. It has degree two. The cyclic prefix and terminal equation
have degree at most two. The direct BINARY equations are unchanged.

Only `claims.and_ + claims.function` is authenticated by this component. The
fields remain an additive ledger decomposition for existing integration APIs;
neither is now an independently authenticated certificate. Full execution and
global execution sum both fields exactly once. Closed standalone transactions
close against the AND provider and expected FUNCTION facts. Open CPU fragments
close their local AND provider before returning the remaining FUNCTION debt.
Those external checks anchor the same combined physical debt. Redistributing
the split while preserving its sum intentionally leaves the local equations
unchanged; changing the total fails. Both fields enter each owning transcript
before interaction commitment and constraint randomness.

There is no pole exception for inactive or zero-multiplicity rows: all four
paired inverses and the single FUNCTION inverse are strict. Padding still
issues eight canonical zero AND queries, included in admitted positive mass.
No RAM-state, OWNER or clock relation is merged here.

The source keeps the same dictionary, semantic metadata, multiplicity admission
and lookup count. It writes one combined prefix and performs one final prefix
correction instead of two. This saves `16*n` bytes of committed interaction
source and, when these columns require native 2n extension, `32*n` bytes of
current evaluation storage. BINARY does not allocate a separate previous-row
coset matrix: it gathers previous samples from that same current matrix. Its
small per-row previous gather has four fewer M31 lanes. Current sampled
values fall by eight. At a native 2n evaluation the current-column transformed
cell count falls from `144*n` to `136*n`; constraints fall by two. These are
accounting results, not measured runtime or peak-RSS improvements.

## Qualification

Focused ReleaseSafe and ReleaseFast gates cover native witness reconstruction,
all-allocation failures, release-main-before-challenges, strict poles/retry,
weighted multiplicities, scalar/PackedM31/PackedQM31 residual parity, genuine
arbitrary-Q cubic degree, real CircuitLane challenge/claim/inverse parity and
mutations, and the complete q70/P26 closed BINARY proof. New standalone and
whole-execution proof pins are recorded separately after fresh receivers run.

## Common composition geometry is a separate issue

`core/air/components.zig` requires all component composition splits to agree.
`word16_execution/components.zig` selects split two for the whole roster and
raises the declared maximum degree-log by one for roles other than DIV/MUL.
Consequently the common quotient commitment uses four columns and the declared
maximum commonly follows the CPU's lifted bound. Individual native component
callbacks still run their own 2n or 4n evaluators. Tiny DIV/MUL roles therefore
do not cause every component's native FFT to become 4n. A future composition
change must distinguish common commitment/FRI costs from native evaluator work;
removing a role alone does not remove the explicit roster override.
