# Conditional exact G2 subgroup source program

This document records the original source/witness checkpoint. A later closed
physical fixture now binds the canonical hints, BYTE/SSA and all zero assertions
for independently pinned generatorQ: see
`src/integrations/riscv_cpu/delegations/op_g2_subgroup/README.md`.
No VM tag, production native suite or execution admission is added. Curve and
subgroup obligations are explicit equations; no host-supplied `isValid` bit is an input.

Scope: canonical **non-infinity** affine Q on BN254's twist. Infinity and malformed
inputs must retain the complete guest/fallback policy; this is not a universal
EVM pairing precompile or a false-result proof. Even a fully proved subgroup
predicate would not establish Miller/final-exponent/residue pairing validity.

## Exact predicate and fixed schedule

The scalar r is copied from the vendored primary source
`opstack/kona/vendor/ark-bn254/src/fields/fr.rs`:
21888242871839275222246405745257275088548364400416034343698204186575808495617.
The Python vector generator checks that file's modulus equals both the existing
independent pairing oracle's R and the Zig literal. It does not use the shorter
psi/Frobenius subgroup equivalence as an acceptance predicate.

Source-owned equations first require `Qy² − Qx³ − twistB = 0` in both Fq
coordinates. A Q-independent binary program then computes `[r−1]Q`, starting at
Q and processing the remaining253bits:253 doubles and99 additions of Q. Its
final four scalar residuals require x=Qx and y=−Qy. On a nonsingular curve this
is exactly `[r]Q=∞`, with the canonical on-curve premise explicitly checked.

Every intermediate scalar prefix for an r-subgroup non-infinity point is between
1 and r−1. A doubled point therefore has nonzero2y; at an addition step its prior
scalar is neither1 nor r−1, so it is neither Q nor −Q and x−Qx is nonzero. Thus
strict affine formulas are complete for this conditional positive domain. A
non-subgroup/off-curve input may reach an exceptional denominator and reject this
route; no false pairing result is inferred from rejection. Parameter/primality
and field/group interpretation remain part of the eventual reviewed construction.

## Hint authority, canonical induction and exact assertions

Each inversion has a source-defined norm n and fresh canonical scalar writer t.
An independent quadratic row produces `n*t−1`; its writer ID MUST appear in the
immutable literal-zero assertion list. A freely generated modular output is not
an inverse proof. `Program.hintObligation()` derives that exact norm/hint/check
association and confirms the zero assertion. There is no self-referential SSA
read: a hint is an existential writer; its denominator metadata is not an SSA
read, while the subsequent checked multiplication reads both norm and hint.

`CanonicalHint` records the mandatory future physical contract:32 output BYTEs,
32 canonical-distance BYTEs,15 Boolean borrow bits, output+distance+1=p, and
source-owned active/ID/fanout; no producer flag can replace these gates. These physical gates were open at this source checkpoint; the later pinned-Q
fixture binds the equivalent concrete31-byte-carry canonical writer, with its
own source identity. Variable/call-bound production gates remain open. Source-only Witness validation checks those
canonical values numerically and never calls that a physical proof. All ordinary
field writers reuse the existing exact bounded integer/canonical implementation
`bn254_dense/row.zig::LayoutFor`, with seven canonical/raw-byte input slots and
one canonical output. The immutable operation ROM selects quadratic templates;
unused inputs are zero, not free relation slots. Future SSA closure must connect
every read to its unique canonical initial/hint/arithmetic writer.

`validate(expected_q)` requires independently supplied expected input; it rejects
a coherent witness for another point. It pins twistB/one literals, checks every
stored arithmetic row and exact input/output value, hint canonicality, and all
358 zero assertions. Q bytes must be authenticated to the original pairing call
before a physical provider can use them; the constructor's argument is not a
replacement for that external frontier. Global RAM/Wire/call IDs and full packet
coverage remain separate obligations.

## Exact source census and remaining cost

- 4390 unique writer nodes:4038 quadratic arithmetic rows +352 canonical hints.
- 358 literal-zero assertions:2 curve +352 inverse checks +4 final point residuals.
- SSA signed read/write mass16434; maximum fixed fanout352, both below M31 p.
- Common arithmetic MAIN530, BYTE queries353; existing carry residual envelopes
  are29,810,053 positive and29,809,501 negative, each below M31 p.
- 4038×530 =2,140,140 active arithmetic MAIN M31 cells per distinct Q. This excludes
  hint canonical rows, initial authentication, ROM/FIXED, padding, BYTE/SSA GKR,
  terminal binding, zero assertions, PCS and recursion. It is not a provider cost
  or throughput estimate. Applying it to87distinct Q is not yet a justified cache:
  repeated caller-Q reuse itself needs authenticated source coverage.

Source-only correctness is deliberately conservative; fewer polynomial rows or
an independently reviewed faster subgroup characterization can be evaluated
later. This checkpoint introduces neither a protocol optimization nor a timing
claim.

## Qualification and reproduction

```sh
python3 opstack/tools/g2_subgroup/vectors.py > /tmp/g2-subgroup-oracle.json
zig test src/frontends/riscv/rv64_bn254_g2_subgroup_test_root.zig -O ReleaseSafe
```

Independent Python integer arithmetic uses the existing affine curve oracle to
compute exact `[r−1]Q` and all352 norm-inverse hints for G2,2G2,5G2 and an actual
on-curve non-subgroup point. Zig matches final coordinates and the full hint-list
hash; the negative point has well-formed canonical arithmetic but fails final
zero assertions. Tests also reject modulus aliases, off-curve input, all-zero
infinity, zero denominators, changed expected Q, noncanonical hints, coherently
bad inverse hints with otherwise valid rows, a slope+p forgery propagated through
all later reads, output mutation and allocation failures.

The later pinned-Q fixture closes physical canonical hint writers, zero-assertion
export and BYTE/SSA closure with adversarial proofs for its conditional toy scope.
Remaining gates are source-bound whole-pairing input and
validity/infinity/subgroup policy; all-loop G2/prepared-line and Fp12/residue
composition; native/fresh-recursive receivers and conditional soundness accounting.
No production code can select this program as an admitted service today.


The source gate is also registered in the product build with a 16-test minimum:

```sh
zig build test-riscv64-op-g2-subgroup-source -Doptimize=ReleaseSafe -j1
```

This source/witness gate does not establish physical hint or subgroup admission.
