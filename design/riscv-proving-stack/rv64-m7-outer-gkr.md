# M7 outer-GKR binding v2

The M6 default proof format remains unchanged. The M7 names in the security
registry are reserved; registration does not enable a producer or receiver.
The outer GKR v1 reference remains available with its original identity.

## DW-R1: Eq normalization and cyclic terminal binding

The v2 binding uses exactly the native `gkr_local/binding.zig` equation
authority. `residualsFor` is shared by the native emitter, the outer emitter
and the mutation tests. Each GKR-bound component commits Eq and Pre, each
with eight M31 coordinates:

```
(E-eq0)*first + (E-eq1)*second
E - E_next2*carry
Pre - Pre_previous - E*projection + target/rows
```

The receiver derives `first`, `second`, `carry`, `eq0` and `eq1` from the
verified GKR row suffix and its own folded PCS OODS point. The succinct
`mle_point.zig` evaluator is instantiated over native OM31 and the octic
circuit lane. No auxiliary is committed, guessed or supplied by the proof.
`binding_v2.evaluateFor` checks the class/version/log and computes these
auxiliaries internally before emitting the residuals.

On the trace domain, the recurrence connects every point in each of the two
half cosets. Each half has one endpoint anchor. Every row-point coordinate
must differ from zero and one, so the carry quotients exist and are nonzero.
Consequently both anchored recurrences determine the entire Eq column;
neither a scaled Eq column nor an interior perturbation can satisfy them.
The native section verifier rejects a degenerate row suffix. The circuit
counterpart emits inverse constraints that reject exactly those degeneracies.

The prefix contains `rows` entries in physical bit-reversed circle order.
Its recurrence is cyclic, including the wrap from the last coset point to
the first. Summing it over the trace domain fixes the target to the weighted
sum of authenticated MAIN fractions. The target is derived from terminal
claims fixed before late gamma/rho draws. Gamma separates numerator and
denominator obligations; rho separates lane groups. Production wiring must
take the target from these verified claims, never producer metadata.

Eq, carry, anchors and every MAIN/FIXED column have circle degree at most
`rows-1`. The projection is affine in these authenticated columns. Each
residual therefore has degree at most `2*rows-2`, so its evaluation-log
degree bound is `row_log+1`. The actual hybrid component must preserve this
bound and source-owned masks when it is wired into the production PCS.

The v2 section header binds the new identity
`stwo/rv64/outer-gkr/om31-strict-draw/lane-major/v2` before its first
challenge. Both wire and transcript versions differ from v1; editing only
the wire version cannot launder a v1 section.

## Characteristic gate

The v2 gate requires source topology and output count. The old GKR-only mass
gate explicitly refuses v2. `sourceUseMass` bounds all positive uses of all
classic and GKR components together, plus public outputs and the reserved
u wire. Every original positive use has weight one; table yields are
negative. This bounds the positive mass of each shared relation, including
uses from classic components omitted by a GKR-only census. No producer
claimed mass enters this calculation.

Tests enlarge a classic component sharing the Gate relation while leaving
every GKR instance unchanged. The source gate rejects characteristic wrap
even though the old GKR-instance mass is unchanged.

## Qualification and implementation boundary

`scripts/rv64_m7_outer_binding_gate.py` runs the CPU-only binding, registry
and host-emulated CUDA fraction suites on the pod under the build lock.
Its receipt includes exact source-file hashes, diagnostic dirty identity,
commands, logs, load and durations. The tests include:

- succinct OM31 auxiliaries against independently interpolated `public_aux`
  columns at random circle points;
- circuit/native equality at row logs through 23;
- forged zero/scaled Eq columns, and an interior Eq mutation where both the
  endpoint and prefix equations pass while the carry recurrence fails;
- the cyclic prefix wrap edge and a wrong terminal target;
- zero/one row coordinates, native and in circuit;
- v1/v2 cross-version rejection, including a rewritten version word;
- lazy lane-major outer fractions against the original tuple authority.

The lazy CUDA source reuses `lookup_tuples.cuh`; it does not introduce new
lookup semantics. It projects a requested original fraction directly from
MAIN/FIXED and lookup challenges, with compile-time term dispatch. Real
poles remain poles and poison sticky status. Its intended consumer is the
shared projected-source GKR traversal, at both product-tree ingress and the
final layer that revisits original fractions.

The concrete lazy GPU callbacks now pass a real RTX 5090 numerical gate:
16 source groups, 242608 original fractions, both ingress layer variants,
sumcheck at 0/2, half-split fold, 48 geometry/alias mutants, and two real
zero-weight pole cases. Memcheck reports zero errors. Exact source and
binary identities are in `vectors/reports/rv64-m7-20261105/outer-gkr/projected-gpu/receipt.json`.
The resident image builder includes and checks the five callback symbols;
complete-image build/production class selection is still a later gate.

Still required before promotion: production hybrid AIR/PCS wiring, Eq/Pre
generation, child-verifier proof framing,
both dev-block production proofs, fresh receiver/audit acceptance, and the
production tamper corpus. These tests do not establish M7 request time,
cell reduction, proof compression or an end-to-end outer-GKR result.
